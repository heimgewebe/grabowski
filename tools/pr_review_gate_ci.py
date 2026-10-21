#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any, Callable

# Run against trusted default-branch evaluator code, never a PR checkout.
_MODULE_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_MODULE_SRC) not in sys.path:
    sys.path.insert(0, str(_MODULE_SRC))
from grabowski_pr_diff import (  # noqa: E402
    BoundLocalDiffError,
    _bounded_git_capture,
    bound_local_pr_git_diff,
    local_pr_git_environment,
)

try:
    import pr_review_gate as gate
    import review_evidence_schemas as evidence_schemas
except ModuleNotFoundError:  # importlib-based tests load this file from the repo root
    from tools import pr_review_gate as gate
    from tools import review_evidence_schemas as evidence_schemas


SCHEMA_VERSION = 1
AUDIT_KIND = "grabowski_self_review_audit"
STATUS_KIND = "grabowski_review_gate_status"
ATTESTATION_KIND = evidence_schemas.REVIEW_GATE_ATTESTATION_KIND
RESULT_KIND = "grabowski_review_gate_ci_result"
LEGACY_STATUS_CONTEXT = "Review evidence gate"
ATTESTED_STATUS_CONTEXT = "Review evidence gate (attested)"
ADVISORY_STATUS_CONTEXT = "Review evidence gate (advisory)"
STATUS_CONTEXT = ATTESTED_STATUS_CONTEXT
COMMENT_PREFIX_V1 = "/grabowski-review-evidence v1"
COMMENT_PREFIX_V2 = "/grabowski-review-evidence v2"
COMMENT_PREFIX = COMMENT_PREFIX_V1
SIGNER_PRINCIPAL = evidence_schemas.REVIEW_GATE_SIGNER_PRINCIPAL
SIGNATURE_NAMESPACE = evidence_schemas.REVIEW_GATE_SIGNATURE_NAMESPACE
DEFAULT_ALLOWED_SIGNERS_PATH = (
    Path(__file__).resolve().parents[1] / "config" / "review-evidence-allowed-signers"
)
MAX_AUDIT_BYTES = 64 * 1024
MAX_STATUS_BYTES = 16 * 1024
MAX_STATUS_B64_BYTES = 32 * 1024
MAX_ATTESTATION_BYTES = 24 * 1024
MAX_ATTESTATION_B64_BYTES = 40 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
COMMAND_TIMEOUT_SECONDS = 30
ALLOWED_WRITE_PERMISSIONS = frozenset({"admin", "maintain", "write", "push"})
REVIEW_TIER_RANK = evidence_schemas.REVIEW_TIER_RANK
COMMENT_STATE_CURRENT = "current"
COMMENT_STATE_SUPERSEDED = "superseded"
COMMENT_STATE_STALE = "stale_or_edited"
COMMENT_STATE_OUTSIDE_WINDOW = "outside_bounded_window"
COMMENT_STATE_AUTHORIZATION_UNKNOWN = "authorization_unknown"
COMMENT_RE = re.compile(
    rf"\A{re.escape(COMMENT_PREFIX_V1)}(?:\s+(?P<payload>[A-Za-z0-9+/=]+))?\s*\Z"
)
COMMENT_V2_RE = re.compile(
    rf"\A{re.escape(COMMENT_PREFIX_V2)}(?:\s+(?P<payload>[A-Za-z0-9+/=]+))?\s*\Z"
)
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class CiEvidenceError(ValueError):
    pass


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _normalize_repo(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized if REPO_RE.fullmatch(normalized) else None


def _normalize_git_sha(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized if GIT_SHA_RE.fullmatch(normalized) else None


def _normalize_sha256(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized if SHA256_RE.fullmatch(normalized) else None


def _prefixed_schema_failures(payload: Any, *, label: str, prefix: str) -> list[str]:
    return [
        f"{prefix} {failure}"
        for failure in evidence_schemas.validate_evidence(payload, label=label)
    ]


def _required_audit_failures(audit: Any) -> list[str]:
    failures = _prefixed_schema_failures(
        audit, label="self-review audit", prefix="audit"
    )
    if not isinstance(audit, dict):
        return failures
    if _normalize_repo(audit.get("repo")) is None:
        failures.append("audit repo is invalid")
    if _normalize_git_sha(audit.get("head_sha")) is None:
        failures.append("audit head_sha is invalid")
    if _normalize_git_sha(audit.get("base_sha")) is None:
        failures.append("audit base_sha is invalid")
    if _normalize_sha256(audit.get("diff_sha256")) is None:
        failures.append("audit diff_sha256 is invalid")
    if (
        not _is_int(audit.get("material_findings_remaining"))
        or audit.get("material_findings_remaining", -1) < 0
    ):
        failures.append("audit material_findings_remaining must be an integer >= 0")
    return failures


def build_status_projection(audit_bytes: bytes) -> dict[str, Any]:
    if len(audit_bytes) > MAX_AUDIT_BYTES:
        raise CiEvidenceError(f"audit exceeds {MAX_AUDIT_BYTES} bytes")
    try:
        audit = json.loads(audit_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CiEvidenceError("audit is not valid UTF-8 JSON") from exc

    failures = _required_audit_failures(audit)
    if failures:
        raise CiEvidenceError("; ".join(failures))

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": STATUS_KIND,
        "repo": _normalize_repo(audit["repo"]),
        "pr": audit["pr"],
        "head_sha": _normalize_git_sha(audit["head_sha"]),
        "base_sha": _normalize_git_sha(audit["base_sha"]),
        "diff_sha256": _normalize_sha256(audit["diff_sha256"]),
        "audit_sha256": hashlib.sha256(audit_bytes).hexdigest(),
        "review_policy_version": audit["review_policy_version"],
        "gate_verdict": audit["gate_verdict"],
        "self_review_gate_valid": audit["self_review_gate_valid"],
        "all_findings_triaged": audit["all_findings_triaged"],
        "material_findings_remaining": audit["material_findings_remaining"],
        "minimum_review_iterations": audit["minimum_review_iterations"],
        "actual_review_iterations": audit["actual_review_iterations"],
        "review_tier": audit["review_tier"],
        "tuning_signal": audit["tuning_signal"],
    }


def canonical_status_bytes(status: dict[str, Any]) -> bytes:
    return (json.dumps(status, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def encode_status_projection(status: dict[str, Any]) -> str:
    return base64.b64encode(canonical_status_bytes(status)).decode("ascii")


def _run_signature_command(argv: list[str], *, stdin: bytes) -> bytes:
    try:
        result = subprocess.run(
            argv,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CiEvidenceError("review evidence signature command could not be executed") from exc
    if result.returncode != 0:
        raise CiEvidenceError("review evidence signature operation failed")
    return result.stdout


def sign_status_projection(status: dict[str, Any], *, signing_key: str | Path) -> bytes:
    failures = _status_schema_failures(status)
    if failures:
        raise CiEvidenceError("; ".join(failures))
    key_path = Path(signing_key).expanduser()
    if not key_path.is_file():
        raise CiEvidenceError("review evidence signing key is missing")
    signature = _run_signature_command(
        [
            "ssh-keygen",
            "-Y",
            "sign",
            "-f",
            str(key_path),
            "-n",
            SIGNATURE_NAMESPACE,
        ],
        stdin=canonical_status_bytes(status),
    )
    if len(signature) > MAX_SIGNATURE_BYTES or not signature.startswith(
        b"-----BEGIN SSH SIGNATURE-----"
    ):
        raise CiEvidenceError("review evidence signature output is invalid")
    return signature


def build_signed_status_attestation(
    audit_bytes: bytes, *, signing_key: str | Path
) -> dict[str, Any]:
    status = build_status_projection(audit_bytes)
    signature = sign_status_projection(status, signing_key=signing_key)
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": ATTESTATION_KIND,
        "signer_principal": SIGNER_PRINCIPAL,
        "signature_namespace": SIGNATURE_NAMESPACE,
        "status": status,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }


def canonical_attestation_bytes(attestation: dict[str, Any]) -> bytes:
    return (
        json.dumps(attestation, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def encode_signed_status_attestation(attestation: dict[str, Any]) -> str:
    return base64.b64encode(canonical_attestation_bytes(attestation)).decode("ascii")


def verify_signed_status_attestation(
    attestation: Any, *, allowed_signers_path: str | Path
) -> dict[str, Any]:
    failures = _prefixed_schema_failures(
        attestation,
        label="signed review gate status",
        prefix="signed status evidence",
    )
    if failures:
        raise CiEvidenceError("; ".join(failures))
    assert isinstance(attestation, dict)
    status = attestation.get("status")
    status_failures = _status_schema_failures(status)
    if status_failures:
        raise CiEvidenceError("; ".join(status_failures))
    assert isinstance(status, dict)
    signature_raw = attestation.get("signature_b64")
    if not isinstance(signature_raw, str):
        raise CiEvidenceError("signed status evidence signature is missing")
    try:
        signature = base64.b64decode(signature_raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CiEvidenceError("signed status evidence signature is not valid base64") from exc
    if len(signature) > MAX_SIGNATURE_BYTES or not signature.startswith(
        b"-----BEGIN SSH SIGNATURE-----"
    ):
        raise CiEvidenceError("signed status evidence signature is invalid")

    allowed_path = Path(allowed_signers_path)
    if not allowed_path.is_file():
        raise CiEvidenceError("trusted review evidence signer allowlist is missing")
    with tempfile.NamedTemporaryFile(mode="wb", prefix="grabowski-review-signature-") as handle:
        handle.write(signature)
        handle.flush()
        _run_signature_command(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(allowed_path),
                "-I",
                SIGNER_PRINCIPAL,
                "-n",
                SIGNATURE_NAMESPACE,
                "-s",
                handle.name,
            ],
            stdin=canonical_status_bytes(status),
        )
    return status


def decode_signed_status_attestation(
    raw: str, *, allowed_signers_path: str | Path
) -> dict[str, Any]:
    normalized = raw.strip()
    if not normalized:
        raise CiEvidenceError("signed status evidence is missing")
    try:
        normalized_size = len(normalized.encode("ascii"))
    except UnicodeEncodeError as exc:
        raise CiEvidenceError("signed status evidence is not valid base64") from exc
    if normalized_size > MAX_ATTESTATION_B64_BYTES:
        raise CiEvidenceError(
            f"signed status evidence exceeds {MAX_ATTESTATION_B64_BYTES} base64 bytes"
        )
    try:
        decoded = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CiEvidenceError("signed status evidence is not valid base64") from exc
    if len(decoded) > MAX_ATTESTATION_BYTES:
        raise CiEvidenceError(
            f"decoded signed status evidence exceeds {MAX_ATTESTATION_BYTES} bytes"
        )
    try:
        attestation = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CiEvidenceError("signed status evidence is not valid UTF-8 JSON") from exc
    return verify_signed_status_attestation(
        attestation, allowed_signers_path=allowed_signers_path
    )


def _status_schema_failures(status: Any) -> list[str]:
    failures = _prefixed_schema_failures(
        status, label="review gate status", prefix="status evidence"
    )
    if not isinstance(status, dict):
        return failures
    if _normalize_repo(status.get("repo")) is None:
        failures.append("status evidence repo is invalid")
    if _normalize_git_sha(status.get("head_sha")) is None:
        failures.append("status evidence head_sha is invalid")
    if _normalize_git_sha(status.get("base_sha")) is None:
        failures.append("status evidence base_sha is invalid")
    for field in ("diff_sha256", "audit_sha256"):
        if _normalize_sha256(status.get(field)) is None:
            failures.append(f"status evidence {field} is invalid")
    return failures


def decode_status_projection(raw: str) -> dict[str, Any]:
    normalized = raw.strip()
    if not normalized:
        raise CiEvidenceError("status evidence is missing")
    try:
        normalized_size = len(normalized.encode("ascii"))
    except UnicodeEncodeError as exc:
        raise CiEvidenceError("status evidence is not valid base64") from exc
    if normalized_size > MAX_STATUS_B64_BYTES:
        raise CiEvidenceError(
            f"status evidence exceeds {MAX_STATUS_B64_BYTES} base64 bytes"
        )
    try:
        decoded = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CiEvidenceError("status evidence is not valid base64") from exc
    if len(decoded) > MAX_STATUS_BYTES:
        raise CiEvidenceError(
            f"decoded status evidence exceeds {MAX_STATUS_BYTES} bytes"
        )
    try:
        status = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CiEvidenceError("status evidence is not valid UTF-8 JSON") from exc
    failures = _status_schema_failures(status)
    if failures:
        raise CiEvidenceError("; ".join(failures))
    return status


def parse_comment_status(body: str) -> dict[str, Any]:
    match = COMMENT_RE.fullmatch(body.strip())
    if match is None:
        raise CiEvidenceError("review evidence comment command is malformed")
    payload = match.group("payload")
    if not payload:
        raise CiEvidenceError("status evidence is missing")
    return decode_status_projection(payload)


def parse_comment_evidence(
    body: str, *, allowed_signers_path: str | Path
) -> tuple[dict[str, Any], bool]:
    stripped = body.strip()
    match_v2 = COMMENT_V2_RE.fullmatch(stripped)
    if match_v2 is not None:
        payload = match_v2.group("payload")
        if not payload:
            raise CiEvidenceError("signed status evidence is missing")
        return (
            decode_signed_status_attestation(
                payload, allowed_signers_path=allowed_signers_path
            ),
            True,
        )
    match_v1 = COMMENT_RE.fullmatch(stripped)
    if match_v1 is not None:
        payload = match_v1.group("payload")
        if not payload:
            raise CiEvidenceError("status evidence is missing")
        return decode_status_projection(payload), False
    raise CiEvidenceError("review evidence comment command is malformed")


def permission_allows_publish(permission: Any) -> bool:
    return (
        isinstance(permission, str)
        and permission.strip().lower() in ALLOWED_WRITE_PERMISSIONS
    )


def _review_command_prefix(body: str) -> str | None:
    stripped = body.strip()
    for prefix in (COMMENT_PREFIX_V1, COMMENT_PREFIX_V2):
        if stripped == prefix or stripped.startswith(prefix + " "):
            return prefix
    return None


def _is_review_command(body: str, *, command_prefix: str | None = None) -> bool:
    prefix = _review_command_prefix(body)
    return prefix is not None and (command_prefix is None or prefix == command_prefix)


def _comment_identity(comment: Any) -> tuple[int, str, str] | None:
    if not isinstance(comment, dict):
        return None
    body = comment.get("body")
    comment_id = comment.get("id", comment.get("databaseId"))
    user = comment.get("user", comment.get("author"))
    actor = user.get("login") if isinstance(user, dict) else None
    if (
        not isinstance(body, str)
        or not _is_int(comment_id)
        or not isinstance(actor, str)
        or not actor
    ):
        return None
    return comment_id, actor, body


def select_latest_authorized_command_comment_id(
    comments: list[Any],
    *,
    permission_lookup: Callable[[str], Any],
    command_prefix: str = COMMENT_PREFIX_V1,
) -> int | None:
    candidates: list[tuple[int, str]] = []
    for comment in comments:
        identity = _comment_identity(comment)
        if identity is None:
            continue
        comment_id, actor, body = identity
        if not _is_review_command(body, command_prefix=command_prefix):
            continue
        candidates.append((comment_id, actor))

    for comment_id, actor in reversed(candidates):
        if permission_allows_publish(permission_lookup(actor)):
            return comment_id
    return None


def command_comment_authorization_state(
    comments: list[Any],
    *,
    current_comment_id: int,
    current_comment_body: str,
    permission_lookup: Callable[[str], Any],
) -> str:
    current_body: str | None = None
    for comment in comments:
        identity = _comment_identity(comment)
        if identity is None:
            continue
        comment_id, _actor, body = identity
        if comment_id == current_comment_id:
            current_body = body
            break
    if current_body is None:
        return COMMENT_STATE_OUTSIDE_WINDOW
    if current_body != current_comment_body:
        return COMMENT_STATE_STALE
    command_prefix = _review_command_prefix(current_comment_body)
    if command_prefix is None:
        return COMMENT_STATE_STALE
    try:
        latest = select_latest_authorized_command_comment_id(
            comments,
            permission_lookup=permission_lookup,
            command_prefix=command_prefix,
        )
    except CiEvidenceError:
        return COMMENT_STATE_AUTHORIZATION_UNKNOWN
    if latest == current_comment_id:
        return COMMENT_STATE_CURRENT
    return COMMENT_STATE_SUPERSEDED


def command_comment_is_current_and_latest_authorized(
    comments: list[Any],
    *,
    current_comment_id: int,
    current_comment_body: str,
    permission_lookup: Callable[[str], Any],
) -> bool:
    return (
        command_comment_authorization_state(
            comments,
            current_comment_id=current_comment_id,
            current_comment_body=current_comment_body,
            permission_lookup=permission_lookup,
        )
        == COMMENT_STATE_CURRENT
    )


def evaluate_status_projection(
    status: dict[str, Any],
    *,
    repo_name: str,
    pr: dict[str, Any],
    diff_sha256: str,
    complexity: dict[str, Any],
    equivalent_diff_sha256s: tuple[str, ...] = (),
) -> list[str]:
    failures = _status_schema_failures(status)
    if failures:
        return failures

    current_repo = _normalize_repo(repo_name)
    current_head = _normalize_git_sha(pr.get("headRefOid"))
    current_base = _normalize_git_sha(pr.get("baseRefOid"))
    current_diff = _normalize_sha256(diff_sha256)
    accepted_diff_identities = {
        item
        for item in (
            current_diff,
            *(_normalize_sha256(value) for value in equivalent_diff_sha256s),
        )
        if item is not None
    }
    if pr.get("state") != "OPEN":
        failures.append("PR is not open")
    if pr.get("isDraft") is True:
        failures.append("PR is draft")
    if _normalize_repo(status.get("repo")) != current_repo:
        failures.append("status evidence repo mismatch")
    if status.get("pr") != pr.get("number"):
        failures.append("status evidence PR number mismatch")
    if _normalize_git_sha(status.get("head_sha")) != current_head:
        failures.append("status evidence head_sha mismatch")
    if _normalize_git_sha(status.get("base_sha")) != current_base:
        failures.append("status evidence base_sha mismatch")
    if _normalize_sha256(status.get("diff_sha256")) not in accepted_diff_identities:
        failures.append("status evidence diff_sha256 mismatch")
    if status.get("review_policy_version") != evidence_schemas.REVIEW_POLICY_VERSION:
        failures.append("status evidence review policy version is stale or invalid")
    if status.get("gate_verdict") != "PASS":
        failures.append("status evidence gate_verdict is not PASS")
    if status.get("self_review_gate_valid") is not True:
        failures.append("status evidence self_review_gate_valid is not true")
    if status.get("all_findings_triaged") is not True:
        failures.append("status evidence all_findings_triaged is not true")
    if status.get("material_findings_remaining") != 0:
        failures.append("status evidence has material findings remaining")
    if status.get("actual_review_iterations", -1) < status.get(
        "minimum_review_iterations", 0
    ):
        failures.append("status evidence review depth is insufficient")

    current_minimum = complexity.get("minimum_self_review_iterations")
    if not _is_int(current_minimum) or current_minimum < 0:
        failures.append("current PR review depth could not be derived")
    elif status.get("minimum_review_iterations", -1) < current_minimum:
        failures.append("status evidence minimum review depth is stale or too weak")

    current_tier = complexity.get("review_tier")
    status_tier = status.get("review_tier")
    if current_tier not in REVIEW_TIER_RANK:
        failures.append("current PR review tier could not be derived")
    elif REVIEW_TIER_RANK.get(status_tier, 0) < REVIEW_TIER_RANK[current_tier]:
        failures.append("status evidence review tier is stale or too weak")
    if status.get("tuning_signal") != "observe":
        failures.append("status evidence tuning_signal is not observe")
    return failures


def _command_label(argv: list[str]) -> str:
    return " ".join(argv[:3])


def _run_json(argv: list[str], *, stdin: bytes | None = None) -> Any:
    try:
        result = subprocess.run(
            argv,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise CiEvidenceError(
            f"command timed out after {COMMAND_TIMEOUT_SECONDS}s: {_command_label(argv)}"
        ) from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise CiEvidenceError(
            f"command failed: {_command_label(argv)}: {detail[:500]}"
        )
    try:
        return json.loads(result.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise CiEvidenceError(
            f"command returned invalid JSON: {_command_label(argv)}"
        ) from exc


def _run_bytes(argv: list[str]) -> bytes:
    try:
        result = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise CiEvidenceError(
            f"command timed out after {COMMAND_TIMEOUT_SECONDS}s: {_command_label(argv)}"
        ) from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise CiEvidenceError(
            f"command failed: {_command_label(argv)}: {detail[:500]}"
        )
    return result.stdout


def load_live_pr(repo_name: str, pr_number: int) -> dict[str, Any]:
    return _run_json(
        [
            "gh",
            "pr",
            "view",
            str(pr_number),
            "--repo",
            repo_name,
            "--json",
            "number,state,isDraft,headRefOid,baseRefOid,changedFiles,additions,deletions,files,url,title",
        ]
    )


def _revision_bound_pr_file_evidence(
    repo_name: str, pr: dict[str, Any]
) -> list[dict[str, Any]]:
    """Bind security-sensitive file status/rename origin to immutable Git SHAs.

    The PR-number-only REST files endpoint can briefly serve a different head
    after A -> B -> A; equal paths and counts do not authenticate rename origins.
    The unpaged Compare response must identify the exact initially observed
    base/head. Ambiguous merge bases and the Compare files cap fail closed.
    """
    base = _normalize_git_sha(pr.get("baseRefOid"))
    head = _normalize_git_sha(pr.get("headRefOid"))
    count = pr.get("changedFiles")
    if base is None or head is None or type(count) is not int or not 1 <= count <= 300:
        raise CiEvidenceError("revision-bound rename evidence identity or file count invalid")
    try:
        payload = _run_json(["gh", "api", f"repos/{repo_name}/compare/{base}...{head}"])
    except CiEvidenceError as exc:
        raise CiEvidenceError("revision-bound rename evidence unavailable") from exc
    commits = payload.get("commits") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("base_commit"), dict)
        or payload["base_commit"].get("sha") != base
        or not isinstance(commits, list)
        or not commits
        or not isinstance(commits[-1], dict)
        or commits[-1].get("sha") != head
    ):
        raise CiEvidenceError("revision-bound compare base/head identity drifted")
    files = payload.get("files")
    evidence = gate._pull_file_evidence([files])
    if (
        evidence is None
        or len(evidence) != count
        or gate._complete_pr_diff_paths({
            "pullFilesEvidenceComplete": True, "files": evidence,
        }) is None
    ):
        raise CiEvidenceError("revision-bound compare file/rename evidence incomplete")
    return evidence


def _require_rename_aware_pr(
    repo_name: str, pr_number: int, pr: dict[str, Any]
) -> dict[str, Any]:
    """Verify the complete REST changed-file set before assigning a review tier.

    GraphQL `gh pr view --json files` omits rename status and source paths.
    Treating those entries as ordinary changes can incorrectly admit a rename
    out of a security-critical workflow as a documentation-only change.
    """
    count = pr.get("changedFiles")
    if (
        _normalize_repo(repo_name) != repo_name
        or type(pr_number) is not int or pr_number <= 0
        or not isinstance(pr, dict) or pr.get("number") != pr_number
        or type(count) is not int or count <= 0 or count > 3000
    ):
        raise CiEvidenceError("complete rename-aware PR file evidence is missing or invalid")
    try:
        rest_files = gate._load_pull_file_evidence(
            Path.cwd(), repo_slug=repo_name, pr=pr_number
        )
    except (RuntimeError, ValueError) as exc:
        raise CiEvidenceError(
            "complete rename-aware GitHub REST file evidence unavailable"
        ) from exc
    if (
        not isinstance(rest_files, list)
        or len(rest_files) != count
        or gate._complete_pr_diff_paths({
            "pullFilesEvidenceComplete": True, "files": rest_files
        }) is None
    ):
        raise CiEvidenceError("complete rename-aware GitHub REST file evidence invalid")

    # Compare the GraphQL snapshot to REST when present. GitHub may truncate
    # GraphQL's list at 100, but even a truncated snapshot may not disagree.
    graphql_files = pr.get("files")
    if not isinstance(graphql_files, list) or len(graphql_files) > count:
        raise CiEvidenceError("complete rename-aware PR GraphQL file evidence invalid")
    graphql_paths = [
        item.get("path") for item in graphql_files if isinstance(item, dict)
    ]
    rest_paths = {item["path"] for item in rest_files}
    if (
        len(graphql_paths) != len(graphql_files)
        or any(not isinstance(path, str) or not path for path in graphql_paths)
        or len(set(graphql_paths)) != len(graphql_paths)
        or not set(graphql_paths).issubset(rest_paths)
    ):
        raise CiEvidenceError("complete rename-aware REST/GraphQL path evidence drifted")
    # Revision-pinned status and previousPath are the classification authority.
    # REST is used only as a completeness/consistency witness, never alone.
    pinned_files = _revision_bound_pr_file_evidence(repo_name, pr)
    if (
        len(pinned_files) != len(rest_files)
        or {item["path"]: item for item in pinned_files}
        != {item["path"]: item for item in rest_files}
    ):
        raise CiEvidenceError("complete rename-aware REST/revision-bound compare metadata drifted")
    return {**pr, "files": pinned_files, "pullFilesEvidenceComplete": True}


def _known_pr_diff_limit_error(message: str, *, changed_files: Any) -> bool:
    """Only GitHub's known 406 line/file limit can use local identity."""
    if type(changed_files) is not int or changed_files < 0:
        return False
    if "HTTP 406" not in message or any(
        marker in message for marker in ("HTTP 401", "HTTP 403", "HTTP 429")
    ):
        return False
    line_cap = re.search(
        r"HTTP 406: (?:Sorry, )?the diff exceeded the maximum number of lines \(20000\)",
        message,
    ) is not None
    file_cap = changed_files > gate.GITHUB_PR_DIFF_MAX_FILES and any(
        (marker.decode("utf-8") if isinstance(marker, bytes) else marker) in message
        for marker in gate.GITHUB_PR_DIFF_TOO_LARGE_MARKERS
    )
    return line_cap or file_cap


def _trusted_revision_git(repo: Path, *argv: str, limit: int = 1024 * 1024) -> bytes:
    """Read pinned Git objects with no inherited config, helpers or subprocess hooks."""
    try:
        return _bounded_git_capture(
            ["git", "-C", str(repo), "-c", "core.pager=cat", *argv],
            cwd=str(repo),
            env=local_pr_git_environment(),
            stdout_limit=limit,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, BoundLocalDiffError, subprocess.SubprocessError) as exc:
        raise CiEvidenceError("exact local PR object check unavailable") from exc


def _fetch_exact_review_objects(
    repo: Path, repo_name: str, pr_number: int,
    *, base: str, head: str, base_ref: str,
) -> None:
    """Import only SHA-checkable remote Git objects into the trusted checkout."""
    if (
        _normalize_repo(repo_name) != repo_name
        or not isinstance(base_ref, str)
        or not base_ref or len(base_ref) > 256
    ):
        raise CiEvidenceError("untrusted PR Git ref")
    _trusted_revision_git(repo, "check-ref-format", f"refs/heads/{base_ref}", limit=8192)
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise CiEvidenceError("GitHub token unavailable for pinned PR objects")
    env = local_pr_git_environment()
    env["GH_TOKEN"] = token
    remote = f"https://github.com/{repo_name}.git"
    args = [
        "git", "-C", str(repo),
        "-c", "protocol.file.allow=never",
        "-c", "core.hooksPath=/dev/null",
        "-c", "credential.helper=",
        "-c", "credential.helper=!gh auth git-credential",
        "fetch", "--no-tags", "--no-write-fetch-head",
        "--no-recurse-submodules", "--",
        remote,
        f"refs/heads/{base_ref}:refs/review-evidence/base",
        f"refs/pull/{pr_number}/head:refs/review-evidence/head",
    ]
    try:
        _bounded_git_capture(
            args, cwd=str(repo), env=env, stdout_limit=8192, timeout=75,
        )
    except (BoundLocalDiffError, OSError, subprocess.SubprocessError) as exc:
        raise CiEvidenceError("cannot fetch exact GitHub PR objects") from exc
    current_head = _trusted_revision_git(
        repo, "rev-parse", "refs/review-evidence/head", limit=8192
    ).strip()
    if current_head != head.encode("ascii"):
        raise CiEvidenceError("fetched PR head is not the pinned head")
    _trusted_revision_git(
        repo, "merge-base", "--is-ancestor", base,
        "refs/review-evidence/base", limit=8192,
    )


def _bound_oversized_diff(repo_name: str, pr_number: int) -> bytes:
    """Prove a complete provider-sized diff from immutable PR commits.

    Only runs on the *trusted* default-branch checkout prepared by the
    issue_comment workflow. No PR file is checked out or executed.
    """
    pr = load_live_pr(repo_name, pr_number)
    base = _normalize_git_sha(pr.get("baseRefOid"))
    head = _normalize_git_sha(pr.get("headRefOid"))
    count = pr.get("changedFiles")
    if (
        pr.get("state") != "OPEN"
        or base is None or head is None
        or type(count) is not int or not 0 < count <= 3000
    ):
        raise CiEvidenceError("local PR fallback requires exact open head/base and file count")
    repo = Path.cwd().resolve()
    if _trusted_revision_git(repo, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise CiEvidenceError("local PR fallback requires complete Git history")
    try:
        _trusted_revision_git(repo, "cat-file", "-e", f"{base}^{{commit}}", limit=8192)
        _trusted_revision_git(repo, "cat-file", "-e", f"{head}^{{commit}}", limit=8192)
    except CiEvidenceError:
        _fetch_exact_review_objects(
            repo, repo_name, pr_number, base=base, head=head,
            base_ref=pr.get("baseRefName"),
        )
        _trusted_revision_git(repo, "cat-file", "-e", f"{base}^{{commit}}", limit=8192)
        _trusted_revision_git(repo, "cat-file", "-e", f"{head}^{{commit}}", limit=8192)
    merge_bases = _trusted_revision_git(
        repo, "merge-base", "--all", base, head, limit=8192
    ).splitlines()
    if len(merge_bases) != 1 or GIT_SHA_RE.fullmatch(
        merge_bases[0].decode("ascii", errors="replace")
    ) is None:
        raise CiEvidenceError("local PR fallback requires exactly one merge base")
    merge_base = merge_bases[0].decode("ascii")

    try:
        rest_files = gate._load_pull_file_evidence(
            repo, repo_slug=repo_name, pr=pr_number
        )
        expected = gate._complete_pr_diff_paths({
            "pullFilesEvidenceComplete": True, "files": rest_files
        })
    except (RuntimeError, ValueError) as exc:
        raise CiEvidenceError("complete GitHub file evidence unavailable") from exc
    if (
        not isinstance(rest_files, list)
        or len(rest_files) != count
        or expected is None
    ):
        raise CiEvidenceError("GitHub file evidence does not cover the complete PR")
    gh_files = pr.get("files")
    # gh pr view may cap this snapshot at 100; compare only when complete.
    if isinstance(gh_files, list) and len(gh_files) == count:
        graphql_paths = [item.get("path") for item in gh_files if isinstance(item, dict)]
        rest_paths = [item.get("path") for item in rest_files]
        if len(graphql_paths) != count or sorted(graphql_paths) != sorted(rest_paths):
            raise CiEvidenceError("GitHub REST and GraphQL file evidence drifted")

    names = _trusted_revision_git(
        repo, "diff", "--name-only", "-z", "--no-ext-diff", "--no-textconv",
        "--no-renames", "--ignore-submodules=none", "--no-color",
        merge_base, head, "--",
    )
    try:
        actual = sorted(name.decode("utf-8") for name in names.split(b"\0") if name)
    except UnicodeDecodeError as exc:
        raise CiEvidenceError("local PR fallback has non-UTF8 paths") from exc
    if len(actual) != len(set(actual)) or actual != expected:
        raise CiEvidenceError("local and GitHub changed paths or modes disagree")
    try:
        diff = bound_local_pr_git_diff(
            repo, merge_base=merge_base, head=head,
            max_diff_bytes=32 * 1024 * 1024,
        )
    except (BoundLocalDiffError, OSError, subprocess.SubprocessError) as exc:
        raise CiEvidenceError("trusted local PR diff could not be proven") from exc
    if not diff:
        raise CiEvidenceError("trusted local PR diff is empty")
    updated = load_live_pr(repo_name, pr_number)
    if any(updated.get(key) != pr.get(key) for key in (
        "headRefOid", "baseRefOid", "changedFiles", "state"
    )):
        raise CiEvidenceError("PR changed during local diff readback")
    return diff


def current_diff_sha256s(repo_name: str, pr_number: int) -> tuple[str, ...]:
    try:
        diff = _run_bytes(["gh", "pr", "diff", str(pr_number), "--repo", repo_name])
    except CiEvidenceError as exc:
        # Even the metadata read is conditional on a plausible GitHub 406.
        # No fallback, extra API traffic or trust downgrade for arbitrary errors.
        message = str(exc)
        if (
            "HTTP 406" not in message
            or any(code in message for code in ("HTTP 401", "HTTP 403", "HTTP 429"))
            or "the diff exceeded the maximum number of lines (20000)" not in message
            and not any(
                (m.decode("utf-8") if isinstance(m, bytes) else m) in message
                for m in gate.GITHUB_PR_DIFF_TOO_LARGE_MARKERS
            )
        ):
            raise
        view = load_live_pr(repo_name, pr_number)
        if not _known_pr_diff_limit_error(
            str(exc), changed_files=view.get("changedFiles")
        ):
            raise
        diff = _bound_oversized_diff(repo_name, pr_number)
    if not diff:
        raise CiEvidenceError("current PR diff is empty")
    return tuple(
        dict.fromkeys((
            gate.github_pr_diff_identity_sha256(diff),
            gate.github_pr_diff_identity_sha256_v1(diff),
        ))
    )


def current_diff_sha256(repo_name: str, pr_number: int) -> str:
    return current_diff_sha256s(repo_name, pr_number)[0]


def collaborator_permission(repo_name: str, actor: str) -> str | None:
    payload = _run_json(
        ["gh", "api", f"repos/{repo_name}/collaborators/{actor}/permission"]
    )
    permission = payload.get("permission") if isinstance(payload, dict) else None
    return permission if isinstance(permission, str) else None


def current_comment_authorization_state(
    repo_name: str,
    pr_number: int,
    *,
    comment_id: int,
    comment_body: str,
    permission_cache: dict[str, str | None] | None = None,
) -> str:
    owner, name = repo_name.split("/", 1)
    query = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      comments(last: 100) {
        nodes { databaseId body author { login } }
      }
    }
  }
}
""".strip()
    payload = _run_json(
        [
            "gh",
            "api",
            "graphql",
            "-f",
            f"query={query}",
            "-F",
            f"owner={owner}",
            "-F",
            f"name={name}",
            "-F",
            f"number={pr_number}",
        ]
    )
    try:
        comments = payload["data"]["repository"]["pullRequest"]["comments"]["nodes"]
    except (KeyError, TypeError) as exc:
        raise CiEvidenceError("current PR comment window could not be read") from exc
    if not isinstance(comments, list):
        raise CiEvidenceError("current PR comment window is invalid")

    cache = permission_cache if permission_cache is not None else {}

    def cached_permission(actor: str) -> str | None:
        if actor not in cache:
            cache[actor] = collaborator_permission(repo_name, actor)
        return cache[actor]

    return command_comment_authorization_state(
        comments,
        current_comment_id=comment_id,
        current_comment_body=comment_body,
        permission_lookup=cached_permission,
    )


def current_comment_is_latest_authorized(
    repo_name: str,
    pr_number: int,
    *,
    comment_id: int,
    comment_body: str,
) -> bool:
    return (
        current_comment_authorization_state(
            repo_name,
            pr_number,
            comment_id=comment_id,
            comment_body=comment_body,
        )
        == COMMENT_STATE_CURRENT
    )


def publish_commit_status(
    *,
    repo_name: str,
    head_sha: str,
    passed: bool,
    failure_count: int,
    context: str,
) -> None:
    target_url = None
    server_url = os.environ.get("GITHUB_SERVER_URL")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if server_url and run_id:
        target_url = f"{server_url.rstrip('/')}/{repo_name}/actions/runs/{run_id}"
    payload: dict[str, Any] = {
        "state": "success" if passed else "failure",
        "context": context,
        "description": (
            (
                "Attested review evidence passed current bindings"
                if context == ATTESTED_STATUS_CONTEXT
                else "Authorized review assertion passed current bindings"
            )
            if passed
            else f"Review evidence blocked ({failure_count} validation failure(s))"
        ),
    }
    if target_url:
        payload["target_url"] = target_url
    _run_json(
        [
            "gh",
            "api",
            "--method",
            "POST",
            f"repos/{repo_name}/statuses/{head_sha}",
            "--input",
            "-",
        ],
        stdin=json.dumps(payload, sort_keys=True).encode("utf-8"),
    )


def _safe_result(
    *,
    repo_name: str,
    pr_number: int,
    pr: dict[str, Any] | None,
    diff_sha256: str | None,
    failures: list[str],
    status: dict[str, Any] | None,
    complexity: dict[str, Any] | None,
    authorized: bool,
    permission: str | None,
    provenance_verified: bool = False,
    status_context: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": RESULT_KIND,
        "repo": repo_name,
        "pr": pr_number,
        "head_sha": (
            _normalize_git_sha(pr.get("headRefOid")) if isinstance(pr, dict) else None
        ),
        "base_sha": (
            _normalize_git_sha(pr.get("baseRefOid")) if isinstance(pr, dict) else None
        ),
        "diff_sha256": _normalize_sha256(diff_sha256),
        "audit_sha256": (
            _normalize_sha256(status.get("audit_sha256"))
            if isinstance(status, dict)
            else None
        ),
        "review_policy_version": evidence_schemas.REVIEW_POLICY_VERSION,
        "review_tier": (
            complexity.get("review_tier") if isinstance(complexity, dict) else None
        ),
        "minimum_review_iterations": (
            complexity.get("minimum_self_review_iterations")
            if isinstance(complexity, dict)
            else None
        ),
        "authorized": authorized,
        "actor_permission": permission,
        "provenance_verified": provenance_verified,
        "status_context": status_context,
        "verdict": "PASS" if authorized and not failures else "BLOCK",
        "failures": failures,
        "private_evidence_included": False,
    }


def _comment_state_failure(state: str) -> str:
    if state == COMMENT_STATE_STALE:
        return "comment was edited after the triggering event"
    if state == COMMENT_STATE_OUTSIDE_WINDOW:
        return "comment is missing or outside the bounded authorization window"
    if state == COMMENT_STATE_SUPERSEDED:
        return "comment was superseded by a newer authorized review-evidence command"
    if state == COMMENT_STATE_AUTHORIZATION_UNKNOWN:
        return "authorization of a newer review-evidence command could not be determined"
    return f"comment authorization state is invalid: {state}"


def prepare_command(args: argparse.Namespace) -> int:
    audit_path = Path(args.audit)
    audit_bytes = audit_path.read_bytes()
    status = build_status_projection(audit_bytes)
    rendered = json.dumps(status, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            with output.open("x", encoding="utf-8") as handle:
                handle.write(rendered)
        except FileExistsError as exc:
            raise CiEvidenceError(f"status projection already exists: {output}") from exc
    if args.comment:
        print(f"{COMMENT_PREFIX_V1} {encode_status_projection(status)}")
    elif args.base64:
        print(encode_status_projection(status))
    else:
        print(rendered, end="")
    return 0


def prepare_attested_command(args: argparse.Namespace) -> int:
    audit_bytes = Path(args.audit).read_bytes()
    attestation = build_signed_status_attestation(
        audit_bytes, signing_key=args.signing_key
    )
    rendered = json.dumps(attestation, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            with output.open("x", encoding="utf-8") as handle:
                handle.write(rendered)
        except FileExistsError as exc:
            raise CiEvidenceError(f"signed status attestation already exists: {output}") from exc
    if args.comment:
        print(
            f"{COMMENT_PREFIX_V2} "
            f"{encode_signed_status_attestation(attestation)}"
        )
    elif args.base64:
        print(encode_signed_status_attestation(attestation))
    else:
        print(rendered, end="")
    return 0


def evaluate_comment_command(args: argparse.Namespace) -> int:
    repo_name = _normalize_repo(args.repo_name or os.environ.get("GITHUB_REPOSITORY"))
    if repo_name is None:
        raise CiEvidenceError("repository identity is missing or invalid")

    event_actor = os.environ.get("GITHUB_ACTOR") or ""
    if args.publish_status:
        if args.comment_id is None:
            raise CiEvidenceError("--comment-id is required when publishing status")
        if not event_actor:
            raise CiEvidenceError("GITHUB_ACTOR is required when publishing status")
        if args.actor and args.actor != event_actor:
            raise CiEvidenceError(
                "--actor must match GITHUB_ACTOR when publishing status"
            )
        if getattr(args, "allowed_signers", None):
            raise CiEvidenceError(
                "--allowed-signers cannot override the trusted repository allowlist when publishing status"
            )
        if os.environ.get("REVIEW_GATE_ALLOWED_SIGNERS"):
            raise CiEvidenceError(
                "REVIEW_GATE_ALLOWED_SIGNERS cannot override the trusted repository allowlist when publishing status"
            )
        actor = event_actor
    else:
        actor = args.actor or event_actor

    permission = collaborator_permission(repo_name, actor)
    authorized = permission_allows_publish(permission)
    if not authorized:
        result = _safe_result(
            repo_name=repo_name,
            pr_number=args.pr,
            pr=None,
            diff_sha256=None,
            failures=["actor is not authorized to publish review evidence status"],
            status=None,
            complexity=None,
            authorized=False,
            permission=permission,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    pr = load_live_pr(repo_name, args.pr)
    head_sha = _normalize_git_sha(pr.get("headRefOid"))
    comment_body = os.environ.get(args.comment_body_env, "")
    command_prefix = _review_command_prefix(comment_body)
    status_context = (
        ATTESTED_STATUS_CONTEXT
        if command_prefix == COMMENT_PREFIX_V2
        else ADVISORY_STATUS_CONTEXT
    )
    allowed_signers_path = (
        str(DEFAULT_ALLOWED_SIGNERS_PATH)
        if args.publish_status
        else (
            getattr(args, "allowed_signers", None)
            or os.environ.get("REVIEW_GATE_ALLOWED_SIGNERS")
            or str(DEFAULT_ALLOWED_SIGNERS_PATH)
        )
    )
    permission_cache: dict[str, str | None] = {actor: permission}

    if args.comment_id is not None:
        try:
            comment_state = current_comment_authorization_state(
                repo_name,
                args.pr,
                comment_id=args.comment_id,
                comment_body=comment_body,
                permission_cache=permission_cache,
            )
        except CiEvidenceError as exc:
            failures = [f"comment freshness could not be proven: {exc}"]
            if args.publish_status and head_sha is not None:
                publish_commit_status(
                    repo_name=repo_name,
                    head_sha=head_sha,
                    passed=False,
                    failure_count=len(failures),
                    context=status_context,
                )
            result = _safe_result(
                repo_name=repo_name,
                pr_number=args.pr,
                pr=pr,
                diff_sha256=None,
                failures=failures,
                status=None,
                complexity=None,
                authorized=True,
                permission=permission,
                status_context=status_context,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 1
        if comment_state != COMMENT_STATE_CURRENT:
            failures = [_comment_state_failure(comment_state)]
            if (
                comment_state != COMMENT_STATE_SUPERSEDED
                and args.publish_status
                and head_sha is not None
            ):
                publish_commit_status(
                    repo_name=repo_name,
                    head_sha=head_sha,
                    passed=False,
                    failure_count=len(failures),
                    context=status_context,
                )
            result = _safe_result(
                repo_name=repo_name,
                pr_number=args.pr,
                pr=pr,
                diff_sha256=None,
                failures=failures,
                status=None,
                complexity=None,
                authorized=True,
                permission=permission,
                status_context=status_context,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if comment_state == COMMENT_STATE_SUPERSEDED else 1

    diff_sha256s = current_diff_sha256s(repo_name, args.pr)
    diff_sha256 = diff_sha256s[0]
    failures: list[str] = []
    complexity: dict[str, Any] | None = None
    try:
        pr = _require_rename_aware_pr(repo_name, args.pr, pr)
        complexity = gate.classify_complexity(pr, None, repo_name=repo_name)
    except CiEvidenceError as exc:
        failures.append(str(exc))
    status: dict[str, Any] | None = None
    provenance_verified = False
    try:
        status, provenance_verified = parse_comment_evidence(
            comment_body, allowed_signers_path=allowed_signers_path
        )
    except CiEvidenceError as exc:
        failures.append(str(exc))
    if status is not None and complexity is not None:
        failures.extend(
            evaluate_status_projection(
                status,
                repo_name=repo_name,
                pr=pr,
                diff_sha256=diff_sha256,
                complexity=complexity,
                equivalent_diff_sha256s=diff_sha256s[1:],
            )
        )

    initial_head = _normalize_git_sha(pr.get("headRefOid"))
    initial_base = _normalize_git_sha(pr.get("baseRefOid"))

    if args.publish_status and args.comment_id is not None:
        try:
            final_comment_state = current_comment_authorization_state(
                repo_name,
                args.pr,
                comment_id=args.comment_id,
                comment_body=comment_body,
                permission_cache=permission_cache,
            )
        except CiEvidenceError as exc:
            failures.append(
                f"comment freshness could not be proven before status publication: {exc}"
            )
        else:
            if final_comment_state == COMMENT_STATE_SUPERSEDED:
                result = _safe_result(
                    repo_name=repo_name,
                    pr_number=args.pr,
                    pr=pr,
                    diff_sha256=diff_sha256,
                    failures=[_comment_state_failure(final_comment_state)],
                    status=status,
                    complexity=complexity,
                    authorized=True,
                    permission=permission,
                    provenance_verified=provenance_verified,
                    status_context=status_context,
                )
                print(json.dumps(result, indent=2, sort_keys=True))
                return 0
            if final_comment_state != COMMENT_STATE_CURRENT:
                failures.append(_comment_state_failure(final_comment_state))

    final_pr = load_live_pr(repo_name, args.pr)
    final_head = _normalize_git_sha(final_pr.get("headRefOid"))
    final_base = _normalize_git_sha(final_pr.get("baseRefOid"))
    if final_head is None:
        failures.append("current PR head_sha is missing or invalid")
    if initial_head != final_head:
        failures.append("PR head changed during review-evidence evaluation")
    if initial_base != final_base:
        failures.append("PR base changed during review-evidence evaluation")
    if final_pr.get("changedFiles") != pr.get("changedFiles"):
        failures.append("PR changed-file count drifted during review-evidence evaluation")

    if args.publish_status and final_head is not None:
        publish_commit_status(
            repo_name=repo_name,
            head_sha=final_head,
            passed=not failures,
            failure_count=len(failures),
            context=status_context,
        )

    result = _safe_result(
        repo_name=repo_name,
        pr_number=args.pr,
        pr=final_pr,
        diff_sha256=diff_sha256,
        failures=failures,
        status=status,
        complexity=complexity,
        authorized=True,
        permission=permission,
        provenance_verified=provenance_verified,
        status_context=status_context,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not failures else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--audit", required=True)
    prepare.add_argument("--output")
    output_mode = prepare.add_mutually_exclusive_group()
    output_mode.add_argument("--base64", action="store_true")
    output_mode.add_argument("--comment", action="store_true")
    prepare.set_defaults(handler=prepare_command)

    prepare_attested = subparsers.add_parser("prepare-attested")
    prepare_attested.add_argument("--audit", required=True)
    prepare_attested.add_argument("--signing-key", required=True)
    prepare_attested.add_argument("--output")
    attested_output_mode = prepare_attested.add_mutually_exclusive_group()
    attested_output_mode.add_argument("--base64", action="store_true")
    attested_output_mode.add_argument("--comment", action="store_true")
    prepare_attested.set_defaults(handler=prepare_attested_command)

    evaluate = subparsers.add_parser("evaluate-comment")
    evaluate.add_argument("--pr", type=int, required=True)
    evaluate.add_argument("--repo-name")
    evaluate.add_argument("--actor")
    evaluate.add_argument("--comment-id", type=int)
    evaluate.add_argument("--comment-body-env", default="REVIEW_GATE_COMMENT_BODY")
    evaluate.add_argument("--allowed-signers")
    evaluate.add_argument("--publish-status", action="store_true")
    evaluate.set_defaults(handler=evaluate_comment_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (CiEvidenceError, OSError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "kind": RESULT_KIND,
                    "verdict": "BLOCK",
                    "failures": [str(exc)],
                    "private_evidence_included": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())

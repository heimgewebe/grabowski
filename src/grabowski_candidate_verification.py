from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable


SCHEMA_VERSION = 1
CANDIDATE_KIND = "CandidateManifest.v1"
VERIFICATION_KIND = "VerificationReceipt.v1"
SUMMARY_KIND = "VerificationSummary.v1"
RESULTING_TREE_CONTRACT = "logical-resulting-tree-v1"
OUTCOMES = frozenset({"PASS", "NEEDS_CHANGE", "INDETERMINATE"})
REQUIRED_VERIFIERS = ("review", "tests")
VERIFIER_POLICIES = {
    "review": "required-review-verdict-v1",
    "tests": "required-tests-returncode-v1",
}
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LANE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_FINDINGS = 512
MAX_RECEIPT_BYTES = 4 * 1024 * 1024


class CandidateVerificationError(ValueError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _required_string(value: Any, field: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise CandidateVerificationError(f"{field} must be a non-empty bounded string")
    if any(character in value for character in "\r\n\x00"):
        raise CandidateVerificationError(f"{field} contains an invalid control character")
    return value


def _required_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise CandidateVerificationError(f"{field} must be a lowercase SHA-256")
    return value


def _required_sha40(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA40_RE.fullmatch(value) is None:
        raise CandidateVerificationError(f"{field} must be a lowercase Git SHA")
    return value


def _normalize_json(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CandidateVerificationError("findings may not contain non-finite numbers")
        return value
    if isinstance(value, str):
        return value.replace("\r\n", "\n").replace("\r", "\n").strip()
    if isinstance(value, list):
        return [_normalize_json(item) for item in value]
    if isinstance(value, dict):
        if any(not isinstance(key, str) or not key for key in value):
            raise CandidateVerificationError("finding keys must be non-empty strings")
        return {key: _normalize_json(value[key]) for key in sorted(value)}
    raise CandidateVerificationError("findings must contain only JSON values")


def normalize_findings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_FINDINGS:
        raise CandidateVerificationError("findings must be a bounded list")
    unique: dict[str, dict[str, Any]] = {}
    for item in value:
        if not isinstance(item, dict):
            raise CandidateVerificationError("each finding must be an object")
        normalized = _normalize_json(item)
        encoded = canonical_json(normalized)
        unique[encoded] = normalized
    return [unique[key] for key in sorted(unique)]


def derive_resulting_tree_sha256(
    *,
    base_head: str,
    patch_sha256: str,
    untracked_manifest_sha256: str,
) -> str:
    """Bind the logical resulting tree without pretending to be a Git tree OID.

    A frozen patch is defined relative to one exact base.  Together with the
    independently bound untracked-file manifest those values uniquely identify
    the candidate tree for this patch-mode contract.  The result is a SHA-256
    contract digest, not Git's repository-format-dependent tree object id.
    """
    return sha256_json(
        {
            "contract": RESULTING_TREE_CONTRACT,
            "base_head": _required_sha40(base_head, "base_head"),
            "patch_sha256": _required_sha256(patch_sha256, "patch_sha256"),
            "untracked_manifest_sha256": _required_sha256(
                untracked_manifest_sha256, "untracked_manifest_sha256"
            ),
        }
    )


def build_candidate_manifest(
    *,
    workspace_id: str,
    round_number: int,
    base_head: str,
    patch_sha256: str,
    untracked_manifest_sha256: str,
    scope_evidence_sha256: str,
    resulting_tree_sha256: str,
    writer_evidence_sha256: str,
    lane_id: str | None = None,
) -> dict[str, Any]:
    workspace = _required_string(workspace_id, "workspace_id", maximum=80)
    if isinstance(round_number, bool) or not isinstance(round_number, int) or round_number < 1:
        raise CandidateVerificationError("round must be a positive integer")
    body: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": CANDIDATE_KIND,
        "workspace_id": workspace,
        "round": round_number,
        "base_head": _required_sha40(base_head, "base_head"),
        "patch_sha256": _required_sha256(patch_sha256, "patch_sha256"),
        "untracked_manifest_sha256": _required_sha256(
            untracked_manifest_sha256, "untracked_manifest_sha256"
        ),
        "scope_evidence_sha256": _required_sha256(
            scope_evidence_sha256, "scope_evidence_sha256"
        ),
        "resulting_tree_sha256": _required_sha256(
            resulting_tree_sha256, "resulting_tree_sha256"
        ),
        "writer_evidence_sha256": _required_sha256(
            writer_evidence_sha256, "writer_evidence_sha256"
        ),
    }
    if lane_id is not None:
        if not isinstance(lane_id, str) or LANE_ID_RE.fullmatch(lane_id) is None:
            raise CandidateVerificationError(
                "lane_id must be a lowercase 32-character hex identity"
            )
        body["lane_id"] = lane_id
    return {"candidate_id": sha256_json(body), **body}


def validate_candidate_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CandidateVerificationError("candidate manifest must be an object")
    expected_keys = {
        "candidate_id",
        "schema_version",
        "kind",
        "workspace_id",
        "round",
        "base_head",
        "patch_sha256",
        "untracked_manifest_sha256",
        "scope_evidence_sha256",
        "resulting_tree_sha256",
        "writer_evidence_sha256",
    }
    if "lane_id" in value:
        expected_keys.add("lane_id")
    if set(value) != expected_keys:
        raise CandidateVerificationError("candidate manifest shape is not canonical")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("kind") != CANDIDATE_KIND:
        raise CandidateVerificationError("candidate manifest contract is unsupported")
    rebuilt = build_candidate_manifest(
        workspace_id=value.get("workspace_id"),
        round_number=value.get("round"),
        base_head=value.get("base_head"),
        patch_sha256=value.get("patch_sha256"),
        untracked_manifest_sha256=value.get("untracked_manifest_sha256"),
        scope_evidence_sha256=value.get("scope_evidence_sha256"),
        resulting_tree_sha256=value.get("resulting_tree_sha256"),
        writer_evidence_sha256=value.get("writer_evidence_sha256"),
        lane_id=value.get("lane_id"),
    )
    if value != rebuilt:
        raise CandidateVerificationError("candidate_id does not match the canonical manifest")
    return rebuilt


def _source_receipt_integrity(receipt: Any) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise CandidateVerificationError("source role receipt must be an object")
    expected = _required_sha256(
        receipt.get("receipt_sha256"), "source_role_receipt_sha256"
    )
    stable = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    if sha256_json(stable) != expected:
        raise CandidateVerificationError("source role receipt integrity mismatch")
    return receipt


def _verification_outcome(verifier_kind: str, receipt: dict[str, Any]) -> str:
    returncode = receipt.get("returncode")
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        return "INDETERMINATE"
    failure = receipt.get("failure_classification")
    if verifier_kind == "tests":
        if returncode == 0:
            return "PASS"
        if failure in {
            "environment_toolchain_failure",
            "toolchain_probe_error",
            "output_limit_exceeded",
            "writer_binding_violation",
        }:
            return "INDETERMINATE"
        return "NEEDS_CHANGE"
    verdict = receipt.get("verdict")
    if verdict in {"NEEDS_CHANGE", "BLOCK"}:
        return "NEEDS_CHANGE"
    if verdict == "PASS" and returncode == 0:
        return "PASS"
    return "INDETERMINATE"


def _receipt_findings(
    verifier_kind: str,
    outcome: str,
    receipt: dict[str, Any],
) -> list[dict[str, Any]]:
    if verifier_kind == "review" and isinstance(receipt.get("findings"), list):
        findings = normalize_findings(receipt["findings"])
        if findings or outcome == "PASS":
            return findings
    if outcome == "PASS":
        return []
    return normalize_findings(
        [
            {
                "code": (
                    "verifier_needs_change"
                    if outcome == "NEEDS_CHANGE"
                    else "verifier_indeterminate"
                ),
                "verifier_kind": verifier_kind,
                "returncode": receipt.get("returncode"),
                "failure_classification": receipt.get("failure_classification"),
                "stdout_sha256": receipt.get("stdout_sha256"),
                "stderr_sha256": receipt.get("stderr_sha256"),
            }
        ]
    )


def _runtime_identity_sha256(runtime_identity: dict[str, Any] | None) -> str | None:
    if not isinstance(runtime_identity, dict):
        return None
    observed = runtime_identity.get("identity_sha256")
    if isinstance(observed, str) and SHA256_RE.fullmatch(observed):
        return observed
    return sha256_json(runtime_identity)


def _canonical_toolchain_identity(
    toolchain_identity: dict[str, Any] | None,
    source_receipt: dict[str, Any],
) -> dict[str, Any]:
    if isinstance(toolchain_identity, dict):
        return {
            "source": "workspace-role-preflight-v1",
            "identity_sha256": sha256_json(toolchain_identity),
            "command_sha256": toolchain_identity.get("command_sha256"),
            "sandbox": toolchain_identity.get("sandbox"),
            "environment_sha256": (
                toolchain_identity.get("environment", {}).get("environment_sha256")
                if isinstance(toolchain_identity.get("environment"), dict)
                else None
            ),
            "resolved_executable": toolchain_identity.get("resolved_executable"),
            "declared_python_module": toolchain_identity.get("declared_python_module"),
            "external_agent_profile": toolchain_identity.get("external_agent_profile"),
            "passed": toolchain_identity.get("passed"),
            "failure_classification": toolchain_identity.get("failure_classification"),
        }
    failure_probe = source_receipt.get("post_failure_toolchain_probe")
    return {
        "source": "role-receipt-fallback-v1",
        "identity_sha256": (
            sha256_json(failure_probe) if isinstance(failure_probe, dict) else None
        ),
        "command_sha256": source_receipt.get("argv_sha256"),
        "sandbox": source_receipt.get("sandbox"),
        "environment_sha256": None,
        "resolved_executable": (
            failure_probe.get("resolved_executable")
            if isinstance(failure_probe, dict)
            else None
        ),
        "declared_python_module": (
            failure_probe.get("declared_python_module")
            if isinstance(failure_probe, dict)
            else None
        ),
        "external_agent_profile": (
            failure_probe.get("external_agent_profile")
            if isinstance(failure_probe, dict)
            else None
        ),
        "passed": source_receipt.get("returncode") == 0,
        "failure_classification": source_receipt.get("failure_classification"),
    }


def derive_verification_receipt(
    *,
    candidate_manifest: dict[str, Any],
    verifier_kind: str,
    source_role_receipt: dict[str, Any],
    runtime_identity: dict[str, Any] | None,
    toolchain_identity: dict[str, Any] | None = None,
    verifier_attempt: int = 1,
) -> dict[str, Any]:
    candidate = validate_candidate_manifest(candidate_manifest)
    if (
        isinstance(verifier_attempt, bool)
        or not isinstance(verifier_attempt, int)
        or verifier_attempt < 1
    ):
        raise CandidateVerificationError("verifier_attempt must be a positive integer")
    if verifier_kind not in VERIFIER_POLICIES:
        raise CandidateVerificationError("verifier_kind is unsupported")
    source = _source_receipt_integrity(source_role_receipt)
    if source.get("role") != verifier_kind:
        raise CandidateVerificationError(
            "source role receipt belongs to another verifier"
        )
    command_sha256 = _required_sha256(source.get("argv_sha256"), "command_sha256")
    sandbox = _required_string(source.get("sandbox"), "sandbox", maximum=256)
    tool_or_command_identity = {
        "executor": "grabowski_agent_role",
        "argv_sha256": command_sha256,
        "role_receipt_schema_version": source.get("schema_version", 1),
        "sandbox": sandbox,
        "review_document_contract": (
            source.get("review_document_contract")
            if verifier_kind == "review"
            else None
        ),
    }
    canonical_toolchain = _canonical_toolchain_identity(toolchain_identity, source)
    environment_identity = {
        "workspace_runtime_identity_sha256": _runtime_identity_sha256(runtime_identity),
        "sandbox": sandbox,
        "expected_head": source.get("expected_head"),
        "expected_base_head": source.get("expected_base_head"),
        "expected_diff_sha256": source.get("expected_diff_sha256"),
        "expected_dirty": source.get("expected_dirty"),
    }
    outcome = _verification_outcome(verifier_kind, source)
    findings = _receipt_findings(verifier_kind, outcome, source)
    body = {
        "schema_version": SCHEMA_VERSION,
        "kind": VERIFICATION_KIND,
        "candidate_id": candidate["candidate_id"],
        "workspace_id": candidate["workspace_id"],
        "round": candidate["round"],
        "verifier_attempt": verifier_attempt,
        "verifier_kind": verifier_kind,
        "verifier_policy": VERIFIER_POLICIES[verifier_kind],
        "tool_or_command_identity": tool_or_command_identity,
        "tool_or_command_identity_sha256": sha256_json(tool_or_command_identity),
        "toolchain_identity": canonical_toolchain,
        "toolchain_identity_sha256": sha256_json(canonical_toolchain),
        "environment_identity": environment_identity,
        "environment_identity_sha256": sha256_json(environment_identity),
        "source_role_receipt_sha256": source["receipt_sha256"],
        "outcome": outcome,
        "findings": findings,
        "findings_sha256": sha256_json(findings),
    }
    return {**body, "receipt_sha256": sha256_json(body)}


def validate_verification_receipt(
    value: Any,
    *,
    expected_candidate_id: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CandidateVerificationError("verification receipt must be an object")
    expected_keys = {
        "schema_version",
        "kind",
        "candidate_id",
        "workspace_id",
        "round",
        "verifier_attempt",
        "verifier_kind",
        "verifier_policy",
        "tool_or_command_identity",
        "tool_or_command_identity_sha256",
        "toolchain_identity",
        "toolchain_identity_sha256",
        "environment_identity",
        "environment_identity_sha256",
        "source_role_receipt_sha256",
        "outcome",
        "findings",
        "findings_sha256",
        "receipt_sha256",
    }
    if set(value) != expected_keys:
        raise CandidateVerificationError("verification receipt shape is not canonical")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("kind") != VERIFICATION_KIND:
        raise CandidateVerificationError("verification receipt contract is unsupported")
    if value.get("candidate_id") != expected_candidate_id:
        raise CandidateVerificationError("verification receipt candidate_id mismatch")
    verifier = value.get("verifier_kind")
    if verifier not in VERIFIER_POLICIES or value.get("verifier_policy") != VERIFIER_POLICIES[verifier]:
        raise CandidateVerificationError("verification policy binding is invalid")
    _required_string(value.get("workspace_id"), "workspace_id", maximum=80)
    round_number = value.get("round")
    if isinstance(round_number, bool) or not isinstance(round_number, int) or round_number < 1:
        raise CandidateVerificationError("verification round is invalid")
    verifier_attempt = value.get("verifier_attempt")
    if (
        isinstance(verifier_attempt, bool)
        or not isinstance(verifier_attempt, int)
        or verifier_attempt < 1
    ):
        raise CandidateVerificationError("verification verifier_attempt is invalid")
    _required_sha256(
        value.get("source_role_receipt_sha256"), "source_role_receipt_sha256"
    )
    if value.get("outcome") not in OUTCOMES:
        raise CandidateVerificationError("verification outcome is invalid")
    for field in (
        "tool_or_command_identity",
        "toolchain_identity",
        "environment_identity",
    ):
        identity = value.get(field)
        if not isinstance(identity, dict):
            raise CandidateVerificationError(
                f"verification {field} evidence is invalid"
            )
        if sha256_json(identity) != value.get(f"{field}_sha256"):
            raise CandidateVerificationError(f"{field} hash mismatch")
    findings = normalize_findings(value.get("findings"))
    if findings != value.get("findings") or sha256_json(findings) != value.get("findings_sha256"):
        raise CandidateVerificationError("verification findings are not canonical")
    stable = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if sha256_json(stable) != value.get("receipt_sha256"):
        raise CandidateVerificationError("verification receipt integrity mismatch")
    return dict(value)


def reduce_verifications(
    *,
    candidate_manifest: dict[str, Any],
    verification_receipts: list[dict[str, Any]],
    required_verifiers: tuple[str, ...] = REQUIRED_VERIFIERS,
) -> dict[str, Any]:
    candidate = validate_candidate_manifest(candidate_manifest)
    if (
        not isinstance(required_verifiers, tuple)
        or not required_verifiers
        or len(set(required_verifiers)) != len(required_verifiers)
        or any(item not in VERIFIER_POLICIES for item in required_verifiers)
    ):
        raise CandidateVerificationError("required verifier policy is invalid")
    if not isinstance(verification_receipts, list):
        raise CandidateVerificationError("verification_receipts must be a list")
    observed: dict[str, dict[str, Any]] = {}
    for raw in verification_receipts:
        receipt = validate_verification_receipt(
            raw, expected_candidate_id=candidate["candidate_id"]
        )
        if (
            receipt["workspace_id"] != candidate["workspace_id"]
            or receipt["round"] != candidate["round"]
        ):
            raise CandidateVerificationError(
                "verification workspace or round binding mismatch"
            )
        verifier = receipt["verifier_kind"]
        if verifier in observed:
            raise CandidateVerificationError("duplicate verifier receipt")
        observed[verifier] = receipt
    required = sorted(required_verifiers)
    missing = [item for item in required if item not in observed]
    findings = [
        finding
        for verifier in sorted(observed)
        for finding in observed[verifier]["findings"]
    ]
    findings.extend(
        {"code": "missing_required_verifier", "verifier_kind": verifier}
        for verifier in missing
    )
    normalized_findings = normalize_findings(findings)
    required_outcomes = {
        verifier: (
            observed[verifier]["outcome"]
            if verifier in observed
            else "INDETERMINATE"
        )
        for verifier in required
    }
    if any(
        outcome == "NEEDS_CHANGE" for outcome in required_outcomes.values()
    ):
        outcome = "NEEDS_CHANGE"
    elif any(
        outcome == "INDETERMINATE" for outcome in required_outcomes.values()
    ):
        outcome = "INDETERMINATE"
    else:
        outcome = "PASS"
    body = {
        "schema_version": SCHEMA_VERSION,
        "kind": SUMMARY_KIND,
        "candidate_id": candidate["candidate_id"],
        "required_verifiers": required,
        "observed_verifiers": sorted(observed),
        "missing_required_verifiers": missing,
        "verifier_outcomes": required_outcomes,
        "verifier_attempts": {
            verifier: observed[verifier]["verifier_attempt"]
            for verifier in sorted(observed)
        },
        "outcome": outcome,
        "findings": normalized_findings,
        "findings_sha256": sha256_json(normalized_findings),
    }
    return {**body, "summary_sha256": sha256_json(body)}


def validate_verification_summary(
    value: Any,
    *,
    candidate_manifest: dict[str, Any],
    verification_receipts: list[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CandidateVerificationError("verification summary must be an object")
    expected = reduce_verifications(
        candidate_manifest=candidate_manifest,
        verification_receipts=verification_receipts,
    )
    if value != expected:
        raise CandidateVerificationError(
            "verification summary differs from deterministic reduction"
        )
    return expected


def _read_regular_json(path: Path) -> dict[str, Any]:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size > MAX_RECEIPT_BYTES
        ):
            raise CandidateVerificationError("immutable receipt file is unsafe")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateVerificationError(f"immutable receipt is unreadable: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise CandidateVerificationError(
            "immutable receipt must contain an object"
        )
    return value


def _safe_receipt_parent(path: Path) -> Path:
    parent = path.parent
    try:
        metadata = parent.lstat()
    except OSError as exc:
        raise CandidateVerificationError(
            f"immutable receipt parent is unreadable: {exc}"
        ) from exc
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise CandidateVerificationError(
            "immutable receipt parent must be a private owner-controlled directory"
        )
    return parent


def persist_immutable_receipt(
    path: Path,
    payload: dict[str, Any],
    *,
    validator: Callable[[Any], dict[str, Any]],
) -> bool:
    validated = validator(payload)
    encoded = (canonical_json(validated) + "\n").encode("utf-8")
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise CandidateVerificationError(
            "immutable receipt exceeds the size boundary"
        )
    parent = _safe_receipt_parent(path)
    try:
        existing = _read_regular_json(path)
    except CandidateVerificationError:
        if path.exists() or path.is_symlink():
            raise
    else:
        if validator(existing) != validated:
            raise CandidateVerificationError(
                "immutable same-round receipt changed"
            )
        return False
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        total = 0
        while total < len(encoded):
            written = os.write(descriptor, encoded[total:])
            if written <= 0:
                raise OSError("short immutable receipt write")
            total += written
        os.fsync(descriptor)
    except FileExistsError:
        existing = _read_regular_json(path)
        if validator(existing) != validated:
            raise CandidateVerificationError(
                "immutable same-round receipt changed"
            )
        return False
    except OSError as exc:
        raise CandidateVerificationError(
            f"immutable receipt could not be written: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    directory = os.open(
        parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    if validator(_read_regular_json(path)) != validated:
        raise CandidateVerificationError("immutable receipt readback mismatch")
    return True


def read_immutable_receipt(
    path: Path,
    *,
    validator: Callable[[Any], dict[str, Any]],
) -> dict[str, Any]:
    return validator(_read_regular_json(path))

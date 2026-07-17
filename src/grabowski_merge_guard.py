from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import subprocess
import threading
import time
from typing import Any
import weakref


_SHA40_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_OWNER_RE = re.compile(r"[A-Za-z0-9._:@-]{1,128}\Z")
_MERGE_GUARD_TTL_SECONDS = 300
_MERGE_GUARD_MAX_CHANGED_PATHS = 100
_MERGE_GUARD_MAX_CHANGED_PATH_BYTES = 8 * 1024
_MERGE_GUARD_REPLAY_PARAMETERS = frozenset({"merge_lease_snapshot", "merge_guard_receipt"})
_SERVER_ACTOR_SCHEMA_VERSION = 1
_SERVER_ACTOR_KIND = "grabowski_server_runtime_actor_identity"
_SERVER_ACTOR_TTL_SECONDS = 300
_SERVER_ACTOR_SECRET = secrets.token_bytes(32)
_SERVER_ACTOR_LOCK = threading.Lock()
_SERVER_ACTOR_SESSIONS: weakref.WeakKeyDictionary[Any, str] = weakref.WeakKeyDictionary()
_SERVER_ACTOR_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "owner_id",
        "profile",
        "issued_at_unix",
        "expires_at_unix",
        "proof_sha256",
    }
)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def issue_server_runtime_actor_identity(
    session: Any,
    *,
    profile: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Issue one short-lived, server-authenticated owner identity for an MCP session."""
    if session is None:
        raise ValueError("server runtime actor session is required")
    if _OWNER_RE.fullmatch(profile) is None:
        raise ValueError("server runtime actor profile is invalid")
    with _SERVER_ACTOR_LOCK:
        try:
            session_nonce = _SERVER_ACTOR_SESSIONS.get(session)
        except TypeError as exc:
            raise ValueError("server runtime actor session must support weak references") from exc
        if session_nonce is None:
            session_nonce = secrets.token_hex(32)
            try:
                _SERVER_ACTOR_SESSIONS[session] = session_nonce
            except TypeError as exc:
                raise ValueError("server runtime actor session must support weak references") from exc
    owner_digest = hmac.new(
        _SERVER_ACTOR_SECRET,
        b"owner\x00" + session_nonce.encode("ascii") + b"\x00" + profile.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    issued_at = int(time.time()) if now_unix is None else int(now_unix)
    payload: dict[str, Any] = {
        "schema_version": _SERVER_ACTOR_SCHEMA_VERSION,
        "kind": _SERVER_ACTOR_KIND,
        "owner_id": f"runtime-actor:{owner_digest}",
        "profile": profile,
        "issued_at_unix": issued_at,
        "expires_at_unix": issued_at + _SERVER_ACTOR_TTL_SECONDS,
    }
    payload["proof_sha256"] = hmac.new(
        _SERVER_ACTOR_SECRET,
        _canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return payload


def verify_server_runtime_actor_identity(
    value: Any,
    *,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Verify a server-issued runtime actor proof and return bounded receipt evidence."""
    if not isinstance(value, dict) or set(value) != _SERVER_ACTOR_KEYS:
        raise ValueError("server runtime actor identity shape is invalid")
    if value.get("schema_version") != _SERVER_ACTOR_SCHEMA_VERSION:
        raise ValueError("server runtime actor identity schema is invalid")
    if value.get("kind") != _SERVER_ACTOR_KIND:
        raise ValueError("server runtime actor identity kind is invalid")
    owner_id = value.get("owner_id")
    profile = value.get("profile")
    if not isinstance(owner_id, str) or _OWNER_RE.fullmatch(owner_id) is None:
        raise ValueError("server runtime actor owner is invalid")
    if not isinstance(profile, str) or _OWNER_RE.fullmatch(profile) is None:
        raise ValueError("server runtime actor profile is invalid")
    issued_at = value.get("issued_at_unix")
    expires_at = value.get("expires_at_unix")
    if not isinstance(issued_at, int) or isinstance(issued_at, bool):
        raise ValueError("server runtime actor issue time is invalid")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise ValueError("server runtime actor expiry is invalid")
    if expires_at - issued_at != _SERVER_ACTOR_TTL_SECONDS:
        raise ValueError("server runtime actor lifetime is invalid")
    current = int(time.time()) if now_unix is None else int(now_unix)
    if issued_at > current + 5 or expires_at < current:
        raise ValueError("server runtime actor identity is not current")
    unsigned = {key: value[key] for key in value if key != "proof_sha256"}
    expected_proof = hmac.new(
        _SERVER_ACTOR_SECRET,
        _canonical_json(unsigned).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    proof = value.get("proof_sha256")
    if not isinstance(proof, str) or not hmac.compare_digest(proof, expected_proof):
        raise ValueError("server runtime actor proof is invalid")
    return {
        "owner_id": owner_id,
        "profile": profile,
        "identity_sha256": _sha256_json(value),
        "issued_at_unix": issued_at,
        "expires_at_unix": expires_at,
    }


def _merge_guard_identifier(namespace: str, value: str) -> str:
    if not isinstance(namespace, str) or not namespace:
        raise ValueError("merge guard identifier namespace is required")
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("merge guard identifier value is invalid")
    digest = hashlib.sha256(
        namespace.encode("utf-8") + b"\x00" + value.encode("utf-8")
    ).hexdigest()
    return f"{namespace}-{digest}"


def merge_guard_repository_root(repo_path: Path) -> Path:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(repo_path),
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
        env={
            "HOME": str(Path.home()),
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    if completed.returncode != 0:
        raise RuntimeError("merge guard cannot resolve Git common directory")
    common_dir = Path(completed.stdout.strip()).resolve()
    if common_dir.name != ".git" or not common_dir.is_dir():
        raise RuntimeError("merge guard Git common directory is not a canonical .git directory")
    repository = common_dir.parent.resolve()
    if not repository.is_dir():
        raise RuntimeError("merge guard canonical repository root is unavailable")
    return repository


def merge_guard_resource_keys(
    repo_path: Path,
    *,
    repo_slug: str,
    pr_number: int,
    base: str,
    head: str,
) -> list[str]:
    repository_id = _merge_guard_identifier("repository", repo_slug.lower())
    base_branch_id = _merge_guard_identifier("branch", base)
    head_branch_id = _merge_guard_identifier("branch", head)
    return sorted(
        {
            f"component:github-repository:{repository_id}",
            f"component:github-branch:{repository_id}:{base_branch_id}",
            f"component:github-branch:{repository_id}:{head_branch_id}",
            f"service:github-main:{repository_id}",
            f"service:github-pr:{repository_id}:{pr_number}",
            f"gate:github-merge:{repository_id}:{base_branch_id}",
            f"deployment:github:{repository_id}:{base_branch_id}",
        }
    )


def _merge_guard_result_info(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {
            "returncode": 1,
            "stdout": "",
            "stderr": "runner returned non-object",
            "stdout_bytes": None,
            "stderr_bytes": None,
        }
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    if isinstance(stdout, bytes):
        stdout_text = stdout.decode("utf-8", errors="replace")
        stdout_bytes: bytes | None = stdout
    else:
        stdout_text = str(stdout)
        raw_stdout = result.get("stdout_bytes")
        stdout_bytes = raw_stdout if isinstance(raw_stdout, bytes) else None
    if isinstance(stderr, bytes):
        stderr_text = stderr.decode("utf-8", errors="replace")
        stderr_bytes: bytes | None = stderr
    else:
        stderr_text = str(stderr)
        raw_stderr = result.get("stderr_bytes")
        stderr_bytes = raw_stderr if isinstance(raw_stderr, bytes) else None
    return {
        "returncode": int(result.get("returncode", 1)),
        "stdout": stdout_text,
        "stderr": stderr_text,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
    }


class CaptainMergeGuardRunner:
    def __init__(
        self,
        *,
        repo_path: Path,
        action: dict[str, Any],
        parameters: dict[str, Any],
        github_runner: Any,
        execution_intent_sha256: str,
        lease_owner_id: str,
        server_actor_identity: dict[str, Any] | None = None,
    ) -> None:
        self.repo_path = repo_path.resolve()
        self.action = action
        self.parameters = parameters
        self.github_runner = github_runner
        self.execution_intent_sha256 = execution_intent_sha256
        self.lease_owner_id = lease_owner_id
        self.lease_owner_source = "execution-intent-context"
        self.server_actor_identity: dict[str, Any] | None = None
        self.server_actor_identity_error = False
        if server_actor_identity is not None:
            try:
                verified_actor = verify_server_runtime_actor_identity(server_actor_identity)
            except ValueError:
                self.lease_owner_id = ""
                self.server_actor_identity_error = True
            else:
                self.server_actor_identity = verified_actor
                self.lease_owner_id = str(verified_actor["owner_id"])
                self.lease_owner_source = "server-runtime-session-v1"
        self.owner_id: str | None = None
        self.resource_keys: list[str] = []
        self.held_resource_keys: list[str] = []
        self.acquisition: dict[str, Any] | None = None
        self.dispatch_called = False
        does_not_establish = [
            "merge_authority",
            "review_completeness",
            "ci_freshness",
            "authorization",
            "absence_of_noncooperating_external_github_actors",
        ]
        if self.server_actor_identity is None:
            does_not_establish.append("server_authenticated_lease_owner_identity")
        self.receipt: dict[str, Any] = {
            "schema_version": 1,
            "kind": "grabowski_captain_merge_lease_guard",
            "status": "not_reached",
            "contract_satisfied": False,
            "dispatch_called": False,
            "resource_keys": [],
            "lease_owner_binding": {
                "source": self.lease_owner_source,
                "server_authenticated": self.server_actor_identity is not None,
                "identity_sha256": (
                    self.server_actor_identity.get("identity_sha256")
                    if self.server_actor_identity is not None
                    else None
                ),
            },
            "does_not_establish": does_not_establish,
        }
        self.static_errors = self._static_binding_errors()
        if self.static_errors:
            self.receipt["status"] = "blocked_before_guard"
            self.receipt["errors"] = list(self.static_errors)

    def _static_binding_errors(self) -> list[str]:
        expected_head = str(self.parameters.get("expected_head", ""))
        expected_base_sha = str(self.parameters.get("expected_base_sha", ""))
        expected_diff = str(self.parameters.get("diff_sha256", ""))
        errors: list[str] = []
        if self.server_actor_identity_error:
            errors.append("merge_guard_server_actor_identity_invalid")
        if _OWNER_RE.fullmatch(self.lease_owner_id) is None:
            errors.append("merge_guard_lease_owner_invalid")
        if _SHA40_RE.fullmatch(expected_head) is None:
            errors.append("merge_guard_expected_head_invalid")
        if _SHA40_RE.fullmatch(expected_base_sha) is None:
            errors.append("merge_guard_expected_base_sha_invalid")
        if _SHA256_RE.fullmatch(expected_diff) is None:
            errors.append("merge_guard_expected_diff_sha256_invalid")
        replay_fields = sorted(_MERGE_GUARD_REPLAY_PARAMETERS.intersection(self.parameters))
        if replay_fields:
            errors.append("merge_guard_cached_snapshot_input_forbidden:" + ",".join(replay_fields))
        return errors

    def _live_bindings(self) -> tuple[dict[str, Any] | None, list[str]]:
        target = self.action["target"]
        repo_slug = str(target["repo"])
        pr_number = int(target["pr"])
        expected_base = str(target["base"])
        expected_head = str(self.parameters.get("expected_head", ""))
        expected_base_sha = str(self.parameters.get("expected_base_sha", ""))
        expected_diff = str(self.parameters.get("diff_sha256", ""))
        errors = list(self.static_errors)
        if errors:
            return None, errors

        view_args = [
            "pr",
            "view",
            str(pr_number),
            "--repo",
            repo_slug,
            "--json",
            "number,state,headRefName,headRefOid,baseRefName,baseRefOid,isDraft,mergeable,mergeStateStatus,changedFiles,files",
        ]
        try:
            view_raw = self.github_runner(self.repo_path, view_args)
        except Exception as exc:
            errors.append(f"merge_guard_live_view_exception:{type(exc).__name__}")
            return None, errors
        view_info = _merge_guard_result_info(view_raw)
        self.receipt["live_view"] = {
            "command": ["gh", *view_args],
            "returncode": view_info["returncode"],
            "stdout_sha256": hashlib.sha256(view_info["stdout"].encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(view_info["stderr"].encode()).hexdigest(),
        }
        if view_info["returncode"] != 0:
            errors.append("merge_guard_live_view_failed")
            return None, errors
        try:
            viewed = json.loads(view_info["stdout"])
        except json.JSONDecodeError:
            errors.append("merge_guard_live_view_invalid_json")
            return None, errors
        if not isinstance(viewed, dict):
            errors.append("merge_guard_live_view_not_object")
            return None, errors
        base_sha = viewed.get("baseRefOid")
        if not isinstance(base_sha, str) or _SHA40_RE.fullmatch(base_sha) is None:
            errors.append("merge_guard_base_sha_missing_or_invalid")
        elif base_sha != expected_base_sha:
            errors.append("merge_guard_base_sha_drift")
        if viewed.get("number") != pr_number:
            errors.append("merge_guard_pr_number_drift")
        if viewed.get("state") != "OPEN":
            errors.append("merge_guard_pr_not_open")
        if viewed.get("isDraft") is not False:
            errors.append("merge_guard_pr_draft_state_not_confirmed")
        head_branch = viewed.get("headRefName")
        if (
            not isinstance(head_branch, str)
            or not head_branch
            or "\x00" in head_branch
            or len(head_branch.encode("utf-8")) > 1024
        ):
            errors.append("merge_guard_head_branch_missing_or_invalid")
        if viewed.get("headRefOid") != expected_head:
            errors.append("merge_guard_head_drift")
        if viewed.get("baseRefName") != expected_base:
            errors.append("merge_guard_base_branch_drift")
        if viewed.get("mergeable") != "MERGEABLE":
            errors.append("merge_guard_mergeable_not_confirmed")
        if viewed.get("mergeStateStatus") != "CLEAN":
            errors.append("merge_guard_merge_state_not_clean")

        changed_files = viewed.get("changedFiles")
        raw_files = viewed.get("files")
        changed_paths: list[str] = []
        if type(changed_files) is not int or changed_files < 1:
            errors.append("merge_guard_changed_file_count_invalid")
        if not isinstance(raw_files, list):
            errors.append("merge_guard_changed_file_list_missing")
        else:
            for index, item in enumerate(raw_files):
                if not isinstance(item, dict):
                    errors.append(f"merge_guard_changed_file_invalid:{index}")
                    continue
                path = item.get("path")
                change_type = item.get("changeType")
                if (
                    not isinstance(path, str)
                    or not path
                    or path.startswith("/")
                    or "\x00" in path
                    or any(part in {"", ".", ".."} for part in path.split("/"))
                ):
                    errors.append(f"merge_guard_changed_path_invalid:{index}")
                    continue
                if change_type in {"RENAMED", "COPIED"}:
                    errors.append(f"merge_guard_changed_path_requires_previous_name:{index}")
                    continue
                if change_type not in {"ADDED", "MODIFIED", "DELETED"}:
                    errors.append(f"merge_guard_change_type_invalid:{index}")
                    continue
                changed_paths.append(path)
            if type(changed_files) is int and changed_files > _MERGE_GUARD_MAX_CHANGED_PATHS:
                errors.append("merge_guard_changed_file_count_exceeds_supported_limit")
            if type(changed_files) is int and changed_files != len(raw_files):
                errors.append("merge_guard_changed_file_list_incomplete")
            if len(raw_files) > _MERGE_GUARD_MAX_CHANGED_PATHS:
                errors.append("merge_guard_changed_path_count_exceeds_limit")
            if len(changed_paths) != len(set(changed_paths)):
                errors.append("merge_guard_changed_paths_duplicate")
        changed_paths = sorted(set(changed_paths))
        if not changed_paths:
            errors.append("merge_guard_changed_paths_empty")
        elif len(_canonical_json(changed_paths).encode("utf-8")) > (
            _MERGE_GUARD_MAX_CHANGED_PATH_BYTES
        ):
            errors.append("merge_guard_changed_paths_exceed_byte_limit")

        diff_args = ["pr", "diff", str(pr_number), "--repo", repo_slug]
        try:
            diff_raw = self.github_runner(self.repo_path, diff_args)
        except Exception as exc:
            errors.append(f"merge_guard_live_diff_exception:{type(exc).__name__}")
            return None, errors
        diff_info = _merge_guard_result_info(diff_raw)
        if isinstance(diff_info.get("stdout_bytes"), bytes):
            live_diff_bytes = diff_info["stdout_bytes"]
            diff_canonicalization = "raw-command-bytes"
        else:
            live_diff_bytes = diff_info["stdout"].encode("utf-8")
            diff_canonicalization = "utf8-runner-text-exact-fallback"
        live_diff_sha256 = hashlib.sha256(live_diff_bytes).hexdigest()
        self.receipt["live_diff"] = {
            "command": ["gh", *diff_args],
            "returncode": diff_info["returncode"],
            "bytes": len(live_diff_bytes),
            "canonicalization": diff_canonicalization,
            "sha256": live_diff_sha256,
            "stderr_sha256": hashlib.sha256(diff_info["stderr"].encode()).hexdigest(),
        }
        if diff_info["returncode"] != 0:
            errors.append("merge_guard_live_diff_failed")
        elif not live_diff_bytes:
            errors.append("merge_guard_live_diff_empty")
        elif live_diff_sha256 != expected_diff:
            errors.append("merge_guard_diff_drift")
        bindings = {
            "repository": repo_slug,
            "pull_request": pr_number,
            "base_branch": expected_base,
            "base_sha": base_sha,
            "expected_base_sha": expected_base_sha,
            "head_branch": head_branch,
            "head_sha": expected_head,
            "diff_sha256": live_diff_sha256,
            "execution_intent_sha256": self.execution_intent_sha256,
            "changed_paths": changed_paths,
            "changed_paths_sha256": _sha256_json(changed_paths),
        }
        return bindings, errors

    def _revalidate_dispatch_bindings(self, bindings: dict[str, Any]) -> list[str]:
        target = self.action["target"]
        view_args = [
            "pr",
            "view",
            str(target["pr"]),
            "--repo",
            str(target["repo"]),
            "--json",
            "number,state,headRefName,headRefOid,baseRefName,baseRefOid,isDraft,mergeable,mergeStateStatus",
        ]
        errors: list[str] = []
        try:
            raw = self.github_runner(self.repo_path, view_args)
        except Exception as exc:
            errors.append(f"merge_guard_dispatch_revalidation_exception:{type(exc).__name__}")
            self.receipt["dispatch_revalidation"] = {
                "command": ["gh", *view_args],
                "errors": list(errors),
            }
            return errors
        info = _merge_guard_result_info(raw)
        stdout_bytes = (
            info["stdout_bytes"]
            if isinstance(info.get("stdout_bytes"), bytes)
            else info["stdout"].encode("utf-8")
        )
        self.receipt["dispatch_revalidation"] = {
            "command": ["gh", *view_args],
            "returncode": info["returncode"],
            "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
            "stderr_sha256": hashlib.sha256(info["stderr"].encode("utf-8")).hexdigest(),
        }
        if info["returncode"] != 0:
            errors.append("merge_guard_dispatch_revalidation_failed")
            return errors
        try:
            viewed = json.loads(info["stdout"])
        except json.JSONDecodeError:
            errors.append("merge_guard_dispatch_revalidation_invalid_json")
            return errors
        if not isinstance(viewed, dict):
            errors.append("merge_guard_dispatch_revalidation_not_object")
            return errors
        expected = {
            "number": bindings["pull_request"],
            "state": "OPEN",
            "headRefName": bindings["head_branch"],
            "headRefOid": bindings["head_sha"],
            "baseRefName": bindings["base_branch"],
            "baseRefOid": bindings["base_sha"],
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "mergeStateStatus": "CLEAN",
        }
        for field, expected_value in expected.items():
            if viewed.get(field) != expected_value:
                errors.append(f"merge_guard_dispatch_revalidation_drift:{field}")
        self.receipt["dispatch_revalidation"]["errors"] = list(errors)
        self.receipt["dispatch_revalidation"]["binding_sha256"] = _sha256_json(
            {field: viewed.get(field) for field in sorted(expected)}
        )
        return errors

    def __call__(self, repo_path: Path, args: list[str]) -> dict[str, Any]:
        if args[:2] != ["pr", "merge"]:
            return self.github_runner(repo_path, args)
        if self.receipt["status"] != "not_reached":
            raise RuntimeError("merge lease guard permits exactly one merge dispatch")
        observed_at_ns = time.time_ns()
        try:
            resource_repository = merge_guard_repository_root(self.repo_path)
        except Exception as exc:
            self.receipt["status"] = "blocked_before_guard"
            self.receipt["observed_at_unix_ns"] = observed_at_ns
            self.receipt["errors"] = [f"merge_guard_repository_identity_failed:{type(exc).__name__}:{exc}"]
            raise RuntimeError("merge lease guard repository identity failed") from exc
        bindings, errors = self._live_bindings()
        self.receipt["observed_at_unix_ns"] = observed_at_ns
        self.receipt["bindings"] = bindings
        if errors or bindings is None:
            self.receipt["status"] = "blocked_before_guard"
            self.receipt["errors"] = errors
            raise RuntimeError("merge lease guard blocked: " + "; ".join(errors))

        import grabowski_resources as resources

        target = self.action["target"]
        bindings["local_resource_repository"] = str(resource_repository)
        absolute_changed_paths = [
            str(Path(resource_repository, path))
            for path in bindings["changed_paths"]
        ]
        self.resource_keys = merge_guard_resource_keys(
            resource_repository,
            repo_slug=str(target["repo"]),
            pr_number=int(target["pr"]),
            base=str(target["base"]),
            head=str(bindings["head_branch"]),
        )
        self.owner_id = "captain-merge:" + hashlib.sha256(
            f"{self.execution_intent_sha256}:{time.time_ns()}".encode("utf-8")
        ).hexdigest()[:24]
        metadata = {
            "merge_guard": {
                **bindings,
                "resource_keys_sha256": _sha256_json(self.resource_keys),
                "observed_at_unix_ns": observed_at_ns,
            }
        }
        try:
            self.acquisition = resources.acquire_merge_guard_resources(
                self.owner_id,
                self.lease_owner_id,
                self.resource_keys,
                repository=str(resource_repository),
                changed_paths=absolute_changed_paths,
                purpose=(
                    f"Captain atomic merge guard for {bindings['repository']}#{bindings['pull_request']} "
                    f"head={bindings['head_sha']} diff={bindings['diff_sha256']}"
                ),
                ttl_seconds=_MERGE_GUARD_TTL_SECONDS,
                metadata=metadata,
            )
        except Exception as exc:
            self.receipt["status"] = "blocked_by_live_lease"
            self.receipt["errors"] = [f"{type(exc).__name__}:{exc}"]
            self.receipt["resource_keys"] = self.resource_keys
            raise RuntimeError("merge lease guard acquisition failed") from exc

        self.held_resource_keys = list(self.acquisition["held_resource_keys"])
        lease_snapshot = {
            "observed_leases": self.acquisition["observed_leases"],
            "acquired_leases": self.acquisition["acquired_leases"],
            "held_resource_keys": self.held_resource_keys,
        }
        self.receipt.update(
            {
                "status": "guard_acquired",
                "contract_satisfied": True,
                "owner_id": self.owner_id,
                "resource_keys": self.resource_keys,
                "resource_keys_sha256": _sha256_json(self.resource_keys),
                "lease_snapshot": lease_snapshot,
                "lease_snapshot_sha256": _sha256_json(lease_snapshot),
                "lease_owner_id": self.lease_owner_id,
                "lease_owner_source": self.lease_owner_source,
                "changed_paths": bindings["changed_paths"],
                "changed_paths_sha256": bindings["changed_paths_sha256"],
                "held_resource_keys": self.held_resource_keys,
                "guard_acquired_at_unix": self.acquisition["observed_at_unix"],
                "lease_snapshot_observed_at_unix_ns": self.acquisition[
                    "observed_at_unix_ns"
                ],
                "guard_expires_at_unix": self.acquisition["expires_at_unix"],
            }
        )
        revalidation_errors = self._revalidate_dispatch_bindings(bindings)
        if revalidation_errors:
            self.receipt["status"] = "blocked_after_guard_revalidation"
            self.receipt["contract_satisfied"] = False
            self.receipt["errors"] = revalidation_errors
            raise RuntimeError(
                "merge lease guard dispatch revalidation blocked: "
                + "; ".join(revalidation_errors)
            )
        self.receipt["dispatch_at_unix_ns"] = time.time_ns()
        self.receipt["dispatch_called"] = True
        self.dispatch_called = True
        return self.github_runner(repo_path, args)

    def finalize(self, execution_result: dict[str, Any]) -> None:
        import grabowski_resources as resources

        self.receipt["completed_at_unix_ns"] = time.time_ns()
        cleanup_required = self.acquisition is not None and self.owner_id is not None
        cleanup_passed = True
        cleanup_error: str | None = None
        self.receipt["external_merge_observed"] = bool(
            execution_result.get("remote_mutation_observed") and not self.dispatch_called
        )
        self.receipt["merge_command_returncode"] = execution_result.get("merge_returncode")
        self.receipt["post_merge_verification_passed"] = execution_result.get("verification_passed") is True
        if self.acquisition is not None and self.owner_id is not None:
            try:
                released = resources.release_resources(
                    self.owner_id, self.held_resource_keys, force=False
                )
                self.receipt["release"] = released
                released_keys = sorted(item["resource_key"] for item in released.get("released", []))
                if released_keys != self.held_resource_keys:
                    cleanup_passed = False
                    cleanup_error = "merge lease guard release incomplete"
                    self.receipt["status"] = "guard_release_incomplete"
                    self.receipt["contract_satisfied"] = False
                elif self.receipt["status"] == "guard_acquired":
                    self.receipt["status"] = "completed"
                else:
                    self.receipt["status"] = self.receipt["status"] + "_released"
            except Exception as exc:
                cleanup_passed = False
                cleanup_error = "merge lease guard release failed"
                self.receipt["status"] = "guard_release_failed"
                self.receipt["contract_satisfied"] = False
                self.receipt["release_error"] = f"{type(exc).__name__}:{exc}"
        if (
            not self.dispatch_called
            and self.receipt["status"] != "not_reached"
        ):
            execution_result["execution_invoked"] = False
            execution_result["execution_attempted"] = False
            execution_result["command_returned"] = False
            execution_result["merge_dispatch_blocked_by_lease_guard"] = True
            if self.receipt["external_merge_observed"]:
                execution_result["verification_error"] = (
                    "external_merge_observed_after_merge_guard_block"
                )
                execution_result["post_verify_errors"] = [
                    "external_merge_observed_after_merge_guard_block"
                ]
            else:
                execution_result["verification_error"] = (
                    "merge_dispatch_blocked_by_lease_guard"
                )
                execution_result["post_verify_errors"] = [
                    "merge_dispatch_blocked_by_lease_guard"
                ]
        execution_result["merge_guard_cleanup_required"] = cleanup_required
        execution_result["merge_guard_cleanup_passed"] = cleanup_passed
        if cleanup_error is not None:
            execution_result["merge_guard_cleanup_error"] = cleanup_error
            operational_errors = list(execution_result.get("operational_errors", []))
            operational_errors.append(cleanup_error)
            execution_result["operational_errors"] = operational_errors
        self.receipt["cleanup_required"] = cleanup_required
        self.receipt["cleanup_passed"] = cleanup_passed
        if cleanup_error is not None:
            self.receipt["cleanup_error"] = cleanup_error
        receipt_material = dict(self.receipt)
        self.receipt["receipt_sha256"] = _sha256_json(receipt_material)
        execution_result["merge_lease_guard"] = self.receipt

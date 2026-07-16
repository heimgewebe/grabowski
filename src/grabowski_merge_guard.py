from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
from typing import Any


_SHA40_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_OWNER_RE = re.compile(r"[A-Za-z0-9._:@-]{1,128}\Z")
_MERGE_GUARD_TTL_SECONDS = 300
_MERGE_GUARD_MAX_CHANGED_PATHS = 128
_MERGE_GUARD_MAX_CHANGED_PATH_BYTES = 8 * 1024
_MERGE_GUARD_REPLAY_PARAMETERS = frozenset({"merge_lease_snapshot", "merge_guard_receipt"})


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _merge_guard_slug(repo_slug: str) -> str:
    return repo_slug.replace("/", "-")


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
    slug = _merge_guard_slug(repo_slug)
    return sorted(
        {
            f"component:github-repository:{slug}",
            f"component:github-branch:{slug}:{base}",
            f"component:github-branch:{slug}:{head}",
            f"service:github-main:{slug}",
            f"service:github-pr:{slug}-{pr_number}",
            f"gate:github-merge:{slug}:{base}",
            f"deployment:github:{slug}:{base}",
        }
    )


def _merge_guard_result_info(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {"returncode": 1, "stdout": "", "stderr": "runner returned non-object"}
    return {
        "returncode": int(result.get("returncode", 1)),
        "stdout": str(result.get("stdout", "")),
        "stderr": str(result.get("stderr", "")),
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
    ) -> None:
        self.repo_path = repo_path.resolve()
        self.action = action
        self.parameters = parameters
        self.github_runner = github_runner
        self.execution_intent_sha256 = execution_intent_sha256
        self.lease_owner_id = lease_owner_id
        self.owner_id: str | None = None
        self.resource_keys: list[str] = []
        self.held_resource_keys: list[str] = []
        self.acquisition: dict[str, Any] | None = None
        self.dispatch_called = False
        self.receipt: dict[str, Any] = {
            "schema_version": 1,
            "kind": "grabowski_captain_merge_lease_guard",
            "status": "not_reached",
            "contract_satisfied": False,
            "dispatch_called": False,
            "resource_keys": [],
            "does_not_establish": [
                "merge_authority",
                "review_completeness",
                "ci_freshness",
                "authorization",
                "absence_of_noncooperating_external_github_actors",
            ],
        }

    def _live_bindings(self) -> tuple[dict[str, Any] | None, list[str]]:
        target = self.action["target"]
        repo_slug = str(target["repo"])
        pr_number = int(target["pr"])
        expected_base = str(target["base"])
        expected_head = str(self.parameters.get("expected_head", ""))
        expected_diff = str(self.parameters.get("diff_sha256", ""))
        errors: list[str] = []
        if _OWNER_RE.fullmatch(self.lease_owner_id) is None:
            errors.append("merge_guard_lease_owner_invalid")
        if _SHA40_RE.fullmatch(expected_head) is None:
            errors.append("merge_guard_expected_head_invalid")
        if _SHA256_RE.fullmatch(expected_diff) is None:
            errors.append("merge_guard_expected_diff_sha256_invalid")
        replay_fields = sorted(_MERGE_GUARD_REPLAY_PARAMETERS.intersection(self.parameters))
        if replay_fields:
            errors.append("merge_guard_cached_snapshot_input_forbidden:" + ",".join(replay_fields))

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
        complete_diff = diff_info["stdout"]
        if complete_diff and not complete_diff.endswith("\n"):
            complete_diff += "\n"
        live_diff_bytes = complete_diff.encode("utf-8")
        live_diff_sha256 = hashlib.sha256(live_diff_bytes).hexdigest()
        self.receipt["live_diff"] = {
            "command": ["gh", *diff_args],
            "returncode": diff_info["returncode"],
            "bytes": len(live_diff_bytes),
            "canonicalization": "utf8-single-terminal-newline",
            "sha256": live_diff_sha256,
            "stderr_sha256": hashlib.sha256(diff_info["stderr"].encode()).hexdigest(),
        }
        if diff_info["returncode"] != 0:
            errors.append("merge_guard_live_diff_failed")
        elif live_diff_sha256 != expected_diff:
            errors.append("merge_guard_diff_drift")
        bindings = {
            "repository": repo_slug,
            "pull_request": pr_number,
            "base_branch": expected_base,
            "base_sha": base_sha,
            "head_branch": head_branch,
            "head_sha": expected_head,
            "diff_sha256": live_diff_sha256,
            "execution_intent_sha256": self.execution_intent_sha256,
            "changed_paths": changed_paths,
            "changed_paths_sha256": _sha256_json(changed_paths),
        }
        return bindings, errors

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
        self.receipt["dispatch_at_unix_ns"] = time.time_ns()
        self.receipt["dispatch_called"] = True
        self.dispatch_called = True
        return self.github_runner(repo_path, args)

    def finalize(self, execution_result: dict[str, Any]) -> None:
        import grabowski_resources as resources

        self.receipt["completed_at_unix_ns"] = time.time_ns()
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
                    self.receipt["status"] = "guard_release_incomplete"
                    self.receipt["contract_satisfied"] = False
                    execution_result["verification_passed"] = False
                    execution_result["verification_error"] = "merge lease guard release incomplete"
                else:
                    self.receipt["status"] = "completed"
            except Exception as exc:
                self.receipt["status"] = "guard_release_failed"
                self.receipt["contract_satisfied"] = False
                self.receipt["release_error"] = f"{type(exc).__name__}:{exc}"
                execution_result["verification_passed"] = False
                execution_result["verification_error"] = "merge lease guard release failed"
        elif (
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
        receipt_material = dict(self.receipt)
        self.receipt["receipt_sha256"] = _sha256_json(receipt_material)
        execution_result["merge_lease_guard"] = self.receipt

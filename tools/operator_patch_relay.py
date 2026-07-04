#!/usr/bin/env python3
"""Apply a local patch file through a bounded Operator Relay receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


DEFAULT_MAX_PATCH_BYTES = 2 * 1024 * 1024


class RelayError(RuntimeError):
    def __init__(self, message: str, returncode: int = 2) -> None:
        super().__init__(message)
        self.returncode = returncode


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_git(repo: Path, args: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode != 0:
        raise RelayError(result.stderr.strip() or result.stdout.strip() or "git command failed")
    return result


def changed_file_names(repo: Path) -> list[str]:
    worktree = run_git(repo, ["diff", "--name-only"], check=True).stdout.splitlines()
    staged = run_git(repo, ["diff", "--cached", "--name-only"], check=True).stdout.splitlines()
    return sorted(set(worktree) | set(staged))


def check_reported_conflicts(result: subprocess.CompletedProcess[str]) -> bool:
    lines = "\n".join([result.stdout, result.stderr]).splitlines()
    for line in lines:
        status = line.strip().lower()
        if status.startswith("applied patch to ") and (
            status.endswith(" with conflicts.") or status.endswith(" with conflicts")
        ):
            return True
    return False


def write_receipt(path: Path | None, receipt: dict[str, Any]) -> None:
    payload = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if path is None:
        print(payload, end="")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    tmp.replace(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check or apply one local patch file with a JSON receipt."
    )
    parser.add_argument("--repo", required=True, help="Git repository path")
    parser.add_argument("--patch", required=True, help="Patch file path")
    parser.add_argument(
        "--mode",
        choices=("check", "apply"),
        default="check",
        help="Only check the patch, or apply it after a successful check",
    )
    parser.add_argument("--expected-head", help="Required current HEAD SHA")
    parser.add_argument("--allow-dirty", action="store_true", help="Allow dirty repo before applying")
    parser.add_argument("--three-way", action="store_true", help="Use git apply --3way when applying")
    parser.add_argument("--receipt", help="Write JSON receipt to this path instead of stdout")
    parser.add_argument(
        "--max-patch-bytes",
        type=int,
        default=DEFAULT_MAX_PATCH_BYTES,
        help="Reject patch files larger than this many bytes",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).expanduser().resolve()
    patch = Path(args.patch).expanduser().resolve()
    receipt_path = Path(args.receipt).expanduser().resolve() if args.receipt else None
    receipt: dict[str, Any] = {
        "schema_version": "operator-patch-relay.v1",
        "mode": args.mode,
        "repo": str(repo),
        "patch": str(patch),
        "expected_head": args.expected_head,
        "allow_dirty": bool(args.allow_dirty),
        "three_way": bool(args.three_way),
        "state": "started",
    }

    try:
        if not repo.is_dir():
            raise RelayError("repo directory does not exist")
        if not (repo / ".git").exists():
            raise RelayError("repo is not a git checkout")
        if not patch.is_file():
            raise RelayError("patch file does not exist")
        patch_size = patch.stat().st_size
        receipt["patch_size_bytes"] = patch_size
        if patch_size > args.max_patch_bytes:
            raise RelayError("patch file exceeds max-patch-bytes")
        receipt["patch_sha256"] = sha256_file(patch)

        head_before = run_git(repo, ["rev-parse", "HEAD"], check=True).stdout.strip()
        receipt["head_before"] = head_before
        if args.expected_head and head_before != args.expected_head:
            raise RelayError("HEAD does not match expected-head")

        status_before = run_git(repo, ["status", "--porcelain=v1", "--untracked-files=normal"], check=True).stdout
        receipt["dirty_before"] = bool(status_before.strip())
        if status_before.strip() and not args.allow_dirty:
            raise RelayError("repo is dirty; pass --allow-dirty to override")

        check_args = ["apply", "--check"]
        if args.three_way:
            check_args.append("--3way")
        check_args.append(str(patch))
        check_result = run_git(repo, check_args)
        receipt["check_returncode"] = check_result.returncode
        receipt["check_stdout"] = check_result.stdout[-4000:]
        receipt["check_stderr"] = check_result.stderr[-4000:]
        receipt["check_conflicts"] = bool(args.three_way and check_reported_conflicts(check_result))
        if check_result.returncode != 0:
            raise RelayError("git apply --check failed", returncode=1)
        if receipt["check_conflicts"]:
            raise RelayError("git apply --check --3way reported conflicts", returncode=1)

        if args.mode == "apply":
            apply_args = ["apply"]
            if args.three_way:
                apply_args.append("--3way")
            apply_args.append(str(patch))
            apply_result = run_git(repo, apply_args)
            receipt["apply_returncode"] = apply_result.returncode
            receipt["apply_stdout"] = apply_result.stdout[-4000:]
            receipt["apply_stderr"] = apply_result.stderr[-4000:]
            if apply_result.returncode != 0:
                raise RelayError("git apply failed", returncode=1)

        head_after = run_git(repo, ["rev-parse", "HEAD"], check=True).stdout.strip()
        status_after = run_git(repo, ["status", "--short", "--untracked-files=normal"], check=True).stdout.splitlines()
        changed_files = changed_file_names(repo)
        receipt.update(
            {
                "head_after": head_after,
                "dirty_after": bool(status_after),
                "status_after": status_after[:200],
                "changed_files": changed_files[:200],
                "state": "applied" if args.mode == "apply" else "checked",
                "exit_code": 0,
                "next_decision_required": "review diff, run tests, then decide commit/push/stop",
            }
        )
        write_receipt(receipt_path, receipt)
        return 0
    except RelayError as error:
        receipt.update(
            {
                "state": "failed",
                "error": str(error),
                "exit_code": error.returncode,
                "next_decision_required": "inspect receipt and decide whether to revise patch or stop",
            }
        )
        write_receipt(receipt_path, receipt)
        return error.returncode


if __name__ == "__main__":
    raise SystemExit(main())

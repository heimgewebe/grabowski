from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
for path in (str(SRC), str(TOOLS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from grabowski_pr_diff import (  # noqa: E402
    GITHUB_PR_DIFF_IDENTITY_CANONICALIZATION,
    canonicalize_github_pr_diff_identity,
    github_pr_diff_identity_sha256,
)


def _load_tool(name: str):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_variable_github_index_abbreviations_have_one_identity() -> None:
    short = (
        b"diff --git a/demo.txt b/demo.txt\n"
        b"index f43b5a8..17e3326 100644\n"
        b"--- a/demo.txt\n+++ b/demo.txt\n@@ -1 +1 @@\n-old\n+new\n"
    )
    long = short.replace(b"f43b5a8..17e3326", b"f43b5a86..17e33268")

    assert canonicalize_github_pr_diff_identity(short) == short
    assert canonicalize_github_pr_diff_identity(long) == short
    assert github_pr_diff_identity_sha256(short) == github_pr_diff_identity_sha256(long)
    assert hashlib.sha256(short).hexdigest() != hashlib.sha256(long).hexdigest()


def test_patch_content_still_changes_identity() -> None:
    first = b"index aaaaaaa1..bbbbbbb2 100644\n@@ -1 +1 @@\n-old\n+new\n"
    second = first.replace(b"+new\n", b"+different\n")

    assert github_pr_diff_identity_sha256(first) != github_pr_diff_identity_sha256(second)


def test_non_index_bytes_and_crlf_are_preserved_exactly() -> None:
    raw = b"captain-diff\r\n"

    assert canonicalize_github_pr_diff_identity(raw) == raw
    assert github_pr_diff_identity_sha256(raw) == hashlib.sha256(raw).hexdigest()


def test_index_mode_and_crlf_are_preserved() -> None:
    raw = b"index abcdef012345..123456789abc 100755\r\nnext\r\n"
    expected = b"index abcdef0..1234567 100755\r\nnext\r\n"

    assert canonicalize_github_pr_diff_identity(raw) == expected


def test_review_gate_ci_uses_shared_identity(monkeypatch) -> None:
    module = _load_tool("pr_review_gate_ci")
    raw = b"index f43b5a86..17e33268 100644\n@@ -1 +1 @@\n-a\n+b\n"
    monkeypatch.setattr(module, "_run_bytes", lambda _argv: raw)

    assert module.current_diff_sha256("heimgewebe/metarepo", 714) == github_pr_diff_identity_sha256(raw)


def test_legacy_claude_live_check_uses_shared_identity(monkeypatch) -> None:
    module = _load_tool("external_review_claude")
    raw = b"index f43b5a86..17e33268 100644\n@@ -1 +1 @@\n-a\n+b\n"
    completed = subprocess.CompletedProcess(["gh"], 0, stdout=raw, stderr=b"")
    monkeypatch.setattr(module, "run_checked", lambda *args, **kwargs: completed)

    assert module.current_pr_diff_sha256(ROOT, 714) == github_pr_diff_identity_sha256(raw)


def test_canonicalization_version_is_explicit() -> None:
    assert GITHUB_PR_DIFF_IDENTITY_CANONICALIZATION == "github-index-oid-prefix-7-v1"

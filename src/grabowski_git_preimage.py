from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess
from typing import Any, Callable

import grabowski_consumer_surface as consumer_surface


def capture_branch_preimage(
    repo: Path,
    probe: Callable[[list[str]], subprocess.CompletedProcess[bytes]],
    *,
    require_attached: bool = True,
) -> dict[str, Any]:
    """Build one exact branch/index CAS preimage from a caller-owned Git probe."""
    branch_probe = probe(["symbolic-ref", "--quiet", "--short", "HEAD"])
    branch: str | None = None
    if branch_probe.returncode == 0:
        branch = branch_probe.stdout.decode("utf-8", errors="strict").strip()
        if not branch:
            raise RuntimeError("Git branch observation returned an empty branch")
    elif branch_probe.returncode != 1:
        raise RuntimeError("Git branch observation failed")
    if require_attached and branch is None:
        raise PermissionError("Local branch mutation requires an attached Git branch")

    head_probe = probe(["rev-parse", "--verify", "--quiet", "HEAD"])
    head: str | None
    head_state: str
    if head_probe.returncode == 0:
        head = head_probe.stdout.decode("ascii", errors="strict").strip()
        if re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", head) is None:
            raise RuntimeError("Git HEAD observation is not an object id")
        head_state = "present"
    elif head_probe.returncode == 1 and branch is not None:
        head = None
        head_state = "unborn"
    else:
        raise RuntimeError("Git HEAD observation failed")

    index_probe = probe(["ls-files", "--stage", "-z"])
    if index_probe.returncode != 0:
        raise RuntimeError("Git index observation failed")
    index_sha256 = hashlib.sha256(index_probe.stdout).hexdigest()

    operation_refs: dict[str, str] = {}
    for name in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "REBASE_HEAD"):
        ref_probe = probe(["rev-parse", "--verify", "--quiet", name])
        if ref_probe.returncode == 0:
            value = ref_probe.stdout.decode("ascii", errors="strict").strip()
            if value:
                operation_refs[name] = value
        elif ref_probe.returncode != 1:
            raise RuntimeError(f"Git operation-state observation failed: {name}")

    material: dict[str, Any] = {
        "schema_version": 1,
        "repository": str(repo),
        "branch": branch,
        "head": head,
        "head_state": head_state,
        "index_sha256": index_sha256,
        "operation_refs": operation_refs,
    }
    return {
        **material,
        "preimage_sha256": hashlib.sha256(
            consumer_surface.canonical_json_bytes(material)
        ).hexdigest(),
    }

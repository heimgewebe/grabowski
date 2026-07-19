from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any, Callable

import grabowski_repoground_catalog as repoground_catalog

MAX_MANIFEST_BYTES = 1_000_000
DEFAULT_PUBLICATION_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_REPOBRIEF_PUBLICATION_ROOT",
        str(Path.home() / "repos" / "manifest-publications" / "bundles"),
    )
).expanduser()
EXCLUDED_REPOSITORIES = {"vault-gewebe"}
SEGMENT_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,198}[A-Za-z0-9])?\Z")
DEFAULT_REFS = ("main", "master")

CommandRunner = Callable[[Path, list[str]], dict[str, Any]]


def unavailable(status: str, **values: Any) -> dict[str, Any]:
    return {"available": False, "status": status, **values}


def safe_segment(value: str) -> str | None:
    if value in {".", ".."} or "/" in value or "\\" in value:
        return None
    return value if SEGMENT_RE.fullmatch(value) else None


def repo_from_remote(remote: str | None, root: str) -> str | None:
    if remote:
        cleaned = remote.strip().removesuffix(".git")
        if "github.com" in cleaned:
            candidate = cleaned.rsplit("/", 1)[-1]
            if ":" in candidate:
                candidate = candidate.rsplit(":", 1)[-1]
            segment = safe_segment(candidate)
            if segment:
                return segment
    return safe_segment(Path(root).name)


def optional_git(repo: Path, runner: CommandRunner, argv: list[str]) -> dict[str, Any]:
    try:
        return runner(repo, argv)
    except Exception as exc:
        return {"returncode": 1, "stdout": "", "stderr": str(exc)}


def ref_candidates(
    repo: Path, runner: CommandRunner, orientation: dict[str, Any]
) -> list[str]:
    candidates: list[str] = []
    origin_head = optional_git(
        repo, runner, ["symbolic-ref", "refs/remotes/origin/HEAD", "--short"]
    )
    if origin_head.get("returncode") == 0:
        raw = str(origin_head.get("stdout") or "").strip()
        if raw.startswith("origin/"):
            candidates.append(raw.split("/", 1)[1])
    upstream = orientation.get("upstream")
    if isinstance(upstream, str) and upstream.startswith("origin/"):
        branch = upstream.split("/", 1)[1]
        if branch in DEFAULT_REFS:
            candidates.append(branch)
    current = orientation.get("branch")
    if isinstance(current, str) and current in DEFAULT_REFS:
        candidates.append(current)
    candidates.extend(DEFAULT_REFS)
    valid = [candidate for candidate in candidates if safe_segment(candidate)]
    return list(dict.fromkeys(valid))


def _relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def _resolve_bounded(base: Path, raw: str, *, kind: str) -> Path:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ValueError(f"invalid {kind} path")
    raw_path = Path(raw)
    if raw_path.is_absolute():
        raise ValueError(f"absolute {kind} path is not allowed")
    resolved = (base / raw_path).resolve()
    allowed = base.resolve()
    if not _relative_to(resolved, allowed):
        raise ValueError(f"{kind} path escapes bundle root")
    return resolved


def sidecar_path(
    manifest: dict[str, Any], manifest_path: Path, role: str
) -> str | None:
    manifest_base = manifest_path.parent.resolve()
    artifacts = manifest.get("artifacts")
    bundle = manifest.get("bundleManifest")
    if isinstance(bundle, dict) and isinstance(bundle.get("path"), str):
        bundle_path = _resolve_bounded(
            manifest_base, bundle["path"], kind="bundleManifest"
        )
        bundle_base = bundle_path.parent.resolve()
        for artifact in artifacts or []:
            if (
                isinstance(artifact, dict)
                and artifact.get("role") == role
                and isinstance(artifact.get("path"), str)
            ):
                return str(
                    _resolve_bounded(
                        bundle_base,
                        artifact["path"],
                        kind=f"artifact:{role}",
                    )
                )
        return None
    if isinstance(artifacts, list):
        for artifact in artifacts:
            if (
                isinstance(artifact, dict)
                and artifact.get("role") == role
                and isinstance(artifact.get("path"), str)
            ):
                return str(
                    _resolve_bounded(
                        manifest_base,
                        artifact["path"],
                        kind=f"artifact:{role}",
                    )
                )
    return None


def _publication_roots(publication_root: Path) -> tuple[Path, Path]:
    if publication_root.name == "bundles":
        return publication_root, publication_root.parent
    nested = publication_root / "bundles"
    canonical_root = (
        nested if nested.is_dir() and not nested.is_symlink() else publication_root
    )
    return canonical_root, publication_root


def _canonical_manifest_resolution(
    publication_root: Path,
    repository: str,
    refs: list[str] | None = None,
) -> dict[str, Any]:
    disabled_legacy_root = publication_root / ".repoground-no-legacy-fallback"
    return repoground_catalog.resolve_catalog(
        publication_root,
        disabled_legacy_root,
        repo=repository,
        refs=refs,
    )


def _legacy_manifest_path(publication_root: Path, repository: str, ref: str) -> Path:
    return (
        publication_root / "external" / "repobrief" / repository / ref / "manifest.json"
    )


def read_manifest(
    manifest_path: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    parsed, error, _digest = repoground_catalog.read_json_object(
        manifest_path, MAX_MANIFEST_BYTES
    )
    if error is None and parsed is not None:
        return parsed, None
    if error == "missing":
        return None, unavailable("missing", manifest_path=str(manifest_path))
    if error == "too_large":
        return None, unavailable(
            "manifest_too_large",
            manifest_path=str(manifest_path),
            max_manifest_bytes=MAX_MANIFEST_BYTES,
        )
    if error in {"invalid_json", "root_not_object"}:
        return None, unavailable(
            "invalid_manifest",
            manifest_path=str(manifest_path),
            reason=error,
        )
    return None, unavailable(
        "manifest_read_error",
        manifest_path=str(manifest_path),
        reason=error or "invalid",
    )


def _freshness_status(snapshot_commit: object, current_head: object) -> str:
    if not isinstance(snapshot_commit, str) or not snapshot_commit:
        return "provenance_missing"
    if not isinstance(current_head, str) or not current_head:
        return "source_unavailable"
    return "fresh" if snapshot_commit == current_head else "stale"


def context(
    repo: Path,
    runner: CommandRunner,
    orientation: dict[str, Any],
    parameters: dict[str, Any],
) -> dict[str, Any]:
    raw_root = parameters.get("repobrief_publication_root")
    if raw_root is None:
        publication_root = DEFAULT_PUBLICATION_ROOT
    elif isinstance(raw_root, str) and raw_root:
        publication_root = Path(raw_root).expanduser()
    else:
        return unavailable(
            "invalid_parameter",
            reason="repobrief_publication_root must be a non-empty string",
        )
    if publication_root.is_symlink() or not publication_root.is_dir():
        return unavailable(
            "missing_publication_root",
            publication_root=str(publication_root),
            freshness_status="publication_unavailable",
        )

    remote_result = optional_git(repo, runner, ["remote", "get-url", "origin"])
    remote = (
        str(remote_result.get("stdout") or "").strip()
        if remote_result.get("returncode") == 0
        else None
    )
    repo_segment = repo_from_remote(remote, str(orientation.get("root") or repo))
    if not repo_segment:
        return unavailable(
            "unresolved_repository",
            reason="could not derive RepoGround repository segment",
            freshness_status="source_unavailable",
        )
    if repo_segment in EXCLUDED_REPOSITORIES:
        return unavailable(
            "excluded",
            repository=repo_segment,
            reason="repository is intentionally excluded from RepoGround fleet publication",
            freshness_status="publication_unavailable",
        )

    canonical_root, legacy_root = _publication_roots(publication_root)
    refs = ref_candidates(repo, runner, orientation)
    canonical_resolution = _canonical_manifest_resolution(
        canonical_root, repo_segment, refs
    )
    candidates: list[tuple[str, Path, str]] = [
        (str(item["ref"]), Path(str(item["manifest_path"])), "canonical_publication")
        for item in canonical_resolution.get("selected", [])
        if isinstance(item, dict)
        and isinstance(item.get("ref"), str)
        and isinstance(item.get("manifest_path"), str)
    ]
    canonical_identities = (canonical_resolution.get("aliases") or {}).get(
        repo_segment, []
    )
    if not candidates and canonical_identities:
        return unavailable(
            "canonical_publication_unavailable",
            repository=repo_segment,
            publication_root=str(canonical_root),
            freshness_status="publication_unavailable",
            reason=canonical_resolution.get("reason"),
            rejected_candidates=canonical_resolution.get("rejected", []),
            ambiguous_candidates=canonical_resolution.get("ambiguous_candidates", []),
        )
    if not candidates:
        candidates.extend(
            (
                ref,
                _legacy_manifest_path(legacy_root, repo_segment, ref),
                "legacy_repobrief_fallback",
            )
            for ref in refs
        )

    searched: list[str] = []
    for ref, manifest_path, authority in candidates:
        searched.append(str(manifest_path))
        manifest, error = read_manifest(manifest_path)
        if error is not None:
            if error["status"] == "missing":
                continue
            return {
                **error,
                "repository": repo_segment,
                "ref": ref,
                "publication_authority": authority,
            }
        assert manifest is not None
        try:
            agent_reading_pack = sidecar_path(
                manifest, manifest_path, "agent_reading_pack"
            )
            canonical_md = sidecar_path(manifest, manifest_path, "canonical_md")
            bundle = manifest.get("bundleManifest")
            bundle_path = None
            if isinstance(bundle, dict) and isinstance(bundle.get("path"), str):
                bundle_path = str(
                    _resolve_bounded(
                        manifest_path.parent.resolve(),
                        bundle["path"],
                        kind="bundleManifest",
                    )
                )
            elif authority == "canonical_publication":
                bundle_path = str(manifest_path)
        except ValueError as exc:
            return unavailable(
                "invalid_manifest_path",
                repository=repo_segment,
                ref=ref,
                manifest_path=str(manifest_path),
                publication_authority=authority,
                reason=str(exc),
            )
        provenance = manifest.get("snapshot_provenance")
        if not isinstance(provenance, dict):
            provenance = manifest.get("snapshotProvenance")
        repositories = []
        if isinstance(provenance, dict) and isinstance(
            provenance.get("repositories"), list
        ):
            repositories = [
                item for item in provenance["repositories"] if isinstance(item, dict)
            ]
        snapshot_commit = repositories[0].get("git_commit") if repositories else None
        freshness = _freshness_status(snapshot_commit, orientation.get("head"))
        does_not_establish = manifest.get("does_not_establish")
        if does_not_establish is None:
            does_not_establish = manifest.get("doesNotEstablish")
        return {
            "available": True,
            "status": "available",
            "repository": repo_segment,
            "ref": ref,
            "publication_root": str(publication_root),
            "publication_authority": authority,
            "manifest_path": str(manifest_path),
            "bundle_manifest_path": bundle_path,
            "generated_at": manifest.get("created_at") or manifest.get("generatedAt"),
            "snapshot_commit": snapshot_commit,
            "current_head_matches_snapshot": freshness == "fresh",
            "freshness_status": freshness,
            "agent_reading_pack_path": agent_reading_pack,
            "canonical_md_path": canonical_md,
            "does_not_establish": does_not_establish,
        }
    return unavailable(
        "missing",
        repository=repo_segment,
        publication_root=str(publication_root),
        searched_manifest_paths=searched,
        freshness_status="publication_unavailable",
        reason="no published RepoGround manifest found for known default refs",
    )

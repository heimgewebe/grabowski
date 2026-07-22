from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Mapping
import hashlib
import json
import os
import re
import stat


MANIFEST_SUFFIX = "_merge.bundle.manifest.json"
BUNDLE_HEALTH_SUFFIX = "_merge.bundle_health.post.json"
OUTPUT_HEALTH_SUFFIX = "_merge.output_health.json"
MAX_MANIFEST_BYTES = 2_000_000
MAX_HEALTH_BYTES = 1_000_000
MAX_REJECTIONS = 100
SEGMENT_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,198}[A-Za-z0-9])?\Z")
COMMIT_RE = re.compile(r"[0-9a-fA-F]{40}\Z")


class CatalogError(ValueError):
    pass


JsonReadError = Literal[
    "non_regular",
    "hardlinked",
    "too_large",
    "missing",
    "symlink",
    "read_error",
    "changed_during_read",
    "invalid_json",
    "root_not_object",
]


@dataclass(frozen=True)
class JsonObjectRead:
    value: dict[str, Any] | None
    error: JsonReadError | None
    digest: str | None
    observed_bytes: int | None


def _bounded(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _safe_segment(value: object) -> str | None:
    if not isinstance(value, str) or value in {".", ".."}:
        return None
    if "/" in value or "\\" in value:
        return None
    return value if SEGMENT_RE.fullmatch(value) else None


def _stem(path: Path) -> str:
    if not path.name.endswith(MANIFEST_SUFFIX):
        raise CatalogError("invalid_manifest_suffix")
    return path.name[: -len(MANIFEST_SUFFIX)]


def _parse_created_at(value: object) -> tuple[str, float] | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    utc = parsed.astimezone(timezone.utc)
    return value, utc.timestamp()


def read_json_object(path: Path, max_bytes: int) -> JsonObjectRead:
    descriptor: int | None = None
    try:
        path_before = os.lstat(path)
        if stat.S_ISLNK(path_before.st_mode):
            return JsonObjectRead(None, "symlink", None, None)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        observed_bytes = before.st_size
        if (path_before.st_dev, path_before.st_ino) != (before.st_dev, before.st_ino):
            return JsonObjectRead(None, "changed_during_read", None, observed_bytes)
        if not stat.S_ISREG(before.st_mode):
            return JsonObjectRead(None, "non_regular", None, observed_bytes)
        if before.st_nlink != 1:
            return JsonObjectRead(None, "hardlinked", None, observed_bytes)
        if before.st_size > max_bytes:
            return JsonObjectRead(None, "too_large", None, observed_bytes)
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        path_after = os.lstat(path)
    except FileNotFoundError:
        return JsonObjectRead(None, "missing", None, None)
    except OSError as exc:
        if exc.errno in {getattr(os, "ELOOP", 40), 40}:
            return JsonObjectRead(None, "symlink", None, None)
        return JsonObjectRead(None, "read_error", None, None)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    observed_bytes = len(data)
    if observed_bytes > max_bytes:
        return JsonObjectRead(None, "too_large", None, observed_bytes)
    if stat.S_ISLNK(path_after.st_mode):
        return JsonObjectRead(None, "symlink", None, observed_bytes)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    path_identity_after = (
        path_after.st_dev,
        path_after.st_ino,
        path_after.st_size,
        path_after.st_mtime_ns,
    )
    if identity_before != identity_after or identity_after != path_identity_after:
        return JsonObjectRead(None, "changed_during_read", None, observed_bytes)
    digest = hashlib.sha256(data).hexdigest()
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return JsonObjectRead(None, "invalid_json", digest, observed_bytes)
    if not isinstance(value, dict):
        return JsonObjectRead(None, "root_not_object", digest, observed_bytes)
    return JsonObjectRead(value, None, digest, observed_bytes)


def catalog_info(path: Path, canonical_root: Path, legacy_root: Path) -> dict[str, Any]:
    """Classify one manifest without silently downgrading malformed canonical paths."""
    if path.is_symlink():
        raise CatalogError("manifest_symlink")
    resolved = path.resolve(strict=False)
    canonical = canonical_root.resolve(strict=False)
    legacy = legacy_root.resolve(strict=False)
    stem = _stem(path)
    canonical_error: str | None = None
    if _bounded(resolved, canonical):
        parts = resolved.relative_to(canonical).parts
        if len(parts) != 4:
            canonical_error = "canonical_path_shape_invalid"
        else:
            repo_id, ref, publication_run_id, filename = parts
            if filename != path.name:
                canonical_error = "canonical_filename_mismatch"
            elif "__" not in repo_id:
                canonical_error = "canonical_repo_id_invalid"
            else:
                owner, repo = repo_id.split("__", 1)
                if not _safe_segment(owner) or not _safe_segment(repo):
                    canonical_error = "canonical_repo_id_invalid"
                elif not _safe_segment(ref) or not _safe_segment(publication_run_id):
                    canonical_error = "canonical_ref_or_run_invalid"
                elif not stem.startswith(f"{repo_id}__{ref}-"):
                    canonical_error = "canonical_stem_identity_mismatch"
                else:
                    return {
                        "authority": "canonical_publication",
                        "authority_rank": 2,
                        "publication_root": str(canonical_root),
                        "owner": owner,
                        "repo": repo,
                        "repo_id": repo_id,
                        "ref": ref,
                        "publication_run_id": publication_run_id,
                        "stem": stem,
                    }

    # Legacy manifests are flat by contract.  This narrow direct-child rule
    # permits overlapping roots without relabelling malformed canonical trees.
    if _bounded(resolved, legacy) and resolved.parent == legacy:
        repo = _repo_from_stem(stem)
        if not _safe_segment(repo):
            raise CatalogError("legacy_repo_invalid")
        return {
            "authority": "legacy_merges_fallback",
            "authority_rank": 1,
            "publication_root": str(legacy_root),
            "owner": None,
            "repo": repo,
            "repo_id": None,
            "ref": None,
            "publication_run_id": None,
            "stem": stem,
        }
    if canonical_error is not None:
        raise CatalogError(canonical_error)
    raise CatalogError("manifest_outside_catalog_roots")


def _repo_from_stem(stem: str) -> str:
    if "-full-max-" in stem:
        return stem.split("-full-max-", 1)[0]
    if "-max-" in stem:
        return stem.split("-max-", 1)[0]
    return stem.split("-", 1)[0]


def _artifact_roles(document: dict[str, Any]) -> set[str]:
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list):
        return set()
    return {
        item["role"]
        for item in artifacts
        if isinstance(item, dict) and isinstance(item.get("role"), str)
    }


def _source_provenance(
    document: dict[str, Any], info: dict[str, Any]
) -> dict[str, Any]:
    strict = info.get("authority") == "canonical_publication"

    def unavailable(reason: str) -> dict[str, Any]:
        if strict:
            raise CatalogError(reason)
        return {"available": False, "reason": reason}

    provenance = document.get("snapshot_provenance")
    if not isinstance(provenance, dict):
        provenance = document.get("snapshotProvenance")
    if not isinstance(provenance, dict):
        return unavailable("snapshot_provenance_absent")
    repositories = provenance.get("repositories")
    if not isinstance(repositories, list):
        return unavailable("snapshot_repositories_absent")

    if strict:
        expected = {
            str(info["repo_id"]),
            f"{info['repo_id']}__{info['ref']}",
        }
    else:
        expected = {str(info["repo"])}
    selected: dict[str, Any] | None = None
    for item in repositories:
        if not isinstance(item, dict):
            continue
        names = {
            value
            for value in (
                item.get("repo"),
                item.get("repository"),
                item.get("repo_id"),
                item.get("name"),
            )
            if isinstance(value, str)
        }
        if names.intersection(expected):
            selected = item
            break
    if selected is None:
        return unavailable("snapshot_repository_entry_absent")
    commit = (
        selected.get("git_commit") or selected.get("commit") or selected.get("head")
    )
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        return unavailable("snapshot_repository_commit_absent")
    dirty = selected.get("git_dirty")
    if dirty is not None and not isinstance(dirty, bool):
        return unavailable("snapshot_repository_dirty_invalid")
    return {
        "available": True,
        "git_commit": commit.lower(),
        "git_dirty": dirty,
        "repository": {
            key: selected[key]
            for key in ("repo", "repository", "repo_id", "name", "ref", "remote_ref")
            if key in selected
        },
    }


def _base_rejection(
    path: Path, info: dict[str, Any] | None, reason: str
) -> dict[str, Any]:
    values: dict[str, Any] = {
        "selected": False,
        "healthy": False,
        "manifest_path": str(path),
        "reason": reason,
    }
    if info:
        values.update(
            {
                key: info.get(key)
                for key in (
                    "authority",
                    "publication_root",
                    "owner",
                    "repo",
                    "repo_id",
                    "ref",
                    "publication_run_id",
                    "stem",
                )
            }
        )
    else:
        try:
            values["stem"] = _stem(path)
        except CatalogError:
            values["stem"] = None
    return values


def inspect_candidate(
    path: Path, canonical_root: Path, legacy_root: Path
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    try:
        info = catalog_info(path, canonical_root, legacy_root)
    except (CatalogError, OSError, RuntimeError) as exc:
        return None, _base_rejection(path, None, str(exc))

    manifest_read = read_json_object(path, MAX_MANIFEST_BYTES)
    document = manifest_read.value
    error = manifest_read.error
    manifest_sha = manifest_read.digest
    if error or document is None:
        rejection = _base_rejection(path, info, f"manifest_{error or 'invalid'}")
        rejection["manifest_sha256"] = manifest_sha
        rejection["manifest_bytes"] = manifest_read.observed_bytes
        return None, rejection

    expected_kind = (
        {"repoground.bundle.manifest"}
        if info["authority"] == "canonical_publication"
        else {"repoground.bundle.manifest", "repolens.bundle.manifest"}
    )
    if document.get("kind") not in expected_kind:
        rejection = _base_rejection(path, info, "manifest_kind_invalid")
        rejection["manifest_sha256"] = manifest_sha
        return None, rejection
    created = _parse_created_at(
        document.get("created_at") or document.get("generatedAt")
    )
    if created is None:
        rejection = _base_rejection(path, info, "manifest_created_at_invalid")
        rejection["manifest_sha256"] = manifest_sha
        return None, rejection
    run_id = document.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        rejection = _base_rejection(path, info, "manifest_run_id_invalid")
        rejection["manifest_sha256"] = manifest_sha
        return None, rejection
    roles = _artifact_roles(document)
    required_roles = (
        {"canonical_md", "output_health"}
        if info["authority"] == "canonical_publication"
        else {"canonical_md"}
    )
    missing_roles = sorted(required_roles.difference(roles))
    if missing_roles:
        rejection = _base_rejection(path, info, "required_artifact_role_missing")
        rejection["missing_artifact_roles"] = missing_roles
        rejection["manifest_sha256"] = manifest_sha
        return None, rejection
    try:
        provenance = _source_provenance(document, info)
    except CatalogError as exc:
        rejection = _base_rejection(path, info, str(exc))
        rejection["manifest_sha256"] = manifest_sha
        return None, rejection

    stem = str(info["stem"])
    bundle_health_path = path.parent / f"{stem}{BUNDLE_HEALTH_SUFFIX}"
    output_health_path = path.parent / f"{stem}{OUTPUT_HEALTH_SUFFIX}"
    bundle_read = read_json_object(bundle_health_path, MAX_HEALTH_BYTES)
    bundle_health = bundle_read.value
    bundle_error = bundle_read.error
    if bundle_error or bundle_health is None:
        rejection = _base_rejection(
            path, info, f"bundle_health_{bundle_error or 'invalid'}"
        )
        rejection["manifest_sha256"] = manifest_sha
        return None, rejection
    if bundle_health.get("status") != "pass":
        rejection = _base_rejection(path, info, "bundle_health_not_pass")
        rejection["manifest_sha256"] = manifest_sha
        rejection["bundle_health_status"] = bundle_health.get("status")
        return None, rejection
    output_read = read_json_object(output_health_path, MAX_HEALTH_BYTES)
    output_health = output_read.value
    output_error = output_read.error
    if output_error or output_health is None:
        rejection = _base_rejection(
            path, info, f"output_health_{output_error or 'invalid'}"
        )
        rejection["manifest_sha256"] = manifest_sha
        return None, rejection
    if output_health.get("verdict") != "pass":
        rejection = _base_rejection(path, info, "output_health_not_pass")
        rejection["manifest_sha256"] = manifest_sha
        rejection["output_health_verdict"] = output_health.get("verdict")
        return None, rejection
    output_run_id = output_health.get("run_id")
    canonical = info["authority"] == "canonical_publication"
    if output_run_id != run_id and (canonical or output_run_id is not None):
        rejection = _base_rejection(path, info, "output_health_run_id_mismatch")
        rejection["manifest_sha256"] = manifest_sha
        return None, rejection

    created_at, created_at_unix = created
    record = {
        **info,
        "selected": False,
        "healthy": True,
        "manifest_path": str(path),
        "path": path,
        "manifest_sha256": manifest_sha,
        "created_at": created_at,
        "created_at_unix": created_at_unix,
        "run_id": run_id,
        "document": document,
        "artifact_roles": sorted(roles),
        "source_provenance": provenance,
        "post_emit_health": bundle_health,
        "output_health": output_health,
    }
    return record, None


def _normalize_repo_query(repo: str | None) -> str | None:
    if repo is None:
        return None
    separator: str | None = None
    if "/" in repo:
        if repo.count("/") != 1:
            raise ValueError(
                "repo must be a safe repository name, owner__repository, or owner/repository identity"
            )
        separator = "/"
    elif "__" in repo:
        separator = "__"
    if separator is not None:
        owner, repository = repo.split(separator, 1)
        if (separator == "/" and "__" in owner) or not _safe_segment(
            owner
        ) or not _safe_segment(repository):
            raise ValueError(
                "repo must be a safe repository name, owner__repository, or owner/repository identity"
            )
        return f"{owner}__{repository}"
    safe = _safe_segment(repo)
    if safe is None:
        raise ValueError(
            "repo must be a safe repository name, owner__repository, or owner/repository identity"
        )
    return safe


def _normalize_refs(
    refs: list[str] | tuple[str, ...] | None,
) -> frozenset[str] | None:
    if refs is None:
        return None
    if not isinstance(refs, (list, tuple)):
        raise ValueError("refs must be a list or tuple of safe ref names")
    values: set[str] = set()
    for ref in refs:
        safe = _safe_segment(ref)
        if safe is None:
            raise ValueError("refs must contain only safe ref names")
        values.add(safe)
    return frozenset(values)


def _canonical_repo_directories(
    canonical_root: Path, repo: str | None
) -> list[Path]:
    if not canonical_root.is_dir() or canonical_root.is_symlink():
        return []
    if repo is None:
        return sorted(
            (
                path
                for path in canonical_root.iterdir()
                if path.is_dir() and not path.is_symlink()
            ),
            key=str,
        )
    if "__" in repo:
        candidate = canonical_root / repo
        return (
            [candidate]
            if candidate.is_dir() and not candidate.is_symlink()
            else []
        )
    return sorted(
        (
            path
            for path in canonical_root.iterdir()
            if path.is_dir()
            and not path.is_symlink()
            and (repo_id := _valid_repo_id(path)) is not None
            and repo_id.split("__", 1)[1] == repo
        ),
        key=str,
    )


def _valid_repo_id(directory: Path) -> str | None:
    if "__" not in directory.name:
        return None
    owner, repository = directory.name.split("__", 1)
    if not _safe_segment(owner) or not _safe_segment(repository):
        return None
    return directory.name


def _repository_directory_has_manifest(directory: Path) -> bool:
    return next(directory.glob(f"*/*/*{MANIFEST_SUFFIX}"), None) is not None


def _catalog_paths(
    canonical_root: Path,
    legacy_root: Path,
    *,
    repo: str | None,
    stem: str | None,
    refs: frozenset[str] | None,
) -> tuple[list[Path], set[str]]:
    paths: list[Path] = []
    repo_directories = _canonical_repo_directories(canonical_root, repo)
    identified_repo_ids = {
        repo_id
        for directory in repo_directories
        if (repo_id := _valid_repo_id(directory)) is not None
        and _repository_directory_has_manifest(directory)
    }
    for directory in repo_directories:
        if refs is None:
            candidates = directory.glob(f"*/*/*{MANIFEST_SUFFIX}")
            paths.extend(candidates)
        else:
            for ref in sorted(refs):
                ref_root = directory / ref
                if ref_root.is_dir() and not ref_root.is_symlink():
                    paths.extend(ref_root.glob(f"*/*{MANIFEST_SUFFIX}"))

    if legacy_root.is_dir() and not legacy_root.is_symlink():
        paths.extend(legacy_root.glob(f"*{MANIFEST_SUFFIX}"))

    scoped: list[Path] = []
    canonical = Path(os.path.abspath(canonical_root))
    legacy = Path(os.path.abspath(legacy_root))
    for path in sorted(set(paths), key=str):
        try:
            path_stem = _stem(path)
        except CatalogError:
            continue
        if stem is not None and path_stem != stem:
            continue
        lexical = Path(os.path.abspath(path))
        if lexical.parent == legacy:
            if repo is not None:
                if "__" in repo or _repo_from_stem(path_stem) != repo:
                    continue
        elif _bounded(lexical, canonical):
            parts = lexical.relative_to(canonical).parts
            if repo is not None and parts:
                repo_id = parts[0]
                if "__" in repo:
                    if repo_id != repo:
                        continue
                elif "__" not in repo_id or repo_id.split("__", 1)[1] != repo:
                    continue
            if refs is not None and len(parts) >= 2 and parts[1] not in refs:
                continue
        else:
            continue
        scoped.append(path)
    return scoped, identified_repo_ids


def scan_catalog(
    canonical_root: Path,
    legacy_root: Path,
    *,
    repo: str | None = None,
    stem: str | None = None,
    refs: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    normalized_repo = _normalize_repo_query(repo)
    normalized_refs = _normalize_refs(refs)
    paths, identified_repo_ids = _catalog_paths(
        canonical_root,
        legacy_root,
        repo=normalized_repo,
        stem=stem,
        refs=normalized_refs,
    )
    healthy: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    rejected_total_count = 0
    for path in paths:
        record, rejection = inspect_candidate(path, canonical_root, legacy_root)
        if record is not None:
            healthy.append(record)
        elif rejection is not None:
            rejected_total_count += 1
            if len(rejected) < MAX_REJECTIONS:
                rejected.append(rejection)
    healthy.sort(
        key=lambda item: (
            int(item["authority_rank"]),
            float(item["created_at_unix"]),
            str(item["manifest_sha256"]),
            str(item["manifest_path"]),
        ),
        reverse=True,
    )
    aliases: dict[str, list[str]] = {}
    for repo_id in sorted(identified_repo_ids):
        repository = repo_id.split("__", 1)[1]
        aliases.setdefault(repository, []).append(repo_id)
    return {
        "healthy": healthy,
        "rejected": rejected,
        "rejected_total_count": rejected_total_count,
        "rejected_truncated": rejected_total_count > len(rejected),
        "identified_repo_ids": sorted(identified_repo_ids),
        "aliases": aliases,
    }


def _choose_latest(
    records: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, str | None, list[dict[str, Any]]]:
    if not records:
        return None, "publication_unavailable", []
    highest_authority = max(int(item["authority_rank"]) for item in records)
    authority_records = [
        item for item in records if int(item["authority_rank"]) == highest_authority
    ]
    newest_time = max(float(item["created_at_unix"]) for item in authority_records)
    newest = [
        item
        for item in authority_records
        if float(item["created_at_unix"]) == newest_time
    ]
    if len(newest) != 1:
        return None, "ambiguous_publication", newest
    return newest[0], None, []


def _rejection_projection(
    scanned: Mapping[str, Any],
    additional: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    extras = additional or []
    stored = [*list(scanned["rejected"]), *extras]
    total = int(scanned["rejected_total_count"]) + len(extras)
    shown = stored[:MAX_REJECTIONS]
    return {
        "rejected": shown,
        "rejected_total_count": total,
        "rejected_truncated": total > len(shown),
    }


def _resolution_result(
    scanned: Mapping[str, Any],
    *,
    available: bool,
    reason: str | None,
    repo: str | None,
    selected: list[dict[str, Any]],
    stem: str | None = None,
    additional_rejections: list[dict[str, Any]] | None = None,
    **values: Any,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "available": available,
        "reason": reason,
        "repo": repo,
        "selected": selected,
        "aliases": scanned["aliases"],
        **_rejection_projection(scanned, additional_rejections),
        **values,
    }
    if stem is not None:
        result["stem"] = stem
    return result


def selected_manifest_paths(
    resolution: Mapping[str, Any],
) -> list[tuple[str, Path]]:
    selected = resolution.get("selected")
    if not isinstance(selected, list):
        raise CatalogError("resolution_selected_invalid")
    candidates: list[tuple[str, Path]] = []
    for item in selected:
        if not isinstance(item, dict):
            raise CatalogError("resolution_candidate_invalid")
        ref = item.get("ref")
        manifest_path = item.get("manifest_path")
        if not isinstance(ref, str) or not isinstance(manifest_path, str):
            raise CatalogError("resolution_candidate_identity_invalid")
        candidates.append((ref, Path(manifest_path)))
    return candidates


def resolve_catalog(
    canonical_root: Path,
    legacy_root: Path,
    *,
    repo: str | None = None,
    stem: str | None = None,
    refs: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    normalized_repo = _normalize_repo_query(repo)
    normalized_refs = _normalize_refs(refs)
    scanned = scan_catalog(
        canonical_root,
        legacy_root,
        repo=normalized_repo,
        stem=stem,
        refs=sorted(normalized_refs) if normalized_refs is not None else None,
    )
    healthy = list(scanned["healthy"])
    aliases = scanned["aliases"]

    if (
        normalized_repo is not None
        and "__" not in normalized_repo
        and len(aliases.get(normalized_repo, [])) > 1
    ):
        return _resolution_result(
            scanned,
            available=False,
            reason="ambiguous_repository_alias",
            repo=normalized_repo,
            stem=stem,
            selected=[],
            repo_ids=aliases[normalized_repo],
        )

    if stem is not None:
        exact = [item for item in healthy if item["stem"] == stem]
        if exact:
            highest_authority = max(int(item["authority_rank"]) for item in exact)
            exact = [
                item
                for item in exact
                if int(item["authority_rank"]) == highest_authority
            ]
            if len(exact) != 1:
                return _resolution_result(
                    scanned,
                    available=False,
                    reason="ambiguous_stem",
                    repo=normalized_repo,
                    stem=stem,
                    selected=[],
                    ambiguous_candidates=[public_candidate(item) for item in exact],
                )
            selected = dict(exact[0])
            selected["selected"] = True
            return _resolution_result(
                scanned,
                available=True,
                reason=None,
                repo=normalized_repo,
                stem=stem,
                selected=[selected],
            )
        return _resolution_result(
            scanned,
            available=False,
            reason="publication_unavailable",
            repo=normalized_repo,
            stem=stem,
            selected=[],
        )

    if normalized_repo is not None:
        if "__" in normalized_repo:
            canonical_identity_exists = normalized_repo in scanned["identified_repo_ids"]
            matching = [
                item for item in healthy if item.get("repo_id") == normalized_repo
            ]
        else:
            canonical_identity_exists = bool(aliases.get(normalized_repo))
            matching = [
                item for item in healthy if item.get("repo") == normalized_repo
            ]
        if canonical_identity_exists:
            matching = [
                item
                for item in matching
                if item["authority"] == "canonical_publication"
            ]
        selected, reason, ambiguous = _choose_latest(matching)
        if selected is None:
            return _resolution_result(
                scanned,
                available=False,
                reason=reason,
                repo=normalized_repo,
                selected=[],
                ambiguous_candidates=[public_candidate(item) for item in ambiguous],
            )
        selected = dict(selected)
        selected["selected"] = True
        return _resolution_result(
            scanned,
            available=True,
            reason=None,
            repo=normalized_repo,
            selected=[selected],
        )

    selected_records: list[dict[str, Any]] = []
    selection_rejections: list[dict[str, Any]] = []
    canonical_groups: dict[str, list[dict[str, Any]]] = {}
    legacy_groups: dict[str, list[dict[str, Any]]] = {}
    for item in healthy:
        if item["authority"] == "canonical_publication":
            canonical_groups.setdefault(str(item["repo_id"]), []).append(item)
        else:
            legacy_groups.setdefault(str(item["repo"]), []).append(item)
    for repo_id, records in sorted(canonical_groups.items()):
        selected, reason, ambiguous = _choose_latest(records)
        if selected is not None:
            value = dict(selected)
            value["selected"] = True
            selected_records.append(value)
        else:
            selection_rejections.append(
                {
                    "selected": False,
                    "healthy": False,
                    "authority": "canonical_publication",
                    "repo_id": repo_id,
                    "repo": repo_id.split("__", 1)[1],
                    "reason": reason,
                    "ambiguous_candidates": [
                        public_candidate(item) for item in ambiguous
                    ],
                }
            )
    canonical_simple_repos = {
        repo_id.split("__", 1)[1] for repo_id in scanned["identified_repo_ids"]
    }
    for simple_repo, records in sorted(legacy_groups.items()):
        if simple_repo in canonical_simple_repos:
            continue
        selected, reason, ambiguous = _choose_latest(records)
        if selected is not None:
            value = dict(selected)
            value["selected"] = True
            selected_records.append(value)
        else:
            selection_rejections.append(
                {
                    "selected": False,
                    "healthy": False,
                    "authority": "legacy_merges_fallback",
                    "repo": simple_repo,
                    "reason": reason,
                    "ambiguous_candidates": [
                        public_candidate(item) for item in ambiguous
                    ],
                }
            )
    selected_records.sort(
        key=lambda item: (
            int(item["authority_rank"]),
            float(item["created_at_unix"]),
            str(item.get("repo_id") or item["repo"]),
        ),
        reverse=True,
    )
    return _resolution_result(
        scanned,
        available=bool(selected_records),
        reason=None if selected_records else "publication_unavailable",
        repo=None,
        selected=selected_records,
        additional_rejections=selection_rejections,
    )


def inspect_stem(canonical_root: Path, legacy_root: Path, stem: str) -> dict[str, Any]:
    scanned = scan_catalog(canonical_root, legacy_root, stem=stem)
    healthy = list(scanned["healthy"])
    rejected = list(scanned["rejected"])
    canonical = [
        item
        for item in [*healthy, *rejected]
        if item.get("authority") == "canonical_publication"
    ]
    pool = canonical if canonical else [*healthy, *rejected]
    if len(pool) != 1:
        return {
            "available": False,
            "reason": "ambiguous_stem" if pool else "publication_unavailable",
            "matches": [
                public_candidate(item) if item.get("healthy") else dict(item)
                for item in pool[:20]
            ],
        }
    item = pool[0]
    if item.get("healthy"):
        return {"available": True, "healthy": True, "record": item, "reason": None}
    return {
        "available": True,
        "healthy": False,
        "record": None,
        "rejection": item,
        "reason": item.get("reason"),
        "manifest_path": item.get("manifest_path"),
    }


def _public_health(value: object, *, output: bool) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    keys = (
        ("verdict", "run_id", "created_at")
        if output
        else ("status", "run_id", "evidence_level", "range_ref_resolution_status")
    )
    public = {key: value.get(key) for key in keys if key in value}
    checks = value.get("checks")
    if output and isinstance(checks, dict):
        public["range_ref_resolution_status"] = checks.get(
            "range_ref_resolution_status"
        )
    return public


def public_candidate(record: dict[str, Any]) -> dict[str, Any]:
    public = {
        key: record.get(key)
        for key in (
            "selected",
            "healthy",
            "authority",
            "publication_root",
            "owner",
            "repo",
            "repo_id",
            "ref",
            "publication_run_id",
            "stem",
            "manifest_path",
            "manifest_sha256",
            "created_at",
            "run_id",
            "artifact_roles",
            "source_provenance",
        )
    }
    public["post_emit_health"] = _public_health(
        record.get("post_emit_health"), output=False
    )
    public["output_health"] = _public_health(record.get("output_health"), output=True)
    return public

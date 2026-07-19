from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
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


def read_json_object(
    path: Path, max_bytes: int
) -> tuple[dict[str, Any] | None, str | None, str | None]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            return None, "non_regular", None
        if before.st_nlink != 1:
            return None, "hardlinked", None
        if before.st_size > max_bytes:
            return None, "too_large", None
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
    except FileNotFoundError:
        return None, "missing", None
    except OSError as exc:
        if exc.errno in {getattr(os, "ELOOP", 40), 40}:
            return None, "symlink", None
        return None, "read_error", None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(data) > max_bytes:
        return None, "too_large", None
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        return None, "changed_during_read", None
    digest = hashlib.sha256(data).hexdigest()
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "invalid_json", digest
    if not isinstance(value, dict):
        return None, "root_not_object", digest
    return value, None, digest


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

    document, error, manifest_sha = read_json_object(path, MAX_MANIFEST_BYTES)
    if error or document is None:
        rejection = _base_rejection(path, info, f"manifest_{error or 'invalid'}")
        rejection["manifest_sha256"] = manifest_sha
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
    bundle_health, bundle_error, _bundle_sha = read_json_object(
        bundle_health_path, MAX_HEALTH_BYTES
    )
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
    output_health, output_error, _output_sha = read_json_object(
        output_health_path, MAX_HEALTH_BYTES
    )
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


def scan_catalog(canonical_root: Path, legacy_root: Path) -> dict[str, Any]:
    paths: list[Path] = []
    if canonical_root.is_dir() and not canonical_root.is_symlink():
        paths.extend(canonical_root.glob(f"*/*/*/*{MANIFEST_SUFFIX}"))
    if legacy_root.is_dir() and not legacy_root.is_symlink():
        paths.extend(legacy_root.glob(f"*{MANIFEST_SUFFIX}"))
    healthy: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    rejected_total_count = 0
    identified_repo_ids: set[str] = set()
    for path in sorted(set(paths), key=str):
        record, rejection = inspect_candidate(path, canonical_root, legacy_root)
        value = record or rejection
        if (
            value
            and value.get("authority") == "canonical_publication"
            and value.get("repo_id")
        ):
            identified_repo_ids.add(str(value["repo_id"]))
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
        repo = repo_id.split("__", 1)[1]
        aliases.setdefault(repo, []).append(repo_id)
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


def _matching_rejections(
    rejected: list[dict[str, Any]], *, repo: str | None, stem: str | None
) -> list[dict[str, Any]]:
    values = rejected
    if stem is not None:
        values = [item for item in values if item.get("stem") == stem]
    if repo is not None:
        if "__" in repo:
            values = [item for item in values if item.get("repo_id") == repo]
        else:
            values = [item for item in values if item.get("repo") == repo]
    return values[:MAX_REJECTIONS]


def resolve_catalog(
    canonical_root: Path,
    legacy_root: Path,
    *,
    repo: str | None = None,
    stem: str | None = None,
    refs: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    scanned = scan_catalog(canonical_root, legacy_root)
    healthy = list(scanned["healthy"])
    normalized_refs: tuple[str, ...] | None = None
    if refs is not None:
        if not isinstance(refs, (list, tuple)):
            raise ValueError("refs must be a list or tuple of safe ref names")
        values: list[str] = []
        for ref in refs:
            safe = _safe_segment(ref)
            if safe is None:
                raise ValueError("refs must contain only safe ref names")
            if safe not in values:
                values.append(safe)
        normalized_refs = tuple(values)
        healthy = [item for item in healthy if item.get("ref") in normalized_refs]
    rejected = list(scanned["rejected"])
    aliases = scanned["aliases"]

    if repo is not None and "__" not in repo and len(aliases.get(repo, [])) > 1:
        return {
            "available": False,
            "reason": "ambiguous_repository_alias",
            "repo": repo,
            "repo_ids": aliases[repo],
            "selected": [],
            "rejected": _matching_rejections(rejected, repo=repo, stem=stem),
            "aliases": aliases,
            "rejected_total_count": scanned["rejected_total_count"],
            "rejected_truncated": scanned["rejected_truncated"],
        }

    if stem is not None:
        exact = [item for item in healthy if item["stem"] == stem]
        if repo is not None:
            if "__" in repo:
                exact = [item for item in exact if item.get("repo_id") == repo]
            else:
                exact = [item for item in exact if item.get("repo") == repo]
        if exact:
            highest_authority = max(int(item["authority_rank"]) for item in exact)
            exact = [
                item
                for item in exact
                if int(item["authority_rank"]) == highest_authority
            ]
            if len(exact) != 1:
                return {
                    "available": False,
                    "reason": "ambiguous_stem",
                    "repo": repo,
                    "stem": stem,
                    "selected": [],
                    "ambiguous_candidates": [public_candidate(item) for item in exact],
                    "rejected": _matching_rejections(rejected, repo=repo, stem=stem),
                    "aliases": aliases,
                }
            selected = dict(exact[0])
            selected["selected"] = True
            return {
                "available": True,
                "reason": None,
                "repo": repo,
                "stem": stem,
                "selected": [selected],
                "rejected": _matching_rejections(rejected, repo=repo, stem=stem),
                "aliases": aliases,
                "rejected_total_count": scanned["rejected_total_count"],
                "rejected_truncated": scanned["rejected_truncated"],
            }
        return {
            "available": False,
            "reason": "publication_unavailable",
            "repo": repo,
            "stem": stem,
            "selected": [],
            "rejected": _matching_rejections(rejected, repo=repo, stem=stem),
            "aliases": aliases,
            "rejected_total_count": scanned["rejected_total_count"],
            "rejected_truncated": scanned["rejected_truncated"],
        }

    if repo is not None:
        canonical_identity_exists = False
        if "__" in repo:
            canonical_identity_exists = repo in scanned["identified_repo_ids"]
            matching = [item for item in healthy if item.get("repo_id") == repo]
        else:
            canonical_identity_exists = bool(aliases.get(repo))
            matching = [item for item in healthy if item.get("repo") == repo]
        if canonical_identity_exists:
            matching = [
                item
                for item in matching
                if item["authority"] == "canonical_publication"
            ]
        selected, reason, ambiguous = _choose_latest(matching)
        if selected is None:
            return {
                "available": False,
                "reason": reason,
                "repo": repo,
                "selected": [],
                "ambiguous_candidates": [public_candidate(item) for item in ambiguous],
                "rejected": _matching_rejections(rejected, repo=repo, stem=None),
                "aliases": aliases,
                "rejected_total_count": scanned["rejected_total_count"],
                "rejected_truncated": scanned["rejected_truncated"],
            }
        selected = dict(selected)
        selected["selected"] = True
        return {
            "available": True,
            "reason": None,
            "repo": repo,
            "selected": [selected],
            "rejected": _matching_rejections(rejected, repo=repo, stem=None),
            "aliases": aliases,
            "rejected_total_count": scanned["rejected_total_count"],
            "rejected_truncated": scanned["rejected_truncated"],
        }

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
    return {
        "available": bool(selected_records),
        "reason": None if selected_records else "publication_unavailable",
        "repo": None,
        "selected": selected_records,
        "rejected": [*rejected, *selection_rejections][:MAX_REJECTIONS],
        "aliases": aliases,
        "rejected_total_count": scanned["rejected_total_count"],
        "rejected_truncated": scanned["rejected_truncated"],
    }


def inspect_stem(canonical_root: Path, legacy_root: Path, stem: str) -> dict[str, Any]:
    scanned = scan_catalog(canonical_root, legacy_root)
    healthy = [item for item in scanned["healthy"] if item.get("stem") == stem]
    rejected = [item for item in scanned["rejected"] if item.get("stem") == stem]
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

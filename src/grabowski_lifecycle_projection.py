from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
from typing import Any, Iterable, Iterator, Mapping

import grabowski_lifecycle_archive as lifecycle
import grabowski_lifecycle_effect_plan as effect_plan


SCHEMA_VERSION = 1
MAX_SWITCH_BYTES = 8 * 1024 * 1024
SWITCH_NAME = re.compile(r"switch-([0-9a-f]{64})\.json\Z")
SWITCH_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "segment_id",
        "segment_identity_sha256",
        "archive_manifest_sha256",
        "archive_segment_sha256",
        "archive_plan_sha256",
        "source_store_sha256",
        "task_bindings",
        "effect_plan",
        "revalidation",
        "applied_at_unix",
        "mutation_performed",
        "does_not_establish",
        "switch_sha256",
    }
)
DOES_NOT_ESTABLISH = [
    "physical_deletion_authority",
    "workspace_cleanup_authority",
    "source_store_unchanged_after_switch",
    "blind_retry_authority",
]


class LifecycleProjectionError(RuntimeError):
    pass


class LifecycleProjectionIntegrityError(LifecycleProjectionError):
    pass


def _validate_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or lifecycle.SHA256.fullmatch(value) is None:
        raise LifecycleProjectionIntegrityError(f"{label} is not a lowercase SHA-256 digest")
    return value


def _validate_ready_projection_binding(
    plan: Mapping[str, Any],
    revalidation: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        validated_plan = effect_plan._validate_plan(plan)
        validated_revalidation = effect_plan._validate_revalidation(
            revalidation,
            plan=validated_plan,
        )
    except (ValueError, effect_plan.LifecycleEffectPlanError) as exc:
        raise LifecycleProjectionIntegrityError(str(exc)) from exc
    if validated_plan.get("effect_kind") != "current_projection_switch":
        raise LifecycleProjectionIntegrityError(
            "projection switch requires current_projection_switch effect plan"
        )
    if validated_revalidation.get("ready_for_effect") is not True:
        raise LifecycleProjectionError(
            "projection switch requires a ready effect revalidation"
        )
    return validated_plan, validated_revalidation


def _projection_resource_key(projection_root: Path) -> str:
    return f"path:{projection_root.expanduser().resolve()}"


def _require_projection_resource(
    plan: Mapping[str, Any],
    *,
    projection_root: Path,
) -> None:
    required = plan.get("required_resource_keys")
    expected = _projection_resource_key(projection_root)
    if not isinstance(required, list) or expected not in required:
        raise LifecycleProjectionIntegrityError(
            f"projection switch plan lacks exact projection resource: {expected}"
        )


@contextmanager
def _locked_projection_root(projection_root: Path) -> Iterator[None]:
    if projection_root.is_symlink():
        raise LifecycleProjectionIntegrityError("projection root may not be a symlink")
    try:
        projection_root.mkdir(exist_ok=True, mode=0o700)
    except OSError as exc:
        raise LifecycleProjectionIntegrityError(
            "projection root cannot be created safely"
        ) from exc
    if projection_root.is_symlink() or not projection_root.is_dir():
        raise LifecycleProjectionIntegrityError("projection root must be a regular directory")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(projection_root, flags)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LifecycleProjectionError(
                "projection root is locked by another switch"
            ) from exc
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _assert_projection_accepts_switch(
    projection: Mapping[str, Any],
    switch: Mapping[str, Any],
) -> None:
    existing = projection.get("archived_task_bindings")
    if not isinstance(existing, Mapping):
        raise LifecycleProjectionIntegrityError(
            "existing archived task projection bindings are invalid"
        )
    for binding in switch["task_bindings"]:
        current = existing.get(binding["task_id"])
        if current is None:
            continue
        if (
            not isinstance(current, Mapping)
            or current.get("record_sha256") != binding["record_sha256"]
        ):
            raise LifecycleProjectionIntegrityError(
                f"projection task binding conflicts with existing archive: {binding['task_id']}"
            )


def _task_bindings_from_archive(verified: Mapping[str, Any]) -> list[dict[str, str]]:
    manifest = verified.get("manifest")
    records = verified.get("records")
    if not isinstance(manifest, Mapping) or not isinstance(records, list):
        raise LifecycleProjectionIntegrityError("verified archive segment is incomplete")
    record_sha256s = manifest.get("record_sha256s")
    if not isinstance(record_sha256s, list) or len(record_sha256s) != len(records):
        raise LifecycleProjectionIntegrityError("archive record hash sequence is invalid")
    bindings: list[dict[str, str]] = []
    seen: set[str] = set()
    for record, digest in zip(records, record_sha256s, strict=True):
        if not isinstance(record, Mapping):
            raise LifecycleProjectionIntegrityError("archive record is invalid")
        task_id = record.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            raise LifecycleProjectionIntegrityError("archive task identity is invalid")
        if task_id in seen:
            raise LifecycleProjectionIntegrityError("archive contains duplicate task identity")
        seen.add(task_id)
        bindings.append(
            {
                "task_id": task_id,
                "record_sha256": _validate_sha256(
                    digest,
                    label=f"archive.record_sha256[{task_id}]",
                ),
            }
        )
    return sorted(bindings, key=lambda item: item["task_id"])


def _validate_task_bindings(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise LifecycleProjectionIntegrityError("projection task bindings are missing")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {"task_id", "record_sha256"}:
            raise LifecycleProjectionIntegrityError("projection task binding is invalid")
        task_id = item.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            raise LifecycleProjectionIntegrityError("projection task identity is invalid")
        if task_id in seen:
            raise LifecycleProjectionIntegrityError("projection contains duplicate task identity")
        seen.add(task_id)
        normalized.append(
            {
                "task_id": task_id,
                "record_sha256": _validate_sha256(
                    item.get("record_sha256"),
                    label=f"projection.record_sha256[{task_id}]",
                ),
            }
        )
    ordered = sorted(normalized, key=lambda item: item["task_id"])
    if normalized != ordered:
        raise LifecycleProjectionIntegrityError("projection task bindings are not canonical")
    return normalized


def _plan_task_ids(plan: Mapping[str, Any]) -> list[str]:
    entries = plan.get("entries")
    if not isinstance(entries, list):
        raise LifecycleProjectionIntegrityError("projection effect plan entries are invalid")
    identities = [entry.get("identity") for entry in entries if isinstance(entry, Mapping)]
    if len(identities) != len(entries) or any(
        not isinstance(identity, str) or not identity for identity in identities
    ):
        raise LifecycleProjectionIntegrityError("projection effect plan identities are invalid")
    if len(identities) != len(set(identities)):
        raise LifecycleProjectionIntegrityError("projection effect plan contains duplicate identities")
    return sorted(identities)


def _switch_body(
    *,
    verified_archive: Mapping[str, Any],
    plan: Mapping[str, Any],
    revalidation: Mapping[str, Any],
    applied_at_unix: int,
) -> dict[str, Any]:
    manifest = verified_archive["manifest"]
    task_bindings = _task_bindings_from_archive(verified_archive)
    if _plan_task_ids(plan) != [item["task_id"] for item in task_bindings]:
        raise LifecycleProjectionIntegrityError(
            "projection effect plan identities do not match archive segment records"
        )
    if not isinstance(applied_at_unix, int) or isinstance(applied_at_unix, bool):
        raise ValueError("applied_at_unix must be an integer")
    if applied_at_unix < revalidation["now_unix"]:
        raise ValueError("projection switch may not predate its revalidation")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_task_archive_projection_switch",
        "segment_id": manifest["segment_id"],
        "segment_identity_sha256": manifest["segment_identity_sha256"],
        "archive_manifest_sha256": manifest["manifest_sha256"],
        "archive_segment_sha256": manifest["segment_sha256"],
        "archive_plan_sha256": manifest["plan_sha256"],
        "source_store_sha256": manifest["source_store_sha256"],
        "task_bindings": task_bindings,
        "effect_plan": dict(plan),
        "revalidation": dict(revalidation),
        "applied_at_unix": applied_at_unix,
        "mutation_performed": True,
        "does_not_establish": list(DOES_NOT_ESTABLISH),
    }


def _validate_switch_payload(
    value: Mapping[str, Any],
    *,
    archive_root: Path,
) -> dict[str, Any]:
    switch = dict(value)
    if set(switch) != SWITCH_KEYS:
        raise LifecycleProjectionIntegrityError("projection switch fields are not exact")
    expected_digest = _validate_sha256(
        switch.get("switch_sha256"),
        label="projection.switch_sha256",
    )
    body = {key: item for key, item in switch.items() if key != "switch_sha256"}
    if lifecycle.sha256_json(body) != expected_digest:
        raise LifecycleProjectionIntegrityError("projection switch digest mismatch")
    if body.get("schema_version") != SCHEMA_VERSION:
        raise LifecycleProjectionIntegrityError("unsupported projection switch schema")
    if body.get("kind") != "grabowski_task_archive_projection_switch":
        raise LifecycleProjectionIntegrityError("projection switch kind mismatch")
    if body.get("mutation_performed") is not True:
        raise LifecycleProjectionIntegrityError("projection switch must record its mutation")
    if body.get("does_not_establish") != DOES_NOT_ESTABLISH:
        raise LifecycleProjectionIntegrityError("projection switch safety non-claims are invalid")
    segment_id = body.get("segment_id")
    if not isinstance(segment_id, str) or not segment_id.startswith("segment-"):
        raise LifecycleProjectionIntegrityError("projection segment identity is invalid")
    segment_identity_sha256 = _validate_sha256(
        body.get("segment_identity_sha256"),
        label="projection.segment_identity_sha256",
    )
    if segment_id != f"segment-{segment_identity_sha256[:24]}":
        raise LifecycleProjectionIntegrityError("projection segment directory identity mismatch")
    for key in (
        "archive_manifest_sha256",
        "archive_segment_sha256",
        "archive_plan_sha256",
        "source_store_sha256",
    ):
        _validate_sha256(body.get(key), label=f"projection.{key}")
    plan = body.get("effect_plan")
    revalidation = body.get("revalidation")
    if not isinstance(plan, Mapping) or not isinstance(revalidation, Mapping):
        raise LifecycleProjectionIntegrityError("projection effect binding is invalid")
    validated_plan, validated_revalidation = _validate_ready_projection_binding(
        plan,
        revalidation,
    )
    applied_at_unix = body.get("applied_at_unix")
    if not isinstance(applied_at_unix, int) or isinstance(applied_at_unix, bool):
        raise LifecycleProjectionIntegrityError("projection switch timestamp is invalid")
    if applied_at_unix < validated_revalidation["now_unix"]:
        raise LifecycleProjectionIntegrityError("projection switch predates its revalidation")
    if applied_at_unix >= effect_plan._earliest_revalidation_lease_expiry(
        validated_revalidation
    ):
        raise LifecycleProjectionIntegrityError(
            "projection switch is not covered by the bound leases"
        )
    task_bindings = _validate_task_bindings(body.get("task_bindings"))
    if _plan_task_ids(validated_plan) != [item["task_id"] for item in task_bindings]:
        raise LifecycleProjectionIntegrityError(
            "projection effect plan identities do not match switch task bindings"
        )
    try:
        verified_archive = lifecycle.verify_task_archive_segment(archive_root / segment_id)
    except lifecycle.LifecycleArchiveIntegrityError as exc:
        raise LifecycleProjectionIntegrityError(str(exc)) from exc
    manifest = verified_archive["manifest"]
    expected_archive = {
        "segment_identity_sha256": manifest["segment_identity_sha256"],
        "archive_manifest_sha256": manifest["manifest_sha256"],
        "archive_segment_sha256": manifest["segment_sha256"],
        "archive_plan_sha256": manifest["plan_sha256"],
        "source_store_sha256": manifest["source_store_sha256"],
    }
    for key, expected in expected_archive.items():
        if body.get(key) != expected:
            raise LifecycleProjectionIntegrityError(
                f"projection archive binding mismatch: {key}"
            )
    if task_bindings != _task_bindings_from_archive(verified_archive):
        raise LifecycleProjectionIntegrityError("projection task bindings drift from archive segment")
    return switch


def verify_task_archive_projection_switch(
    switch_path: Path,
    *,
    archive_root: Path,
) -> dict[str, Any]:
    if switch_path.parent.is_symlink():
        raise LifecycleProjectionIntegrityError(
            "projection switch parent may not be a symlink"
        )
    try:
        payload = lifecycle._read_regular_bytes(switch_path, max_bytes=MAX_SWITCH_BYTES)
    except lifecycle.LifecycleArchiveIntegrityError as exc:
        raise LifecycleProjectionIntegrityError(str(exc)) from exc
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleProjectionIntegrityError("projection switch JSON is invalid") from exc
    if not isinstance(value, Mapping):
        raise LifecycleProjectionIntegrityError("projection switch must be a JSON object")
    switch = _validate_switch_payload(value, archive_root=archive_root)
    _require_projection_resource(
        switch["effect_plan"],
        projection_root=switch_path.parent,
    )
    expected_name = f"switch-{switch['segment_identity_sha256']}.json"
    if switch_path.name != expected_name:
        raise LifecycleProjectionIntegrityError(
            "projection switch filename does not match segment identity"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "verified",
        "switch_path": str(switch_path),
        "switch": switch,
    }


def load_task_archive_projection(
    *,
    projection_root: Path,
    archive_root: Path,
) -> dict[str, Any]:
    if projection_root.is_symlink():
        raise LifecycleProjectionIntegrityError("projection root may not be a symlink")
    if not projection_root.exists():
        return {
            "schema_version": SCHEMA_VERSION,
            "switches": [],
            "archived_task_bindings": {},
            "projection_sha256": lifecycle.sha256_json([]),
        }
    if not projection_root.is_dir():
        raise LifecycleProjectionIntegrityError("projection root must be a directory")
    switches: list[dict[str, Any]] = []
    archived_task_bindings: dict[str, dict[str, str]] = {}
    for path in sorted(projection_root.iterdir(), key=lambda item: item.name):
        if SWITCH_NAME.fullmatch(path.name) is None:
            raise LifecycleProjectionIntegrityError(
                f"unexpected projection root entry: {path.name}"
            )
        verified = verify_task_archive_projection_switch(path, archive_root=archive_root)
        switch = verified["switch"]
        switches.append(switch)
        for binding in switch["task_bindings"]:
            task_id = binding["task_id"]
            candidate = {
                "record_sha256": binding["record_sha256"],
                "segment_id": switch["segment_id"],
                "switch_sha256": switch["switch_sha256"],
            }
            existing = archived_task_bindings.get(task_id)
            if existing is not None:
                if existing["record_sha256"] != candidate["record_sha256"]:
                    raise LifecycleProjectionIntegrityError(
                        f"task appears with conflicting archive hashes: {task_id}"
                    )
                continue
            archived_task_bindings[task_id] = candidate
    switch_digests = sorted(switch["switch_sha256"] for switch in switches)
    return {
        "schema_version": SCHEMA_VERSION,
        "switches": switches,
        "archived_task_bindings": archived_task_bindings,
        "projection_sha256": lifecycle.sha256_json(switch_digests),
    }


def apply_task_archive_projection_switch(
    segment_dir: Path,
    *,
    projection_root: Path,
    plan: Mapping[str, Any],
    revalidation: Mapping[str, Any],
    applied_at_unix: int,
) -> dict[str, Any]:
    validated_plan, validated_revalidation = _validate_ready_projection_binding(
        plan,
        revalidation,
    )
    _require_projection_resource(validated_plan, projection_root=projection_root)
    if applied_at_unix >= effect_plan._earliest_revalidation_lease_expiry(
        validated_revalidation
    ):
        raise LifecycleProjectionError(
            "projection switch is not covered by the bound leases"
        )
    try:
        verified_archive = lifecycle.verify_task_archive_segment(segment_dir)
    except lifecycle.LifecycleArchiveIntegrityError as exc:
        raise LifecycleProjectionIntegrityError(str(exc)) from exc
    body = _switch_body(
        verified_archive=verified_archive,
        plan=validated_plan,
        revalidation=validated_revalidation,
        applied_at_unix=applied_at_unix,
    )
    switch = {**body, "switch_sha256": lifecycle.sha256_json(body)}
    archive_root = segment_dir.parent
    with _locked_projection_root(projection_root):
        projection_before = load_task_archive_projection(
            projection_root=projection_root,
            archive_root=archive_root,
        )
        _assert_projection_accepts_switch(projection_before, switch)
        switch_path = projection_root / f"switch-{switch['segment_identity_sha256']}.json"
        if switch_path.exists():
            verified = verify_task_archive_projection_switch(
                switch_path,
                archive_root=archive_root,
            )
            if verified["switch"] != switch:
                raise LifecycleProjectionIntegrityError(
                    "existing projection switch conflicts with segment identity"
                )
            idempotent_replay = True
        else:
            payload = json.dumps(
                switch,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            ).encode("utf-8") + b"\n"
            try:
                lifecycle._write_create_only(switch_path, payload)
            except FileExistsError:
                verified = verify_task_archive_projection_switch(
                    switch_path,
                    archive_root=archive_root,
                )
                if verified["switch"] != switch:
                    raise LifecycleProjectionIntegrityError(
                        "existing projection switch conflicts with segment identity"
                    )
                idempotent_replay = True
            else:
                lifecycle._fsync_directory(projection_root)
                verified = verify_task_archive_projection_switch(
                    switch_path,
                    archive_root=archive_root,
                )
                idempotent_replay = False
        projection = load_task_archive_projection(
            projection_root=projection_root,
            archive_root=archive_root,
        )
    return {
        **verified,
        "idempotent_replay": idempotent_replay,
        "projection_sha256": projection["projection_sha256"],
        "post_state_sha256s": {
            "archive_manifest": switch["archive_manifest_sha256"],
            "projection_switch": switch["switch_sha256"],
            "task_projection": projection["projection_sha256"],
        },
    }


def bounded_current_task_projection(
    records: Iterable[Mapping[str, Any]],
    *,
    projection: Mapping[str, Any],
) -> list[dict[str, Any]]:
    bindings = projection.get("archived_task_bindings")
    if not isinstance(bindings, Mapping):
        raise LifecycleProjectionIntegrityError("archived task projection bindings are invalid")
    current: list[dict[str, Any]] = []
    for raw in records:
        record = dict(raw)
        task_id = record.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            raise LifecycleProjectionIntegrityError("current task record identity is invalid")
        binding = bindings.get(task_id)
        if binding is None:
            current.append(record)
            continue
        if not isinstance(binding, Mapping):
            raise LifecycleProjectionIntegrityError(
                f"archived task projection binding is invalid: {task_id}"
            )
        expected_digest = _validate_sha256(
            binding.get("record_sha256"),
            label=f"projection.current_record_sha256[{task_id}]",
        )
        if lifecycle.sha256_json(record) != expected_digest:
            raise LifecycleProjectionIntegrityError(
                f"current task record drifted from archived projection: {task_id}"
            )
    return current

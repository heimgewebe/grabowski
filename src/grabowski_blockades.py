"""Pure decision core for evidence-bound scoped operator blockades.

The module intentionally performs no filesystem mutation. Runtime adapters may
persist validated records and execute a validated recovery transaction, but the
policy decision remains deterministic and testable in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = 1
SCOPE_KINDS = (
    "path",
    "capability",
    "task",
    "owner",
    "repo",
    "service",
    "host",
    "global",
)
POSTURES = ("observe", "preflight_required", "mutation_freeze", "hard_stop")
POSTURE_ORDER = {name: index for index, name in enumerate(POSTURES)}
ACTION_CLASSES = ("read", "status", "audit_read", "mutate", "recovery_disarm")
SOURCES = ("typed", "legacy_file", "environment")
DISARM_POLICIES = ("in_band", "external_only")
GLOBAL_HARD_STOP_TRIGGER_CLASSES = (
    "audit_integrity_invalid",
    "audit_provenance_unknown",
    "deployment_provenance_invalid",
    "broker_identity_invalid",
    "recovery_identity_invalid",
    "external_environment_stop",
    "host_wide_damage_unknown",
    "legacy_operator_marker",
    "global_trust_unknown",
)

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,255}\Z")
_BLOCKADE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,127}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_REASON_CHARS = 1000
_MAX_EVIDENCE_REFS = 64
_MAX_EVIDENCE_REF_CHARS = 1000


class BlockadeValidationError(ValueError):
    """Raised when persisted or caller-supplied blockade data is invalid."""


def _exact_keys(
    value: Mapping[str, Any],
    *,
    required: set[str],
    optional: set[str] | None = None,
    label: str,
) -> None:
    optional = optional or set()
    actual = set(value)
    missing = required - actual
    unknown = actual - required - optional
    if missing:
        raise BlockadeValidationError(f"{label} is missing keys: {sorted(missing)}")
    if unknown:
        raise BlockadeValidationError(f"{label} has unknown keys: {sorted(unknown)}")


def _bounded_string(
    value: Any,
    *,
    label: str,
    max_chars: int,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if not isinstance(value, str) or not value:
        raise BlockadeValidationError(f"{label} must be a non-empty string")
    if "\x00" in value:
        raise BlockadeValidationError(f"{label} contains NUL")
    if len(value) > max_chars:
        raise BlockadeValidationError(f"{label} exceeds {max_chars} characters")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise BlockadeValidationError(f"{label} has an invalid format")
    return value


def _sha256_value(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise BlockadeValidationError(f"{label} must be lowercase SHA-256")
    return value


def _timestamp(value: Any, *, label: str) -> datetime:
    text = _bounded_string(value, label=label, max_chars=64)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise BlockadeValidationError(f"{label} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise BlockadeValidationError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _timestamp_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise BlockadeValidationError("datetime must include a timezone")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _absolute_path(value: Any, *, label: str) -> str:
    text = _bounded_string(value, label=label, max_chars=4096)
    path = PurePosixPath(text)
    if not path.is_absolute():
        raise BlockadeValidationError(f"{label} must be an absolute POSIX path")
    if any(part in {".", ".."} for part in text.split("/")):
        raise BlockadeValidationError(f"{label} contains dot traversal")
    normalized = str(path)
    if normalized != text:
        raise BlockadeValidationError(f"{label} is not canonical")
    return normalized


def _scope_value(kind: str, value: Any) -> str:
    if kind == "global":
        if value != "*":
            raise BlockadeValidationError("global scope value must be '*'")
        return "*"
    if kind in {"path", "repo"}:
        return _absolute_path(value, label=f"{kind} scope value")
    return _bounded_string(
        value,
        label=f"{kind} scope value",
        max_chars=256,
        pattern=_IDENTIFIER_RE,
    )


def canonical_json(value: Mapping[str, Any]) -> bytes:
    """Return stable UTF-8 JSON for hashing and persistence."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class Scope:
    kind: str
    value: str

    def __post_init__(self) -> None:
        if self.kind not in SCOPE_KINDS:
            raise BlockadeValidationError(f"unsupported scope kind: {self.kind}")
        object.__setattr__(self, "value", _scope_value(self.kind, self.value))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "Scope":
        if not isinstance(value, Mapping):
            raise BlockadeValidationError("scope must be an object")
        _exact_keys(value, required={"kind", "value"}, label="scope")
        return cls(kind=value["kind"], value=value["value"])

    def to_mapping(self) -> dict[str, str]:
        return {"kind": self.kind, "value": self.value}


@dataclass(frozen=True)
class Provenance:
    tool: str
    request_id: str
    session_id: str
    task_id: str
    owner_id: str

    def __post_init__(self) -> None:
        for name in ("tool", "request_id", "session_id", "task_id", "owner_id"):
            value = getattr(self, name)
            object.__setattr__(
                self,
                name,
                _bounded_string(value, label=f"provenance.{name}", max_chars=256),
            )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "Provenance":
        if not isinstance(value, Mapping):
            raise BlockadeValidationError("provenance must be an object")
        required = {"tool", "request_id", "session_id", "task_id", "owner_id"}
        _exact_keys(value, required=required, label="provenance")
        return cls(**{name: value[name] for name in sorted(required)})

    def to_mapping(self) -> dict[str, str]:
        return {
            "tool": self.tool,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "task_id": self.task_id,
            "owner_id": self.owner_id,
        }


@dataclass(frozen=True)
class BlockadeRecord:
    blockade_id: str
    posture: str
    scope: Scope
    reason: str
    trigger_class: str
    engaged_at: datetime
    evidence_refs: tuple[str, ...]
    provenance: Provenance
    source: str = "typed"
    disarm_policy: str = "in_band"
    expires_at: datetime | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version != SCHEMA_VERSION
        ):
            raise BlockadeValidationError(
                f"unsupported blockade schema_version: {self.schema_version}"
            )
        object.__setattr__(
            self,
            "blockade_id",
            _bounded_string(
                self.blockade_id,
                label="blockade_id",
                max_chars=128,
                pattern=_BLOCKADE_ID_RE,
            ),
        )
        if self.posture not in POSTURES:
            raise BlockadeValidationError(f"unsupported posture: {self.posture}")
        if not isinstance(self.scope, Scope):
            raise BlockadeValidationError("scope must be a Scope")
        object.__setattr__(
            self,
            "reason",
            _bounded_string(
                self.reason,
                label="reason",
                max_chars=_MAX_REASON_CHARS,
            ),
        )
        object.__setattr__(
            self,
            "trigger_class",
            _bounded_string(
                self.trigger_class,
                label="trigger_class",
                max_chars=256,
                pattern=_IDENTIFIER_RE,
            ),
        )
        if (
            self.posture == "hard_stop"
            and self.scope.kind == "global"
            and self.trigger_class not in GLOBAL_HARD_STOP_TRIGGER_CLASSES
        ):
            raise BlockadeValidationError(
                "global hard_stop requires a global trust trigger class"
            )
        if not isinstance(self.engaged_at, datetime):
            raise BlockadeValidationError("engaged_at must be a datetime")
        engaged = _timestamp(_timestamp_text(self.engaged_at), label="engaged_at")
        object.__setattr__(self, "engaged_at", engaged)
        if isinstance(self.evidence_refs, (str, bytes)) or not isinstance(
            self.evidence_refs, Sequence
        ):
            raise BlockadeValidationError("evidence_refs must be an array")
        if not isinstance(self.evidence_refs, tuple):
            object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        if not 1 <= len(self.evidence_refs) <= _MAX_EVIDENCE_REFS:
            raise BlockadeValidationError(
                f"evidence_refs must contain 1..{_MAX_EVIDENCE_REFS} entries"
            )
        normalized_refs: list[str] = []
        for index, ref in enumerate(self.evidence_refs):
            normalized_refs.append(
                _bounded_string(
                    ref,
                    label=f"evidence_refs[{index}]",
                    max_chars=_MAX_EVIDENCE_REF_CHARS,
                )
            )
        if len(set(normalized_refs)) != len(normalized_refs):
            raise BlockadeValidationError("evidence_refs must be unique")
        object.__setattr__(self, "evidence_refs", tuple(sorted(normalized_refs)))
        if not isinstance(self.provenance, Provenance):
            raise BlockadeValidationError("provenance must be Provenance")
        if self.source not in SOURCES:
            raise BlockadeValidationError(f"unsupported source: {self.source}")
        if self.disarm_policy not in DISARM_POLICIES:
            raise BlockadeValidationError(
                f"unsupported disarm_policy: {self.disarm_policy}"
            )
        if self.source == "environment" and self.disarm_policy != "external_only":
            raise BlockadeValidationError(
                "environment source requires external_only disarm policy"
            )
        if self.expires_at is not None:
            if not isinstance(self.expires_at, datetime):
                raise BlockadeValidationError("expires_at must be a datetime")
            expires = _timestamp(_timestamp_text(self.expires_at), label="expires_at")
            object.__setattr__(self, "expires_at", expires)
            if self.posture in {"mutation_freeze", "hard_stop"}:
                raise BlockadeValidationError(
                    f"{self.posture} must not expire automatically"
                )
            if expires <= engaged:
                raise BlockadeValidationError("expires_at must be after engaged_at")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "BlockadeRecord":
        if not isinstance(value, Mapping):
            raise BlockadeValidationError("blockade record must be an object")
        required = {
            "schema_version",
            "blockade_id",
            "posture",
            "scope",
            "reason",
            "trigger_class",
            "engaged_at",
            "evidence_refs",
            "provenance",
            "source",
            "disarm_policy",
        }
        _exact_keys(value, required=required, optional={"expires_at"}, label="record")
        refs = value["evidence_refs"]
        if not isinstance(refs, list):
            raise BlockadeValidationError("evidence_refs must be an array")
        return cls(
            schema_version=value["schema_version"],
            blockade_id=value["blockade_id"],
            posture=value["posture"],
            scope=Scope.from_mapping(value["scope"]),
            reason=value["reason"],
            trigger_class=value["trigger_class"],
            engaged_at=_timestamp(value["engaged_at"], label="engaged_at"),
            expires_at=(
                _timestamp(value["expires_at"], label="expires_at")
                if "expires_at" in value
                else None
            ),
            evidence_refs=tuple(refs),
            provenance=Provenance.from_mapping(value["provenance"]),
            source=value["source"],
            disarm_policy=value["disarm_policy"],
        )

    def to_mapping(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": self.schema_version,
            "blockade_id": self.blockade_id,
            "posture": self.posture,
            "scope": self.scope.to_mapping(),
            "reason": self.reason,
            "trigger_class": self.trigger_class,
            "engaged_at": _timestamp_text(self.engaged_at),
            "evidence_refs": list(self.evidence_refs),
            "provenance": self.provenance.to_mapping(),
            "source": self.source,
            "disarm_policy": self.disarm_policy,
        }
        if self.expires_at is not None:
            result["expires_at"] = _timestamp_text(self.expires_at)
        return result

    @property
    def sha256(self) -> str:
        return canonical_sha256(self.to_mapping())

    def active_at(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        current = _timestamp(_timestamp_text(current), label="now")
        return self.expires_at is None or current < self.expires_at


@dataclass(frozen=True)
class DisarmEvidence:
    blockade_id: str
    record_sha256: str
    scope: Scope
    marker_path: str
    marker_present: bool
    marker_regular: bool
    marker_nlink: int
    marker_mode: int
    marker_owner_matches: bool
    environment_switch_off: bool
    audit_valid: bool
    deployment_provenance_valid: bool
    canonical_recovery_fresh: bool
    root_broker_ready: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "blockade_id",
            _bounded_string(
                self.blockade_id,
                label="disarm.blockade_id",
                max_chars=128,
                pattern=_BLOCKADE_ID_RE,
            ),
        )
        object.__setattr__(
            self,
            "record_sha256",
            _sha256_value(self.record_sha256, label="disarm.record_sha256"),
        )
        if not isinstance(self.scope, Scope):
            raise BlockadeValidationError("disarm.scope must be Scope")
        object.__setattr__(
            self,
            "marker_path",
            _absolute_path(self.marker_path, label="disarm.marker_path"),
        )
        for name in (
            "marker_present",
            "marker_regular",
            "marker_owner_matches",
            "environment_switch_off",
            "audit_valid",
            "deployment_provenance_valid",
            "canonical_recovery_fresh",
            "root_broker_ready",
        ):
            if not isinstance(getattr(self, name), bool):
                raise BlockadeValidationError(f"disarm.{name} must be boolean")
        if isinstance(self.marker_nlink, bool) or not isinstance(
            self.marker_nlink, int
        ):
            raise BlockadeValidationError("disarm.marker_nlink must be an integer")
        if isinstance(self.marker_mode, bool) or not isinstance(self.marker_mode, int):
            raise BlockadeValidationError("disarm.marker_mode must be an integer")


@dataclass(frozen=True)
class DisarmValidation:
    allowed: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class ActionContext:
    action_class: str
    path: str | None = None
    capability: str | None = None
    task_id: str | None = None
    owner_id: str | None = None
    repo: str | None = None
    service: str | None = None
    host: str | None = None
    expected_marker_path: str | None = None
    fresh_preflight: bool = False
    disarm_evidence: DisarmEvidence | None = None

    def __post_init__(self) -> None:
        if self.action_class not in ACTION_CLASSES:
            raise BlockadeValidationError(
                f"unsupported action_class: {self.action_class}"
            )
        if self.path is not None:
            object.__setattr__(
                self, "path", _absolute_path(self.path, label="action.path")
            )
        if self.repo is not None:
            object.__setattr__(
                self, "repo", _absolute_path(self.repo, label="action.repo")
            )
        for name in ("capability", "task_id", "owner_id", "service", "host"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(
                    self,
                    name,
                    _bounded_string(
                        value,
                        label=f"action.{name}",
                        max_chars=256,
                        pattern=_IDENTIFIER_RE,
                    ),
                )
        if self.expected_marker_path is not None:
            object.__setattr__(
                self,
                "expected_marker_path",
                _absolute_path(
                    self.expected_marker_path, label="action.expected_marker_path"
                ),
            )
        if not isinstance(self.fresh_preflight, bool):
            raise BlockadeValidationError("action.fresh_preflight must be boolean")
        if self.action_class == "recovery_disarm":
            if self.disarm_evidence is None:
                raise BlockadeValidationError(
                    "recovery_disarm requires disarm_evidence"
                )
            if self.expected_marker_path is None:
                raise BlockadeValidationError(
                    "recovery_disarm requires expected_marker_path"
                )
        elif self.disarm_evidence is not None or self.expected_marker_path is not None:
            raise BlockadeValidationError(
                "disarm evidence and expected marker path are only valid for "
                "recovery_disarm"
            )


@dataclass(frozen=True)
class BlockadeDecision:
    allowed: bool
    blocked: bool
    requires_preflight: bool
    effective_posture: str | None
    matched_blockade_ids: tuple[str, ...]
    matched_record_sha256s: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    reasons: tuple[str, ...]
    disarm_validation: DisarmValidation | None = None

    def to_mapping(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "allowed": self.allowed,
            "blocked": self.blocked,
            "requires_preflight": self.requires_preflight,
            "effective_posture": self.effective_posture,
            "matched_blockade_ids": list(self.matched_blockade_ids),
            "matched_record_sha256s": list(self.matched_record_sha256s),
            "evidence_refs": list(self.evidence_refs),
            "reasons": list(self.reasons),
        }
        if self.disarm_validation is not None:
            result["disarm_validation"] = {
                "allowed": self.disarm_validation.allowed,
                "reasons": list(self.disarm_validation.reasons),
            }
        return result


def _path_matches(base: str, candidate: str) -> bool:
    base_path = PurePosixPath(base)
    candidate_path = PurePosixPath(candidate)
    return candidate_path == base_path or base_path in candidate_path.parents


def scope_matches(scope: Scope, action: ActionContext) -> bool:
    if scope.kind == "global":
        return True
    if scope.kind == "path":
        return action.path is not None and _path_matches(scope.value, action.path)
    if scope.kind == "repo":
        return action.repo is not None and _path_matches(scope.value, action.repo)
    action_value = {
        "capability": action.capability,
        "task": action.task_id,
        "owner": action.owner_id,
        "service": action.service,
        "host": action.host,
    }[scope.kind]
    return action_value is not None and action_value == scope.value


def validate_disarm(
    record: BlockadeRecord,
    evidence: DisarmEvidence,
    *,
    expected_marker_path: str,
) -> DisarmValidation:
    trusted_marker_path = _absolute_path(
        expected_marker_path, label="expected_marker_path"
    )
    reasons: list[str] = []
    checks = (
        (evidence.blockade_id == record.blockade_id, "blockade_id_mismatch"),
        (evidence.record_sha256 == record.sha256, "record_sha256_mismatch"),
        (evidence.scope == record.scope, "scope_mismatch"),
        (
            evidence.marker_path == trusted_marker_path,
            "marker_path_mismatch",
        ),
        (record.disarm_policy == "in_band", "external_only_disarm"),
        (record.source != "environment", "environment_source_external_only"),
        (evidence.marker_present, "marker_absent"),
        (evidence.marker_regular, "marker_not_regular"),
        (evidence.marker_nlink == 1, "marker_link_count_invalid"),
        (evidence.marker_mode == 0o600, "marker_mode_invalid"),
        (evidence.marker_owner_matches, "marker_owner_mismatch"),
        (evidence.environment_switch_off, "environment_switch_engaged"),
        (evidence.audit_valid, "audit_invalid"),
        (
            evidence.deployment_provenance_valid,
            "deployment_provenance_invalid",
        ),
        (evidence.canonical_recovery_fresh, "canonical_recovery_stale"),
        (evidence.root_broker_ready, "root_broker_not_ready"),
    )
    for passed, reason in checks:
        if not passed:
            reasons.append(reason)
    return DisarmValidation(allowed=not reasons, reasons=tuple(reasons))


def evaluate_blockades(
    records: Iterable[BlockadeRecord],
    action: ActionContext,
    *,
    now: datetime | None = None,
) -> BlockadeDecision:
    current = now or datetime.now(timezone.utc)
    items = tuple(records)
    if not all(isinstance(record, BlockadeRecord) for record in items):
        raise BlockadeValidationError("records must contain BlockadeRecord values")
    blockade_ids = [record.blockade_id for record in items]
    if len(blockade_ids) != len(set(blockade_ids)):
        raise BlockadeValidationError("duplicate blockade_id")
    matching = sorted(
        (
            record
            for record in items
            if record.active_at(current) and scope_matches(record.scope, action)
        ),
        key=lambda record: record.blockade_id,
    )
    postures = [record.posture for record in matching]
    effective = max(postures, key=POSTURE_ORDER.__getitem__) if postures else None
    matched_ids = tuple(record.blockade_id for record in matching)
    matched_hashes = tuple(record.sha256 for record in matching)
    evidence_refs = tuple(
        sorted({ref for record in matching for ref in record.evidence_refs})
    )
    reasons: list[str] = []
    requires_preflight = False
    disarm_validation: DisarmValidation | None = None

    if action.action_class in {"read", "status", "audit_read"}:
        allowed = True
        if effective is not None:
            reasons.append("immutable_read_lane_remains_available")
    elif action.action_class == "mutate":
        if effective is None or effective == "observe":
            allowed = True
            if effective == "observe":
                reasons.append("observe_only")
        elif effective == "preflight_required":
            requires_preflight = True
            allowed = action.fresh_preflight
            reasons.append(
                "fresh_preflight_satisfied" if allowed else "fresh_preflight_required"
            )
        else:
            allowed = False
            reasons.append(f"mutation_blocked_by_{effective}")
    else:
        evidence = action.disarm_evidence
        assert evidence is not None
        target = next(
            (
                record
                for record in matching
                if record.blockade_id == evidence.blockade_id
            ),
            None,
        )
        if target is None:
            allowed = False
            disarm_validation = DisarmValidation(
                allowed=False,
                reasons=("target_blockade_not_active_in_scope",),
            )
        else:
            assert action.expected_marker_path is not None
            disarm_validation = validate_disarm(
                target,
                evidence,
                expected_marker_path=action.expected_marker_path,
            )
            external_active = any(
                record.source == "environment"
                or record.disarm_policy == "external_only"
                for record in matching
            )
            if external_active:
                allowed = False
                disarm_validation = DisarmValidation(
                    allowed=False,
                    reasons=tuple(
                        dict.fromkeys(
                            disarm_validation.reasons
                            + ("external_stop_requires_external_clear",)
                        )
                    ),
                )
            else:
                allowed = disarm_validation.allowed
        reasons.extend(disarm_validation.reasons)
        if allowed:
            reasons.append("evidence_bound_recovery_allowed")

    return BlockadeDecision(
        allowed=allowed,
        blocked=not allowed,
        requires_preflight=requires_preflight,
        effective_posture=effective,
        matched_blockade_ids=matched_ids,
        matched_record_sha256s=matched_hashes,
        evidence_refs=evidence_refs,
        reasons=tuple(reasons),
        disarm_validation=disarm_validation,
    )


def _adapter_provenance(*, source: str, host: str) -> Provenance:
    return Provenance(
        tool=f"{source}-adapter",
        request_id=f"{source}:{host}",
        session_id="runtime-observation",
        task_id="runtime-observation",
        owner_id="grabowski-runtime",
    )


def legacy_marker_record(
    *,
    marker_path: str,
    marker_sha256: str,
    engaged_at: datetime,
    host: str,
) -> BlockadeRecord:
    path = _absolute_path(marker_path, label="marker_path")
    digest = _sha256_value(marker_sha256, label="marker_sha256")
    normalized_host = _bounded_string(
        host,
        label="host",
        max_chars=256,
        pattern=_IDENTIFIER_RE,
    )
    return BlockadeRecord(
        blockade_id=f"legacy-{digest[:24]}",
        posture="hard_stop",
        scope=Scope("global", "*"),
        reason="Legacy canonical operator stop marker is present.",
        trigger_class="legacy_operator_marker",
        engaged_at=engaged_at,
        evidence_refs=(f"path:{path}", f"sha256:{digest}"),
        provenance=_adapter_provenance(source="legacy", host=normalized_host),
        source="legacy_file",
        disarm_policy="in_band",
    )


def environment_stop_record(
    *,
    value_sha256: str,
    engaged_at: datetime,
    host: str,
) -> BlockadeRecord:
    digest = _sha256_value(value_sha256, label="value_sha256")
    normalized_host = _bounded_string(
        host,
        label="host",
        max_chars=256,
        pattern=_IDENTIFIER_RE,
    )
    return BlockadeRecord(
        blockade_id=f"environment-{digest[:24]}",
        posture="hard_stop",
        scope=Scope("global", "*"),
        reason="External environment operator stop is engaged.",
        trigger_class="external_environment_stop",
        engaged_at=engaged_at,
        evidence_refs=(f"environment-value-sha256:{digest}",),
        provenance=_adapter_provenance(
            source="environment",
            host=normalized_host,
        ),
        source="environment",
        disarm_policy="external_only",
    )


def load_records(values: Sequence[Mapping[str, Any]]) -> tuple[BlockadeRecord, ...]:
    """Strictly parse a persisted list and reject duplicate identities."""

    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise BlockadeValidationError("records must be an array")
    records = tuple(BlockadeRecord.from_mapping(value) for value in values)
    ids = [record.blockade_id for record in records]
    if len(ids) != len(set(ids)):
        raise BlockadeValidationError("duplicate blockade_id")
    return records

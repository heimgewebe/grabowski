from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

VALID_STATES = {"healthy", "warning", "unreachable", "unknown", "stale"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class CollectorResult:
    source: str
    status: str
    observed_at: str
    data: dict[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in VALID_STATES:
            raise ValueError(f"invalid status: {self.status}")
        if not self.source:
            raise ValueError("source must not be empty")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["warnings"] = list(self.warnings)
        value["errors"] = list(self.errors)
        return value


@dataclass(frozen=True)
class Snapshot:
    schema_version: int
    generated_at: str
    results: tuple[CollectorResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "results": [result.to_dict() for result in self.results],
        }

    @property
    def overall_status(self) -> str:
        states = {item.status for item in self.results}
        if "unreachable" in states:
            return "warning"
        if "warning" in states or "stale" in states:
            return "warning"
        if states == {"healthy"}:
            return "healthy"
        return "unknown"

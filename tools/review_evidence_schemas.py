from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any


_MISSING = object()


@dataclass(frozen=True)
class FieldRule:
    """Small dependency-free schema rule that can also emit JSON Schema."""

    json_types: tuple[str, ...]
    const: Any = _MISSING
    enum: tuple[Any, ...] | None = None
    items: "FieldRule | None" = None
    min_items: int | None = None
    min_length: int | None = None
    minimum: int | float | None = None
    maximum: int | float | None = None

    def as_json_schema(self) -> dict[str, Any]:
        schema: dict[str, Any] = {}
        if len(self.json_types) == 1:
            schema["type"] = self.json_types[0]
        else:
            schema["type"] = list(self.json_types)
        if self.const is not _MISSING:
            schema["const"] = self.const
        if self.enum is not None:
            schema["enum"] = list(self.enum)
        if self.items is not None:
            schema["items"] = self.items.as_json_schema()
        if self.min_items is not None:
            schema["minItems"] = self.min_items
        if self.min_length is not None:
            schema["minLength"] = self.min_length
        if self.minimum is not None:
            schema["minimum"] = self.minimum
        if self.maximum is not None:
            schema["maximum"] = self.maximum
        return schema


@dataclass(frozen=True)
class EvidenceSchema:
    name: str
    fields: dict[str, FieldRule]
    required: frozenset[str]
    additional_properties: bool

    def validate(self, payload: Any) -> tuple[str, ...]:
        if not isinstance(payload, dict):
            return ("evidence must be a JSON object",)

        failures: list[str] = []
        missing = sorted(self.required - set(payload))
        if missing:
            failures.append("missing required field(s): " + ", ".join(missing))

        if not self.additional_properties:
            unknown = sorted(set(payload) - set(self.fields))
            if unknown:
                failures.append("unknown field(s): " + ", ".join(unknown))

        for field_name, value in payload.items():
            rule = self.fields.get(field_name)
            if rule is None:
                continue
            failures.extend(_validate_rule(value, rule, field_name))
        return tuple(failures)

    def as_json_schema(self) -> dict[str, Any]:
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": self.name,
            "type": "object",
            "properties": {
                field_name: rule.as_json_schema()
                for field_name, rule in self.fields.items()
            },
            "required": sorted(self.required),
            "additionalProperties": self.additional_properties,
        }


def _matches_json_type(value: Any, json_type: str) -> bool:
    if json_type == "object":
        return isinstance(value, dict)
    if json_type == "array":
        return isinstance(value, list)
    if json_type == "string":
        return isinstance(value, str)
    if json_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if json_type == "number":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
        )
    if json_type == "boolean":
        return isinstance(value, bool)
    if json_type == "null":
        return value is None
    raise ValueError(f"unsupported JSON type rule: {json_type}")


def _type_label(json_types: tuple[str, ...]) -> str:
    if len(json_types) == 1:
        article = "an" if json_types[0] in {"array", "integer", "object"} else "a"
        return f"{article} {json_types[0]}"
    return "one of: " + ", ".join(json_types)


def _validate_rule(value: Any, rule: FieldRule, path: str) -> list[str]:
    failures: list[str] = []
    if not any(_matches_json_type(value, json_type) for json_type in rule.json_types):
        return [f"field {path} must be {_type_label(rule.json_types)}"]

    if rule.const is not _MISSING and value != rule.const:
        failures.append(f"field {path} must equal {rule.const!r}")
    if rule.enum is not None and value not in rule.enum:
        failures.append(f"field {path} must be one of: {', '.join(map(str, rule.enum))}")
    if isinstance(value, str) and rule.min_length is not None and len(value) < rule.min_length:
        failures.append(f"field {path} must contain at least {rule.min_length} character(s)")
    if isinstance(value, list):
        if rule.min_items is not None and len(value) < rule.min_items:
            failures.append(f"field {path} must contain at least {rule.min_items} item(s)")
        if rule.items is not None:
            for index, item in enumerate(value):
                failures.extend(_validate_rule(item, rule.items, f"{path}[{index}]"))
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    ):
        if rule.minimum is not None and value < rule.minimum:
            failures.append(f"field {path} must be >= {rule.minimum}")
        if rule.maximum is not None and value > rule.maximum:
            failures.append(f"field {path} must be <= {rule.maximum}")
    return failures


STRING = FieldRule(("string",), min_length=1)
INTEGER = FieldRule(("integer",))
NON_NEGATIVE_INTEGER = FieldRule(("integer",), minimum=0)
POSITIVE_INTEGER = FieldRule(("integer",), minimum=1)
BOOLEAN = FieldRule(("boolean",))
OBJECT = FieldRule(("object",))
STRING_ARRAY = FieldRule(("array",), items=STRING)
NON_EMPTY_STRING_ARRAY = FieldRule(("array",), items=STRING, min_items=1)
OBJECT_ARRAY = FieldRule(("array",), items=OBJECT)


SELF_REVIEW_SCHEMA = EvidenceSchema(
    name="Grabowski self-review evidence v1",
    fields={
        "schema_version": FieldRule(("integer",), const=1),
        "kind": FieldRule(("string",), const="grabowski_self_review"),
        "reviewer": STRING,
        "review_mode": FieldRule(("string",), const="critical_diff_review"),
        "repo": STRING,
        "pr": POSITIVE_INTEGER,
        "head_sha": STRING,
        "diff_sha256": STRING,
        "diff_reviewed": BOOLEAN,
        "reviewed_files": NON_EMPTY_STRING_ARRAY,
        "review_focus": NON_EMPTY_STRING_ARRAY,
        "verdict": FieldRule(("string",), enum=("PASS", "NEEDS_CHANGE", "BLOCK")),
        "minimum_review_iterations": POSITIVE_INTEGER,
        "review_iterations": FieldRule(("array",), items=OBJECT, min_items=1),
        "all_findings_triaged": BOOLEAN,
        "findings": OBJECT_ARRAY,
        "material_findings_remaining": FieldRule(("integer", "null"), minimum=0),
        "material_findings_after_first_review": FieldRule(("integer", "null"), minimum=0),
        "uncertainty": FieldRule(("number", "null"), minimum=0, maximum=1),
        "stop_reason": FieldRule(
            ("string",),
            enum=(
                "clean_pass",
                "diminishing_returns",
                "residual_only_with_reason",
                "small_trivial_change",
            ),
        ),
        "residual_risk": OBJECT,
        # Deprecated v1 compatibility fields remain structurally accepted;
        # the gate decides whether they have any policy effect.
        "codex_review": OBJECT,
        "claude_review": OBJECT,
        "external_review": OBJECT,
    },
    required=frozenset(
        {
            "schema_version",
            "kind",
            "review_mode",
            "repo",
            "pr",
            "head_sha",
            "diff_reviewed",
            "reviewed_files",
            "review_focus",
            "verdict",
            "review_iterations",
            "all_findings_triaged",
            "findings",
            "material_findings_remaining",
            "material_findings_after_first_review",
            "uncertainty",
            "stop_reason",
        }
    ),
    additional_properties=False,
)


EXTERNAL_REVIEW_SCHEMA = EvidenceSchema(
    name="Grabowski external review evidence v1",
    fields={
        "schema_version": FieldRule(("integer",), const=1),
        "kind": FieldRule(("string",), const="external_review"),
        "required": BOOLEAN,
        "repo": STRING,
        "pr": POSITIVE_INTEGER,
        "head_sha": STRING,
        "diff_sha256": STRING,
        "prompt_sha256": STRING,
        "prompt_includes_diff": BOOLEAN,
        "prompt_transmitted": BOOLEAN,
        "review_input": OBJECT,
        "reviews": OBJECT_ARRAY,
        "external_reviews_triaged": BOOLEAN,
        "findings": OBJECT_ARRAY,
    },
    required=frozenset(
        {
            "schema_version",
            "kind",
            "repo",
            "pr",
            "head_sha",
            "diff_sha256",
            "prompt_sha256",
            "prompt_includes_diff",
            "reviews",
            "external_reviews_triaged",
            "findings",
        }
    ),
    additional_properties=False,
)


CLAUDE_EVIDENCE_SCHEMA = EvidenceSchema(
    name="Grabowski Claude ultrareview evidence v1",
    fields={
        "schema_version": FieldRule(("integer",), const=1),
        "kind": FieldRule(("string",), const="claude_ultrareview"),
        "repo": STRING,
        "pr": POSITIVE_INTEGER,
        "head_sha": STRING,
        "expected_head_sha": STRING,
        "tool": FieldRule(("string",), const="claude-code"),
        "tool_version": STRING,
        "command": NON_EMPTY_STRING_ARRAY,
        "exit_code": INTEGER,
        "json_ok": BOOLEAN,
        "verdict": FieldRule(("string",), enum=("PASS", "NEEDS_CHANGE", "BLOCK")),
        "finding_count": NON_NEGATIVE_INTEGER,
        "findings_triaged": BOOLEAN,
        "stdout_sha256": STRING,
        "stderr_sha256": STRING,
    },
    required=frozenset(
        {
            "schema_version",
            "kind",
            "repo",
            "pr",
            "head_sha",
            "expected_head_sha",
            "tool",
            "tool_version",
            "command",
            "exit_code",
            "json_ok",
            "verdict",
            "finding_count",
            "findings_triaged",
            "stdout_sha256",
            "stderr_sha256",
        }
    ),
    additional_properties=False,
)


SCHEMAS = {
    "self-review": SELF_REVIEW_SCHEMA,
    "external review evidence": EXTERNAL_REVIEW_SCHEMA,
    "Claude evidence": CLAUDE_EVIDENCE_SCHEMA,
}


def validate_evidence(payload: Any, *, label: str) -> tuple[str, ...]:
    try:
        schema = SCHEMAS[label]
    except KeyError as exc:
        raise ValueError(f"unknown evidence schema label: {label}") from exc
    return schema.validate(payload)


def json_schema_for(label: str) -> dict[str, Any]:
    try:
        schema = SCHEMAS[label]
    except KeyError as exc:
        raise ValueError(f"unknown evidence schema label: {label}") from exc
    return schema.as_json_schema()

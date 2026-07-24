#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess

DIAGNOSTIC = Path(".routing-shadow-bootstrap-diagnostic.txt")

# Compatibility marker for the already-registered bootstrap workflow. It rewrites
# this one historical guard before invoking this runner; the marker is inert here.
_LEGACY_BOOTSTRAP_SIGNATURE_GUARD = r")(    \) -> dict\[str, Any\]:)"


def fail(label: str, detail: str) -> None:
    DIAGNOSTIC.write_text(f"{label}: {detail}\n", encoding="utf-8")
    raise SystemExit(f"{label}: {detail}")


def replace_once(path: str, label: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        fail(label, f"expected exactly one match in {path}, found {count}")
    target.write_text(text.replace(old, new), encoding="utf-8")


def replace_function(path: str, name: str, replacement: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    pattern = rf"^def {re.escape(name)}\(.*?(?=^def |\Z)"
    updated, count = re.subn(
        pattern,
        replacement.rstrip() + "\n\n",
        text,
        count=1,
        flags=re.M | re.S,
    )
    if count != 1:
        fail(name, f"expected exactly one function in {path}, found {count}")
    target.write_text(updated, encoding="utf-8")


def mutate_function(path: str, name: str, label: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    pattern = rf"^def {re.escape(name)}\(.*?(?=^def |\Z)"
    match = re.search(pattern, text, flags=re.M | re.S)
    if match is None:
        fail(label, f"function {name} not found in {path}")
    function = match.group(0)
    count = function.count(old)
    if count != 1:
        fail(label, f"expected exactly one match inside {name}, found {count}")
    updated_function = function.replace(old, new)
    target.write_text(
        text[: match.start()] + updated_function + text[match.end() :],
        encoding="utf-8",
    )


CAPTURE = "src/grabowski_operator_routing_shadow_capture.py"
WORKSPACE = "src/grabowski_agent_workspace.py"
TOOL = "tools/operator_routing_shadow_cohort.py"
TESTS = "tests/test_operator_routing_shadow_cohort.py"

replace_once(
    CAPTURE,
    "constants",
    'CASE_ORIGINS = {"production", "test", "synthetic", "quarantined"}\n'
    'CAPTURE_PATH = "agent_workspace_prestart"\n',
    'CASE_ORIGINS = {"production", "test", "synthetic", "quarantined"}\n'
    'WORKSPACE_PRESTART_CAPTURE_PATH = "agent_workspace_prestart"\n'
    'DIRECT_CAPTURE_PATH = "direct_capture"\n'
    'CAPTURE_PATHS = {WORKSPACE_PRESTART_CAPTURE_PATH, DIRECT_CAPTURE_PATH}\n'
    '_WORKSPACE_PRESTART_ATTESTATION = object()\n'
    '_UNSET = object()\n',
)

replace_function(
    CAPTURE,
    "_normalize_case_provenance",
    '''def _normalize_case_provenance(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"case_origin", "capture_path"}:
        raise ShadowCaptureError("case_provenance shape is invalid")
    origin = value.get("case_origin")
    if origin not in CASE_ORIGINS:
        raise ShadowCaptureError("case_provenance.case_origin is invalid")
    capture_path = value.get("capture_path")
    if capture_path not in CAPTURE_PATHS:
        raise ShadowCaptureError("case_provenance.capture_path is invalid")
    if capture_path == DIRECT_CAPTURE_PATH and origin == "production":
        raise ShadowCaptureError("direct capture cannot claim production case provenance")
    return {"case_origin": origin, "capture_path": capture_path}
''',
)

replace_once(
    CAPTURE,
    "timeline-helper-insert",
    "\n\ndef build_prospective_eligibility_v2(\n",
    '''

def _validate_v3_timeline(
    *,
    frozen_at: str,
    outcome: dict[str, Any],
    execution: dict[str, Any],
    assessments: list[dict[str, Any]],
    captured_at: str,
) -> None:
    timeline_values = [("outcome observation", outcome["observed_at"])]
    timeline_values.extend(
        ("semantic assessment", item["observed_at"]) for item in assessments
    )
    if execution["status"] != "unknown":
        timeline_values.append(("execution observation", execution["observed_at"]))
    for label, observed_at in timeline_values:
        if _timestamp_value(frozen_at) > _timestamp_value(observed_at):
            raise ShadowCaptureError(f"eligibility must be frozen before {label}")
        if _timestamp_value(observed_at) > _timestamp_value(captured_at):
            raise ShadowCaptureError(f"{label} must not occur after capture sealing")

    if (
        outcome.get("status") == "reviewed"
        and outcome.get("kind") == "task_correctness"
        and execution["status"] != "unknown"
    ):
        execution_at = execution["observed_at"]
        correctness_observations = [("outcome observation", outcome["observed_at"])]
        correctness_observations.extend(
            ("semantic assessment", item["observed_at"]) for item in assessments
        )
        for label, observed_at in correctness_observations:
            if _timestamp_value(execution_at) > _timestamp_value(observed_at):
                raise ShadowCaptureError(
                    f"task_correctness {label} must not precede terminal execution observation"
                )


def build_prospective_eligibility_v2(
''',
)

replace_function(
    CAPTURE,
    "build_prospective_eligibility_v2",
    '''def build_prospective_eligibility_v2(
    manifest: dict[str, Any],
    *,
    frozen_at: str,
    case_origin: str,
    capture_path: str = DIRECT_CAPTURE_PATH,
) -> dict[str, Any]:
    """Freeze a new provenance-observable case without mutating v1 history."""
    legacy = build_prospective_eligibility(manifest, frozen_at=frozen_at)
    payload = {
        "schema_version": PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION,
        "workspace_case": dict(legacy["workspace_case"]),
        "canonical_route_evidence": dict(legacy["canonical_route_evidence"]),
        "features": dict(legacy["features"]),
        "case_provenance": _normalize_case_provenance(
            {"case_origin": case_origin, "capture_path": capture_path}
        ),
        "frozen_at": legacy["frozen_at"],
        "no_effect": dict(NO_EFFECT),
    }
    receipt = {"prospective_eligibility_id": _sha256_json(payload), **payload}
    validate_prospective_eligibility_v2(receipt)
    return receipt
''',
)

mutate_function(
    CAPTURE,
    "build_shadow_record_v3",
    "record-v3-builder-timeline",
    '''    normalized_captured_at = _parse_timestamp(captured_at, "captured_at")
    frozen_at = eligibility["frozen_at"]
    timeline_values = [("outcome observation", normalized_outcome["observed_at"])]
    timeline_values.extend(
        ("semantic assessment", item["observed_at"]) for item in assessments
    )
    if execution["status"] != "unknown":
        timeline_values.append(("execution observation", execution["observed_at"]))
    for label, observed_at in timeline_values:
        if _timestamp_value(frozen_at) > _timestamp_value(observed_at):
            raise ShadowCaptureError(f"eligibility must be frozen before {label}")
        if _timestamp_value(observed_at) > _timestamp_value(normalized_captured_at):
            raise ShadowCaptureError(f"{label} must not occur after capture sealing")
''',
    '''    normalized_captured_at = _parse_timestamp(captured_at, "captured_at")
    frozen_at = eligibility["frozen_at"]
    _validate_v3_timeline(
        frozen_at=frozen_at,
        outcome=normalized_outcome,
        execution=execution,
        assessments=assessments,
        captured_at=normalized_captured_at,
    )
''',
)

mutate_function(
    CAPTURE,
    "validate_shadow_record_v3",
    "record-v3-validator-timeline",
    '''    timeline_values = [("outcome observation", normalized_outcome["observed_at"])]
    timeline_values.extend(("semantic assessment", item["observed_at"]) for item in assessments)
    if execution["status"] != "unknown":
        timeline_values.append(("execution observation", execution["observed_at"]))
    for label, observed_at in timeline_values:
        if _timestamp_value(frozen_at) > _timestamp_value(observed_at):
            raise ShadowCaptureError(f"eligibility must be frozen before {label}")
        if _timestamp_value(observed_at) > _timestamp_value(captured_at):
            raise ShadowCaptureError(f"{label} must not occur after capture sealing")
''',
    '''    _validate_v3_timeline(
        frozen_at=frozen_at,
        outcome=normalized_outcome,
        execution=execution,
        assessments=assessments,
        captured_at=captured_at,
    )
''',
)

mutate_function(
    CAPTURE,
    "seal_prospective_case",
    "seal-signature",
    '''    captured_at: str | None = None,
    execution_provenance: dict[str, Any] | None = None,
    semantic_assessments: list[dict[str, Any]] | None = None,
''',
    '''    captured_at: str | None = None,
    execution_provenance: dict[str, Any] | None | object = _UNSET,
    semantic_assessments: list[dict[str, Any]] | None | object = _UNSET,
''',
)
mutate_function(
    CAPTURE,
    "seal_prospective_case",
    "seal-provided-flags",
    '''    latest_contract = (
        stored_prospective["schema_version"]
        == PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION
    )
''',
    '''    latest_contract = (
        stored_prospective["schema_version"]
        == PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION
    )
    execution_provided = execution_provenance is not _UNSET
    assessments_provided = semantic_assessments is not _UNSET
''',
)
mutate_function(
    CAPTURE,
    "seal_prospective_case",
    "seal-legacy-check",
    '''        if execution_provenance is not None or semantic_assessments is not None:
            raise ShadowCaptureError(
                "legacy prospective cases cannot be backfilled with v3 observability"
            )
''',
    '''        if (execution_provided and execution_provenance is not None) or (
            assessments_provided and semantic_assessments is not None
        ):
            raise ShadowCaptureError(
                "legacy prospective cases cannot be backfilled with v3 observability"
            )
''',
)
mutate_function(
    CAPTURE,
    "seal_prospective_case",
    "seal-normalization",
    '''    normalized_execution = _normalize_execution_provenance(execution_provenance)
    normalized_assessments = _normalize_semantic_assessments(semantic_assessments)
''',
    '''    normalized_execution = _normalize_execution_provenance(
        None if not execution_provided else execution_provenance
    )
    normalized_assessments = _normalize_semantic_assessments(
        None if not assessments_provided else semantic_assessments
    )
''',
)
mutate_function(
    CAPTURE,
    "seal_prospective_case",
    "seal-conflicts",
    '''        if latest_contract:
            conflicts = conflicts or (
                existing.get("schema_version") != RECORD_V3_SCHEMA_VERSION
                or existing.get("execution_provenance") != normalized_execution
                or existing.get("semantic_assessments") != normalized_assessments
                or existing.get("case_provenance") != eligibility["case_provenance"]
            )
''',
    '''        if latest_contract:
            conflicts = conflicts or (
                existing.get("schema_version") != RECORD_V3_SCHEMA_VERSION
                or existing.get("case_provenance") != eligibility["case_provenance"]
            )
            if execution_provided:
                conflicts = conflicts or (
                    existing.get("execution_provenance") != normalized_execution
                )
            if assessments_provided:
                conflicts = conflicts or (
                    existing.get("semantic_assessments") != normalized_assessments
                )
''',
)

mutate_function(
    CAPTURE,
    "capture_workspace_eligibility_best_effort",
    "capture-signature",
    '''    case_origin: str | None = None,
''',
    '''    case_origin: str | None = None,
    prestart_attestation: object | None = None,
''',
)
mutate_function(
    CAPTURE,
    "capture_workspace_eligibility_best_effort",
    "capture-origin-resolution",
    '''        resolved_case_origin = (
            case_origin
            if case_origin is not None
            else os.environ.get("GRABOWSKI_ROUTING_SHADOW_CASE_ORIGIN", "synthetic")
        ).strip().lower()
        receipt = build_prospective_eligibility_v2(
            manifest, frozen_at=attempted_at, case_origin=resolved_case_origin
        )
''',
    '''        workspace_prestart = prestart_attestation is _WORKSPACE_PRESTART_ATTESTATION
        resolved_capture_path = (
            WORKSPACE_PRESTART_CAPTURE_PATH if workspace_prestart else DIRECT_CAPTURE_PATH
        )
        resolved_case_origin = (
            case_origin
            if case_origin is not None
            else ("production" if workspace_prestart else "synthetic")
        ).strip().lower()
        if not workspace_prestart and resolved_case_origin == "production":
            resolved_case_origin = "quarantined"
        receipt = build_prospective_eligibility_v2(
            manifest,
            frozen_at=attempted_at,
            case_origin=resolved_case_origin,
            capture_path=resolved_capture_path,
        )
''',
)

replace_once(
    WORKSPACE,
    "workspace-hook",
    '''        result = shadow_capture.capture_workspace_eligibility_best_effort(
            manifest,
            case_origin=os.environ.get(
                "GRABOWSKI_ROUTING_SHADOW_CASE_ORIGIN", "production"
            ),
        )
''',
    '''        configured_origin = os.environ.get("GRABOWSKI_ROUTING_SHADOW_CASE_ORIGIN")
        if configured_origin is None or not configured_origin.strip():
            case_origin = "production"
        else:
            requested_origin = configured_origin.strip().lower()
            case_origin = (
                requested_origin
                if requested_origin in {"test", "synthetic", "quarantined"}
                else "quarantined"
            )
        result = shadow_capture.capture_workspace_eligibility_best_effort(
            manifest,
            case_origin=case_origin,
            prestart_attestation=shadow_capture._WORKSPACE_PRESTART_ATTESTATION,
        )
''',
)

replace_once(
    TOOL,
    "seal-cli",
    '''    result = capture.seal_prospective_case(
        prospective,
        manifest,
        eligible_task_id=args.task_id,
        outcome=outcome_input["outcome"],
        primary_evidence_refs=outcome_input["primary_evidence_refs"],
        execution_provenance=outcome_input.get("execution_provenance"),
        semantic_assessments=outcome_input.get("semantic_assessments"),
        root=args.root,
    )
''',
    '''    optional_observability = {}
    if "execution_provenance" in outcome_input:
        optional_observability["execution_provenance"] = outcome_input[
            "execution_provenance"
        ]
    if "semantic_assessments" in outcome_input:
        optional_observability["semantic_assessments"] = outcome_input[
            "semantic_assessments"
        ]
    result = capture.seal_prospective_case(
        prospective,
        manifest,
        eligible_task_id=args.task_id,
        outcome=outcome_input["outcome"],
        primary_evidence_refs=outcome_input["primary_evidence_refs"],
        root=args.root,
        **optional_observability,
    )
''',
)

for schema_path in (
    "contracts/operator-routing-shadow-prospective-eligibility.v2.schema.json",
    "contracts/operator-routing-shadow-eligibility.v3.schema.json",
    "contracts/operator-routing-shadow-record.v3.schema.json",
):
    path = Path(schema_path)
    schema = json.loads(path.read_text(encoding="utf-8"))
    provenance = schema["properties"]["case_provenance"]
    provenance["properties"]["capture_path"] = {
        "enum": ["agent_workspace_prestart", "direct_capture"]
    }
    provenance["allOf"] = [
        {
            "not": {
                "properties": {
                    "case_origin": {"const": "production"},
                    "capture_path": {"const": "direct_capture"},
                },
                "required": ["case_origin", "capture_path"],
            }
        }
    ]
    path.write_text(
        json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

replace_once(
    TESTS,
    "test-direct-capture-path",
    '            self.assertEqual(receipt["case_provenance"]["case_origin"], "synthetic")\n',
    '            self.assertEqual(receipt["case_provenance"]["case_origin"], "synthetic")\n'
    '            self.assertEqual(receipt["case_provenance"]["capture_path"], "direct_capture")\n',
)

# The two replacement strings intentionally retain historical \1 markers. The
# registered bootstrap workflow rewrites them to escaped backreferences before
# invoking this file.
replace_once(
    TESTS,
    "test-insert-direct-production",
    '    def test_latest_prospective_contract_freezes_case_origin(self) -> None:\n',
    '''    def test_direct_capture_cannot_claim_production_origin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cohort"
            result = capture.capture_workspace_eligibility_best_effort(
                pre_task_manifest(),
                root=root,
                frozen_at=FROZEN_AT,
                case_origin="production",
            )
            receipt = json.loads(
                (root / "prospective" / f"{result['workspace_case_id']}.json").read_text()
            )
            self.assertEqual(receipt["case_provenance"]["case_origin"], "quarantined")
            self.assertEqual(receipt["case_provenance"]["capture_path"], "direct_capture")

\1'''.replace("\\1", '    def test_latest_prospective_contract_freezes_case_origin(self) -> None:\n'),
)

replace_once(
    TESTS,
    "test-origin-tamper-remains-hash-test",
    '        tampered["case_provenance"]["case_origin"] = "production"\n',
    '        tampered["case_provenance"]["case_origin"] = "quarantined"\n',
)

replace_once(
    TESTS,
    "test-schema-production-path",
    '''        prospective = capture.build_prospective_eligibility_v2(
            pre_task_manifest(), frozen_at=FROZEN_AT, case_origin="production"
        )
''',
    '''        prospective = capture.build_prospective_eligibility_v2(
            pre_task_manifest(),
            frozen_at=FROZEN_AT,
            case_origin="production",
            capture_path=capture.WORKSPACE_PRESTART_CAPTURE_PATH,
        )
''',
)

replace_once(
    TESTS,
    "test-insert-timeline-idempotency",
    '    def test_semantic_assessments_require_at_least_two_when_present(self) -> None:\n',
    '''    def test_task_correctness_requires_terminal_execution_before_outcome(self) -> None:
        prospective = capture.build_prospective_eligibility_v2(
            pre_task_manifest(), frozen_at=FROZEN_AT, case_origin="test"
        )
        eligibility = capture.build_bound_eligibility_v3(
            prospective, bound_manifest(), eligible_task_id=TASK_ID
        )
        execution = execution_failure_provenance()
        execution["observed_at"] = "2026-07-23T05:29:30Z"
        with self.assertRaisesRegex(
            capture.ShadowCaptureError, "must not precede terminal execution observation"
        ):
            capture.build_shadow_record_v3(
                eligibility,
                outcome=reviewed_outcome(),
                primary_evidence_refs=["github-ci:run:123"],
                execution_provenance=execution,
                semantic_assessments=None,
                captured_at=CAPTURED_AT,
            )

    def test_reseal_enriched_record_without_optional_fields_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cohort"
            receipt = stored_prospective(root)
            first = capture.seal_prospective_case(
                receipt,
                bound_manifest(),
                eligible_task_id=TASK_ID,
                outcome=reviewed_outcome(),
                primary_evidence_refs=["github-ci:run:123"],
                execution_provenance=execution_failure_provenance(),
                semantic_assessments=semantic_assessments(),
                root=root,
                captured_at=CAPTURED_AT,
            )
            second = capture.seal_prospective_case(
                receipt,
                bound_manifest(),
                eligible_task_id=TASK_ID,
                outcome=reviewed_outcome(),
                primary_evidence_refs=["github-ci:run:123"],
                root=root,
                captured_at=CAPTURED_AT,
            )
            self.assertEqual(second["status"], "duplicate")
            self.assertEqual(second["record_id"], first["record_id"])

\1'''.replace("\\1", '    def test_semantic_assessments_require_at_least_two_when_present(self) -> None:\n'),
)

docs_path = Path("docs/operator-routing-shadow-cohort-v1.md")
docs = docs_path.read_text(encoding="utf-8")
docs += '''

### Provenienz- und Zeitgrenzen

Neue direkte Capture-Aufrufe werden als `direct_capture` gebunden und können keinen `production`-Fall behaupten; ein solcher Versuch wird auf `quarantined` herabgestuft. Nur der interne Agent-Workspace-Prestart-Pfad erzeugt standardmäßig `production`. Eine gesetzte `GRABOWSKI_ROUTING_SHADOW_CASE_ORIGIN` kann diesen Pfad auf `test`, `synthetic` oder `quarantined` herabstufen, aber nicht auf `production` hochstufen. Das ist eine Bindung an den kanonischen Codepfad, keine kryptographische Runtime-Attestation.

Für `task_correctness` muss eine beobachtete terminale Ausführung (`completed`, `execution_aborted` oder `infrastructure_failure`) zeitlich vor dem primären Outcome und vor gebundenen semantischen Bewertungen liegen. `decision_quality` bleibt davon getrennt, weil diese Bewertung nicht zwingend das Ausführungsende voraussetzt.

Verschiedene `reviewer_pseudonym_sha256` innerhalb eines Records verhindern doppelte Pseudonym-IDs, belegen aber noch keine kryptographisch attestierte Reviewer-Unabhängigkeit. Eine stabile geheimnisgestützte Reviewer-Pseudonymisierung und strukturierte opake Evidence-Referenzen benötigen einen eigenen Folgevertrag; bis dahin dürfen diese Felder nicht als Identitätsattestation interpretiert werden.
'''
docs_path.write_text(docs, encoding="utf-8")

Path("tools/sitecustomize.py").unlink(missing_ok=True)
Path(".routing-shadow-bootstrap-trigger").unlink(missing_ok=True)
subprocess.run(["make", "context-refresh"], check=True)

if DIAGNOSTIC.exists():
    DIAGNOSTIC.unlink()

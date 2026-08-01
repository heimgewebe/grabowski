from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = ROOT / "src" / "grabowski_reposkop_context.py"
TESTS = ROOT / "tests" / "test_reposkop_context.py"


def replace_between(text: str, start_token: str, end_token: str, replacement: str) -> str:
    start = text.index(start_token)
    end = text.index(end_token, start)
    return text[:start] + replacement + text[end:]


context = CONTEXT.read_text(encoding="utf-8")
context = context.replace("TOOL_KIND = \"grabowski_reposkop_context\"\nSCHEMA_VERSION = 1", "TOOL_KIND = \"grabowski_reposkop_context\"\nSCHEMA_VERSION = 2")
context = replace_between(
    context,
    "def _is_schema_version_one",
    "\ndef _kill_process_group",
    '''def _is_schema_version(value: Any, expected: int) -> bool:
    return type(value) is int and value == expected


def _reject_nonfinite_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is unsupported: {value}")


def _reposkop_artifact_sha256(value: dict[str, Any]) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return _sha256_bytes(payload)


def _verify_reposkop_digest(
    artifact: dict[str, Any], *, field: str, label: str
) -> str:
    expected = _required_sha256(artifact.get(field), label=label)
    unsigned = dict(artifact)
    unsigned.pop(field, None)
    if _reposkop_artifact_sha256(unsigned) != expected:
        raise ReposkopContextError(
            f"Reposkop report has mismatched {label}"
        )
    return expected


def _validate_report(
    report: Any,
    *,
    target: Path,
    purpose: str,
    allowed_paths: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ReposkopContextError("Reposkop report must be a JSON object")
    if (
        report.get("kind") != "reposkop_coherence_report"
        or not _is_schema_version(report.get("schema_version"), 2)
    ):
        raise ReposkopContextError("Reposkop report kind or schema is unsupported")
    if report.get("effect_authorized") is not False:
        raise ReposkopContextError("Reposkop report must keep effect_authorized=false")
    if report.get("authority_boundary") != {
        "checkout_identity_truth": "reposkop",
        "checkout_transition_truth": "reposkop",
        "effect_executor": "grabowski",
        "task_truth": "bureau",
        "pull_request_truth": "github",
        "display": "leitstand",
    }:
        raise ReposkopContextError("Reposkop report authority boundary is unsupported")
    observation = report.get("observation")
    projection = report.get("projection")
    if not isinstance(observation, dict) or not isinstance(projection, dict):
        raise ReposkopContextError(
            "Reposkop report is missing observation or projection"
        )
    if (
        observation.get("kind") != "reposkop_checkout_observation"
        or not _is_schema_version(observation.get("schema_version"), 2)
    ):
        raise ReposkopContextError(
            "Reposkop observation kind or schema is unsupported"
        )
    if observation.get("authority") != {
        "producer": "reposkop",
        "domain": "local_checkout_identity",
        "claim": "canonical",
    }:
        raise ReposkopContextError("Reposkop observation authority is unsupported")
    if observation.get("observation_complete") is not True:
        raise ReposkopContextError("Reposkop observation must be complete")
    if (
        projection.get("kind") != "reposkop_coherence_projection"
        or not _is_schema_version(projection.get("schema_version"), 1)
    ):
        raise ReposkopContextError(
            "Reposkop projection kind or schema is unsupported"
        )
    if projection.get("effect_authorized") is not False:
        raise ReposkopContextError(
            "Reposkop projection must keep effect_authorized=false"
        )
    identities = observation.get("identities")
    if not isinstance(identities, dict):
        raise ReposkopContextError("Reposkop observation is missing identities")
    accepted_paths = {str(target)}
    if allowed_paths is not None:
        accepted_paths.update(allowed_paths)
    if (
        identities.get("path") not in accepted_paths
        or identities.get("purpose") != purpose
    ):
        raise ReposkopContextError(
            "Reposkop report target or purpose does not match the request"
        )
    _required_sha256(
        identities.get("repository_identity_sha256"),
        label="repository_identity_sha256",
    )
    _required_sha256(
        identities.get("checkout_identity_sha256"),
        label="checkout_identity_sha256",
    )
    observation_sha256 = _verify_reposkop_digest(
        observation,
        field="observation_sha256",
        label="observation_sha256",
    )
    if projection.get("observation_sha256") != observation_sha256:
        raise ReposkopContextError(
            "Reposkop projection is not bound to the observation"
        )
    _verify_reposkop_digest(
        projection,
        field="projection_sha256",
        label="projection_sha256",
    )
    _verify_reposkop_digest(
        report,
        field="report_sha256",
        label="report_sha256",
    )
    return report
''',
)
context = replace_between(
    context,
    "def _receipt_identity",
    "\ndef _receipt_payload",
    '''def _receipt_identity(
    report: dict[str, Any], *, target: Path, purpose: str, executable_sha256: str
) -> dict[str, Any]:
    observation = report["observation"]
    identities = observation["identities"]
    return {
        "schema_version": SCHEMA_VERSION,
        "target_path": str(target),
        "purpose": purpose,
        "reposkop_executable_sha256": executable_sha256,
        "report_sha256": report["report_sha256"],
        "observation_sha256": observation["observation_sha256"],
        "repository_identity_sha256": identities["repository_identity_sha256"],
        "checkout_identity_sha256": identities["checkout_identity_sha256"],
        "projection_sha256": report["projection"]["projection_sha256"],
    }
''',
)
CONTEXT.write_text(context, encoding="utf-8")

tests = TESTS.read_text(encoding="utf-8")
tests = replace_between(
    tests,
    "    def report(",
    "\n    def patches(",
    '''    def report(
        self,
        *,
        effect_authorized: bool = False,
        schema_version: object = 2,
        observation_kind: str = "reposkop_checkout_observation",
        observation_schema_version: int = 2,
        projection_kind: str = "reposkop_coherence_projection",
        projection_schema_version: int = 1,
    ) -> dict[str, object]:
        target = str(self.repo.resolve())
        purpose = "grabowski-repo-state-context"
        observation: dict[str, object] = {
            "kind": observation_kind,
            "schema_version": observation_schema_version,
            "observed_at": "2026-07-29T08:00:00Z",
            "authority": {
                "producer": "reposkop",
                "domain": "local_checkout_identity",
                "claim": "canonical",
            },
            "observation_complete": True,
            "identities": {
                "path": target,
                "purpose": purpose,
                "repository_identity_sha256": "d" * 64,
                "checkout_identity_sha256": "e" * 64,
            },
        }
        observation["observation_sha256"] = context._reposkop_artifact_sha256(
            observation
        )
        projection: dict[str, object] = {
            "kind": projection_kind,
            "schema_version": projection_schema_version,
            "observation_sha256": observation["observation_sha256"],
            "effect_authorized": False,
        }
        projection["projection_sha256"] = context._reposkop_artifact_sha256(
            projection
        )
        report: dict[str, object] = {
            "kind": "reposkop_coherence_report",
            "schema_version": schema_version,
            "generated_at": "2026-07-29T08:00:00Z",
            "authority_boundary": {
                "checkout_identity_truth": "reposkop",
                "checkout_transition_truth": "reposkop",
                "effect_executor": "grabowski",
                "task_truth": "bureau",
                "pull_request_truth": "github",
                "display": "leitstand",
            },
            "effect_authorized": effect_authorized,
            "observation": observation,
            "projection": projection,
        }
        report["report_sha256"] = context._reposkop_artifact_sha256(report)
        return report
''',
)
TESTS.write_text(tests, encoding="utf-8")

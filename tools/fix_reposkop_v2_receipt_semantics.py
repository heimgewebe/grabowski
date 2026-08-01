from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "grabowski_reposkop_context.py"
TESTS = ROOT / "tests" / "test_reposkop_context.py"


def replace_between(text: str, start: str, end: str, replacement: str) -> str:
    left = text.index(start)
    right = text.index(end, left)
    return text[:left] + replacement + text[right:]


source = SOURCE.read_text(encoding="utf-8")
source = replace_between(
    source,
    "def _receipt_identity",
    "\ndef _receipt_payload",
    '''def _semantic_report_identity(report: dict[str, Any]) -> dict[str, Any]:
    observation = dict(report["observation"])
    observation.pop("observed_at", None)
    observation.pop("observation_sha256", None)
    projection = dict(report["projection"])
    projection.pop("observation_sha256", None)
    projection.pop("observation_validation", None)
    projection.pop("projection_sha256", None)
    return {
        "observation": observation,
        "projection": projection,
    }


def _receipt_identity(
    report: dict[str, Any], *, target: Path, purpose: str, executable_sha256: str
) -> dict[str, Any]:
    observation = report["observation"]
    identities = observation["identities"]
    semantic = _semantic_report_identity(report)
    return {
        "schema_version": SCHEMA_VERSION,
        "target_path": str(target),
        "purpose": purpose,
        "reposkop_executable_sha256": executable_sha256,
        "repository_identity_sha256": identities["repository_identity_sha256"],
        "checkout_identity_sha256": identities["checkout_identity_sha256"],
        "semantic_observation_sha256": _sha256_bytes(
            _canonical_json(semantic["observation"])
        ),
        "semantic_projection_sha256": _sha256_bytes(
            _canonical_json(semantic["projection"])
        ),
    }
''',
)
SOURCE.write_text(source, encoding="utf-8")

tests = TESTS.read_text(encoding="utf-8")
old_assertions = '''        self.assertEqual(receipt["report_sha256"], first["report"]["report_sha256"])
        self.assertEqual(
            receipt["observation_sha256"],
            first["report"]["observation"]["observation_sha256"],
        )
        self.assertEqual(
            receipt["repository_identity_sha256"],
            first["report"]["observation"]["identities"][
                "repository_identity_sha256"
            ],
        )
        self.assertEqual(
            receipt["checkout_identity_sha256"],
            first["report"]["observation"]["identities"][
                "checkout_identity_sha256"
            ],
        )
'''
new_assertions = '''        self.assertNotIn("report_sha256", receipt)
        self.assertNotIn("observation_sha256", receipt)
        self.assertNotIn("projection_sha256", receipt)
        self.assertEqual(
            receipt["repository_identity_sha256"],
            first["report"]["observation"]["identities"][
                "repository_identity_sha256"
            ],
        )
        self.assertEqual(
            receipt["checkout_identity_sha256"],
            first["report"]["observation"]["identities"][
                "checkout_identity_sha256"
            ],
        )
        self.assertRegex(receipt["semantic_observation_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(receipt["semantic_projection_sha256"], r"^[0-9a-f]{64}$")
'''
if old_assertions not in tests:
    raise SystemExit("receipt assertion block not found")
tests = tests.replace(old_assertions, new_assertions, 1)
marker = "    def test_records_one_receipt_and_replays_unchanged_semantic_state(self) -> None:\n"
new_test = '''    def test_capture_timestamps_do_not_change_semantic_receipt_key(self) -> None:
        first = self.report()
        second = json.loads(json.dumps(first))
        second["generated_at"] = "2026-07-29T08:01:00Z"
        second["observation"]["observed_at"] = "2026-07-29T08:01:00Z"
        observation = second["observation"]
        observation.pop("observation_sha256", None)
        observation["observation_sha256"] = context._reposkop_artifact_sha256(
            observation
        )
        projection = second["projection"]
        projection["observation_sha256"] = observation["observation_sha256"]
        projection.pop("projection_sha256", None)
        projection["projection_sha256"] = context._reposkop_artifact_sha256(
            projection
        )
        second.pop("report_sha256", None)
        second["report_sha256"] = context._reposkop_artifact_sha256(second)

        executable = {"sha256": "f" * 64}
        first_binding = context._usage_binding(
            first,
            target=self.repo.resolve(),
            purpose="grabowski-repo-state-context",
            executable=executable,
        )
        second_binding = context._usage_binding(
            second,
            target=self.repo.resolve(),
            purpose="grabowski-repo-state-context",
            executable=executable,
        )
        self.assertNotEqual(first["report_sha256"], second["report_sha256"])
        self.assertEqual(
            first_binding["usage_key_sha256"], second_binding["usage_key_sha256"]
        )
        self.assertEqual(first_binding["data"], second_binding["data"])

'''
if marker not in tests:
    raise SystemExit("test insertion marker not found")
tests = tests.replace(marker, new_test + marker, 1)
TESTS.write_text(tests, encoding="utf-8")

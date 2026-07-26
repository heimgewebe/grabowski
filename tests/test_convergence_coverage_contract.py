from pathlib import Path
import json
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "docs" / "proofs" / "convergence-closure-surface-coverage-v1.json"
AUDIT = ROOT / "docs" / "convergence-closure-surface-coverage.md"


class ConvergenceCoverageContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proof = json.loads(PROOF.read_text(encoding="utf-8"))
        self.surfaces = {
            f"{item['surface_kind']}:{item['surface_id']}": item
            for item in self.proof["surfaces"]
        }

    def test_proof_shape_and_source_bindings(self) -> None:
        self.assertEqual(1, self.proof["schema_version"])
        self.assertEqual(
            "grabowski.convergence_closure_surface_coverage",
            self.proof["kind"],
        )
        for field in ("grabowski_commit", "protocol_commit"):
            self.assertRegex(self.proof["source"][field], r"^[0-9a-f]{40}$")
        self.assertEqual(len(self.surfaces), len(self.proof["surfaces"]))
        allowed = set(self.proof["allowed_classifications"])
        self.assertTrue(allowed)
        for item in self.proof["surfaces"]:
            self.assertIn(item["surface_kind"], {"grip", "tool"})
            self.assertIn(item["classification"], allowed)
            self.assertTrue(item["convergence_requirement"])
            self.assertTrue(item["reason"])

    def test_every_named_surface_exists(self) -> None:
        catalog = json.loads(
            (ROOT / self.proof["source"]["capability_catalog"]).read_text(
                encoding="utf-8"
            )
        )
        tool_names = {item["id"] for item in catalog["tools"]}
        grip_source = (ROOT / self.proof["source"]["grip_source"]).read_text(
            encoding="utf-8"
        )
        grip_names = set(
            re.findall(r'^    "([^"]+)": GripSpec\(', grip_source, re.MULTILINE)
        )
        for key, item in self.surfaces.items():
            available = tool_names if item["surface_kind"] == "tool" else grip_names
            self.assertIn(item["surface_id"], available, key)

    def test_name_based_discovery_is_fully_classified(self) -> None:
        pattern = re.compile(self.proof["discovery"]["surface_name_pattern"], re.I)
        catalog = json.loads(
            (ROOT / self.proof["source"]["capability_catalog"]).read_text(
                encoding="utf-8"
            )
        )
        discovered_tools = {
            f"tool:{item['id']}" for item in catalog["tools"] if pattern.search(item["id"])
        }
        grip_source = (ROOT / self.proof["source"]["grip_source"]).read_text(
            encoding="utf-8"
        )
        discovered_grips = {
            f"grip:{name}"
            for name in re.findall(
                r'^    "([^"]+)": GripSpec\(', grip_source, re.MULTILINE
            )
            if pattern.search(name)
        }
        self.assertEqual(set(), (discovered_tools | discovered_grips) - self.surfaces.keys())
        self.assertTrue(
            set(self.proof["discovery"]["required_explicit_surfaces"])
            <= self.surfaces.keys()
        )

    def test_semantic_gaps_are_explicit_and_documented(self) -> None:
        expected = {
            "grip:operator-obligation-close": "semantic_gap",
            "grip:task-closeout-archive": "conditional_semantic_gap",
            "tool:grabowski_agent_workspace_close": "conditional_semantic_gap",
        }
        audit = AUDIT.read_text(encoding="utf-8")
        for key, classification in expected.items():
            self.assertEqual(classification, self.surfaces[key]["classification"])
            self.assertIn(key.split(":", 1)[1], audit)
        self.assertTrue(self.proof["follow_up_required"])

    def test_publication_and_pr_surfaces_are_explicit(self) -> None:
        expected = {
            "tool:grabowski_git": "effect_only",
            "grip:branch-publish": "effect_only",
            "grip:pr-create-or-update": "effect_only",
            "tool:grabowski_bureau_task_publish": "effect_only",
            "tool:grabowski_text_artifact_publish": "preflight_or_evidence",
            "grip:pr-check-readiness": "read_only_observation",
            "tool:grabowski_bureau_task_publish_preview": "read_only_observation",
            "tool:grabowski_github_pr_view": "read_only_observation",
        }
        audit = AUDIT.read_text(encoding="utf-8")
        for key, classification in expected.items():
            self.assertEqual(classification, self.surfaces[key]["classification"])
            self.assertIn(key.split(":", 1)[1], audit)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
from pathlib import Path
import sys
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_mcp as mcp  # noqa: E402


VALID_FRONTMATTER = """---
operational_runbook:
  contract: operational-runbook.v1
  id: infra.windows-tailnet-openssh
  status: active
  title: Windows Tailnet OpenSSH
  applies_to:
    operations: [ssh_diagnostics]
    platforms: [windows]
    components: [tailscale, openssh, windows_firewall]
  symptoms: [ssh_timeout, tcp_22_timeout]
  evidence_refs: [bureau:OPERATOR-INTEGRATION-LOOP-V1-T039]
  verified_against:
    - kind: repository_commit
      value: abcdef
  does_not_establish: [current_state, root_cause, mutation_permission]
---
# Windows Tailnet OpenSSH
"""


def metadata(
    runbook_id: str,
    *,
    operation: str,
    platform: str,
    component: str,
    symptom: str,
    status: str = "active",
) -> dict[str, object]:
    return {
        "contract": "operational-runbook.v1",
        "id": runbook_id,
        "status": status,
        "title": runbook_id,
        "applies_to": {
            "operations": [operation],
            "platforms": [platform],
            "components": [component],
        },
        "symptoms": [symptom],
        "evidence_refs": [f"evidence:{runbook_id}"],
        "verified_against": [{"kind": "fixture", "value": runbook_id}],
        "does_not_establish": ["current_state", "root_cause"],
    }


def candidate(
    runbook_id: str,
    *,
    repo: str = "infra",
    operation: str = "ssh_diagnostics",
    platform: str = "windows",
    component: str = "tailscale",
    symptom: str = "ssh_timeout",
    freshness_state: str = "current",
    status: str = "active",
) -> dict[str, object]:
    return {
        "repo": repo,
        "path": f"runbooks/{runbook_id.split('.')[-1]}.md",
        "metadata": metadata(
            runbook_id,
            operation=operation,
            platform=platform,
            component=component,
            symptom=symptom,
            status=status,
        ),
        "freshness_state": freshness_state,
        "source": {
            "repo": repo,
            "path": f"runbooks/{runbook_id.split('.')[-1]}.md",
            "stem": "fixture-stem",
            "bundle_commit": "a" * 40,
            "manifest_sha256": "b" * 64,
            "content_sha256": "c" * 64,
            "range_ref": {"content_sha256": "c" * 64},
        },
    }


class OperationalGuidanceTests(unittest.TestCase):
    def test_source_registers_read_only_guidance_tool(self) -> None:
        source = (ROOT / "src/grabowski_mcp.py").read_text(encoding="utf-8")
        self.assertIn('name="grabowski_operational_guidance"', source)
        self.assertIn("annotations=READ_ANNOTATIONS", source)

    def test_valid_runbook_frontmatter_contract(self) -> None:
        parsed = mcp._operational_guidance_frontmatter(VALID_FRONTMATTER)
        normalized = mcp._operational_guidance_validate_runbook(parsed)
        self.assertEqual(normalized["contract"], "operational-runbook.v1")
        self.assertEqual(normalized["id"], "infra.windows-tailnet-openssh")
        self.assertEqual(normalized["status"], "active")
        self.assertEqual(normalized["applies_to"]["platforms"], ["windows"])
        self.assertIn("root_cause", normalized["does_not_establish"])

    def test_runbook_contract_rejects_unknown_fields_and_unbounded_shapes(self) -> None:
        parsed = mcp._operational_guidance_frontmatter(VALID_FRONTMATTER)
        parsed["secret_policy"] = "surprise"
        with self.assertRaisesRegex(ValueError, "unsupported operational runbook fields"):
            mcp._operational_guidance_validate_runbook(parsed)
        parsed.pop("secret_policy")
        parsed["verified_against"] = []
        with self.assertRaisesRegex(ValueError, "verified_against"):
            mcp._operational_guidance_validate_runbook(parsed)

    def test_metadata_filter_runs_before_semantic_ranking(self) -> None:
        row = metadata(
            "infra.windows-tailnet-openssh",
            operation="ssh_diagnostics",
            platform="windows",
            component="tailscale",
            symptom="ssh_timeout",
        )
        self.assertIsNotNone(
            mcp._operational_guidance_match_score(
                row,
                operation="ssh_diagnostics",
                platforms=["windows"],
                components=["tailscale"],
                symptoms=["ssh_timeout"],
            )
        )
        self.assertIsNone(
            mcp._operational_guidance_match_score(
                row,
                operation="ssh_diagnostics",
                platforms=["linux"],
                components=["tailscale"],
                symptoms=["ssh_timeout"],
            )
        )

    def test_automatic_mode_requires_systemkatalog_scope(self) -> None:
        with mock.patch.object(mcp, "_require_capability"):
            result = mcp.grabowski_operational_guidance(
                "ssh_diagnostics",
                platforms=["windows"],
                components=["tailscale"],
                symptoms=["ssh_timeout"],
            )
        self.assertEqual(result["status"], "no_match")
        self.assertEqual(result["guidance"], [])
        self.assertIn("system_ref", result["reason"])

    def test_explicit_reference_has_precedence_and_never_falls_back(self) -> None:
        row = candidate("infra.windows-tailnet-openssh")
        with (
            mock.patch.object(mcp, "_require_capability"),
            mock.patch.object(
                mcp,
                "_operational_guidance_discover_repo",
                return_value={"status": "available", "runbooks": [row], "errors": []},
            ) as discover,
            mock.patch.object(
                mcp,
                "_operational_guidance_system_scope",
                side_effect=AssertionError("automatic scope must not run"),
            ),
            mock.patch.object(
                mcp,
                "_operational_guidance_semantic_score",
                return_value=1.0,
            ),
        ):
            result = mcp.grabowski_operational_guidance(
                "ssh_diagnostics",
                platforms=["windows"],
                components=["tailscale"],
                symptoms=["ssh_timeout"],
                system_refs=["grabowski"],
                guidance_refs=[
                    {"repo": "infra", "path": "runbooks/windows-tailnet-openssh.md"}
                ],
            )
        self.assertEqual(result["mode"], "explicit")
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["guidance"][0]["id"], "infra.windows-tailnet-openssh")
        discover.assert_called_once_with(
            "infra", exact_path="runbooks/windows-tailnet-openssh.md"
        )

    def test_invalid_explicit_reference_is_visible_and_has_no_automatic_fallback(self) -> None:
        with (
            mock.patch.object(mcp, "_require_capability"),
            mock.patch.object(
                mcp,
                "_operational_guidance_system_scope",
                side_effect=AssertionError("automatic scope must not run"),
            ),
        ):
            result = mcp.grabowski_operational_guidance(
                "ssh_diagnostics",
                guidance_refs=[{"repo": "infra", "path": "../secret.md"}],
                system_refs=["infra"],
            )
        self.assertEqual(result["mode"], "explicit")
        self.assertEqual(result["status"], "unverifiable")
        self.assertEqual(result["guidance"], [])
        self.assertTrue(result["diagnostics"])

    def test_automatic_scope_comes_from_systemkatalog_then_metadata(self) -> None:
        row = candidate("infra.windows-tailnet-openssh")
        with (
            mock.patch.object(mcp, "_require_capability"),
            mock.patch.object(
                mcp,
                "_operational_guidance_system_scope",
                return_value={
                    "repositories": ["infra"],
                    "bindings": [
                        {
                            "system_ref": "infra",
                            "system_id": "repo:infra",
                            "repo": "infra",
                            "catalog_commit": "d" * 40,
                        }
                    ],
                    "errors": [],
                },
            ),
            mock.patch.object(
                mcp,
                "_operational_guidance_discover_repo",
                return_value={"status": "available", "runbooks": [row], "errors": []},
            ),
            mock.patch.object(
                mcp,
                "_operational_guidance_semantic_score",
                return_value=0.9,
            ),
        ):
            result = mcp.grabowski_operational_guidance(
                "ssh_diagnostics",
                platforms=["windows"],
                components=["tailscale"],
                symptoms=["ssh_timeout"],
                system_refs=["infra"],
            )
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["scope"]["repositories"], ["infra"])
        self.assertEqual(result["scope"]["systems"][0]["system_id"], "repo:infra")

    def test_stale_or_inactive_runbook_is_not_presented_as_current_guidance(self) -> None:
        row = candidate(
            "infra.windows-tailnet-openssh", freshness_state="stale"
        )
        with (
            mock.patch.object(mcp, "_require_capability"),
            mock.patch.object(
                mcp,
                "_operational_guidance_system_scope",
                return_value={"repositories": ["infra"], "bindings": [], "errors": []},
            ),
            mock.patch.object(
                mcp,
                "_operational_guidance_discover_repo",
                return_value={"status": "available", "runbooks": [row], "errors": []},
            ),
        ):
            result = mcp.grabowski_operational_guidance(
                "ssh_diagnostics",
                platforms=["windows"],
                components=["tailscale"],
                symptoms=["ssh_timeout"],
                system_refs=["infra"],
            )
        self.assertEqual(result["status"], "stale")
        self.assertEqual(result["guidance"], [])
        self.assertEqual(result["stale_candidates"][0]["id"], "infra.windows-tailnet-openssh")

    def test_cross_repo_equal_metadata_match_abstains_as_ambiguous(self) -> None:
        first = candidate("infra.tailnet", repo="infra")
        second = candidate("grabowski.tailnet", repo="grabowski")
        first["match_score"] = 20
        second["match_score"] = 20
        with mock.patch.object(
            mcp, "_operational_guidance_semantic_score", return_value=1.0
        ):
            ranked, ambiguous = mcp._operational_guidance_rank(
                [first, second], semantic_query="ssh windows tailscale"
            )
        self.assertTrue(ambiguous)
        self.assertEqual(len(ranked), 2)

    def test_same_repo_repoground_score_breaks_metadata_tie(self) -> None:
        first = candidate("infra.tailnet-a", repo="infra")
        second = candidate("infra.tailnet-b", repo="infra")
        first["match_score"] = 20
        second["match_score"] = 20

        def semantic(row: dict[str, object], *, query: str) -> float:
            del query
            return 0.9 if row["metadata"]["id"] == "infra.tailnet-b" else 0.4  # type: ignore[index]

        with mock.patch.object(
            mcp, "_operational_guidance_semantic_score", side_effect=semantic
        ):
            ranked, ambiguous = mcp._operational_guidance_rank(
                [first, second], semantic_query="ssh windows tailscale"
            )
        self.assertFalse(ambiguous)
        self.assertEqual(ranked[0]["metadata"]["id"], "infra.tailnet-b")  # type: ignore[index]

    def test_no_match_does_not_force_best_guess(self) -> None:
        row = candidate("infra.windows-tailnet-openssh")
        with (
            mock.patch.object(mcp, "_require_capability"),
            mock.patch.object(
                mcp,
                "_operational_guidance_system_scope",
                return_value={"repositories": ["infra"], "bindings": [], "errors": []},
            ),
            mock.patch.object(
                mcp,
                "_operational_guidance_discover_repo",
                return_value={"status": "available", "runbooks": [row], "errors": []},
            ),
        ):
            result = mcp.grabowski_operational_guidance(
                "dns_recovery",
                platforms=["linux"],
                components=["dns"],
                symptoms=["resolution_failure"],
                system_refs=["infra"],
            )
        self.assertEqual(result["status"], "no_match")
        self.assertEqual(result["guidance"], [])

    def test_result_preserves_advisory_non_claims(self) -> None:
        with mock.patch.object(mcp, "_require_capability"):
            result = mcp.grabowski_operational_guidance(
                "ssh_diagnostics", system_refs=[]
            )
        for item in (
            "current_state",
            "root_cause",
            "mutation_permission",
            "retry_permission",
            "task_completion",
            "routing_authority",
            "policy_authority",
            "recovery_authority",
        ):
            self.assertIn(item, result["does_not_establish"])
        self.assertTrue(result["shadow_mode"])

    def test_shadow_goldset_measures_fifteen_operational_classes(self) -> None:
        specs = [
            ("infra.tailscale", "ssh_diagnostics", "windows", "tailscale", "ssh_timeout"),
            ("infra.dns", "dns_recovery", "linux", "dns", "resolution_failure"),
            ("infra.restic", "restore", "linux", "restic", "restore_failure"),
            ("infra.bitwarden", "secret_access", "linux", "bitwarden", "cli_failure"),
            ("infra.systemd", "service_recovery", "linux", "systemd", "unit_failed"),
            ("weltgewebe.deploy", "deployment", "linux", "caddy", "deploy_failure"),
            ("weltgewebe.caddy", "http_recovery", "linux", "caddy", "route_failure"),
            ("grabowski.github", "pr_recovery", "linux", "github", "pr_blocked"),
            ("grabowski.worktree", "worktree_recovery", "linux", "git", "worktree_conflict"),
            ("grabowski.lease", "lease_recovery", "linux", "bureau", "lease_blocked"),
            ("bureau.runtime", "runtime_refresh", "linux", "bureau", "runtime_drift"),
            ("grabowski.transport", "transport_recovery", "linux", "connector", "transport_failure"),
            ("grabowski.browser", "browser_recovery", "linux", "chrome", "browser_failure"),
            ("grabowski.windows", "fleet_diagnostics", "windows", "fleet", "remote_unreachable"),
            ("infra.backup", "backup_recovery", "linux", "restic", "backup_failure"),
        ]
        runbooks = [
            metadata(
                runbook_id,
                operation=operation,
                platform=platform,
                component=component,
                symptom=symptom,
            )
            for runbook_id, operation, platform, component, symptom in specs
        ]
        started = time.perf_counter()
        top1_correct = 0
        top3_found = 0
        false_positive = 0
        wrong_platform = 0
        for runbook_id, operation, platform, component, symptom in specs:
            scored = []
            for row in runbooks:
                score = mcp._operational_guidance_match_score(
                    row,
                    operation=operation,
                    platforms=[platform],
                    components=[component],
                    symptoms=[symptom],
                )
                if score is not None:
                    scored.append((score, row["id"], row))
            scored.sort(key=lambda item: (-item[0], item[1]))
            self.assertTrue(scored)
            top1_correct += int(scored[0][1] == runbook_id)
            top3_found += int(any(item[1] == runbook_id for item in scored[:3]))
            false_positive += max(0, len(scored) - 1)
            wrong_platform += sum(
                1
                for _, _, row in scored
                if platform not in row["applies_to"]["platforms"]  # type: ignore[index]
            )
        negative = [
            mcp._operational_guidance_match_score(
                row,
                operation="unknown_operation",
                platforms=["haiku_os"],
                components=["unknown_component"],
                symptoms=["unknown_symptom"],
            )
            for row in runbooks
        ]
        elapsed_ms = (time.perf_counter() - started) * 1000
        context_bytes = len(
            json.dumps(runbooks, sort_keys=True, ensure_ascii=False).encode("utf-8")
        )
        metrics = {
            "case_count": len(specs),
            "top1_precision": top1_correct / len(specs),
            "top3_recall": top3_found / len(specs),
            "false_positive_count": false_positive,
            "abstention_correct": all(value is None for value in negative),
            "wrong_platform_matches": wrong_platform,
            "context_bytes": context_bytes,
            "elapsed_ms": elapsed_ms,
        }
        self.assertEqual(metrics["case_count"], 15)
        self.assertEqual(metrics["top1_precision"], 1.0)
        self.assertEqual(metrics["top3_recall"], 1.0)
        self.assertEqual(metrics["false_positive_count"], 0)
        self.assertTrue(metrics["abstention_correct"])
        self.assertEqual(metrics["wrong_platform_matches"], 0)
        self.assertGreater(metrics["context_bytes"], 0)
        self.assertGreaterEqual(metrics["elapsed_ms"], 0)


if __name__ == "__main__":
    unittest.main()

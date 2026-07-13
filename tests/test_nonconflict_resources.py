from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types

import grabowski_nonconflict as nonconflict
import grabowski_resources as resources


class NonConflictResourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.database = self.root / "state" / "resources.sqlite3"
        self.database_patch = patch.object(resources, "RESOURCE_DB", self.database)
        self.database_patch.start()
        self.now = int(time.time())

    def tearDown(self) -> None:
        self.database_patch.stop()
        self.temporary.cleanup()

    def scope(
        self,
        name: str,
        *,
        path: str | None = None,
        component: str | None = None,
        runtime_resource: str | None = None,
        process: str | None = None,
        deployment: str | None = None,
        migration: str | None = None,
        generated_artifact: str | None = None,
        shared_gate: str | None = None,
        effects: list[str] | None = None,
    ) -> dict[str, object]:
        worktree = self.root / "worktrees" / name
        selected_effects = effects or ["write"]
        gates = [] if shared_gate is None else [shared_gate]
        for effect, gate in nonconflict.GLOBAL_GATE_BY_EFFECT.items():
            if effect in selected_effects and gate not in gates:
                gates.append(gate)
        return {
            "schema_version": 1,
            "repository": str(self.repo),
            "task_id": f"TASK-{name.upper()}",
            "base_head": "0" * 40,
            "head": ("a" if name == "a" else "b") * 40,
            "branch": f"feat/{name}",
            "worktree": str(worktree),
            "effects": selected_effects,
            "paths": [path or str(self.repo / "src" / f"{name}.py")],
            "components": [] if component is None else [component],
            "runtime_resources": [] if runtime_resource is None else [runtime_resource],
            "processes": [] if process is None else [process],
            "deployments": [] if deployment is None else [deployment],
            "migrations": [] if migration is None else [migration],
            "generated_artifacts": (
                [] if generated_artifact is None else [generated_artifact]
            ),
            "shared_gates": gates,
        }

    def acquire_blocker(self, *, ttl: int = 180) -> dict[str, object]:
        scope = self.scope("a")
        resources.acquire_resources(
            "owner-a",
            [f"repo:{self.repo}"],
            purpose="primary repository work",
            ttl_seconds=ttl,
            metadata={
                "scope_manifest": scope,
                "scope_manifest_complete": True,
            },
        )
        return scope

    def assess(self, requested: dict[str, object] | None = None) -> dict[str, object]:
        requested_scope = requested or self.scope("b")
        return resources.assess_nonconflict(
            blocked_resource_key=f"repo:{self.repo}",
            requesting_owner="owner-b",
            resource_keys=[f"path:{self.repo / 'src' / 'b.py'}"],
            purpose="secondary exact work",
            requested_scope=requested_scope,
            requested_scope_complete=True,
            proof_ttl_seconds=90,
        )

    def test_unattested_blocking_scope_cannot_be_bypassed(self) -> None:
        scope = self.scope("a")
        resources.acquire_resources(
            "owner-a",
            [f"repo:{self.repo}"],
            purpose="unattested broad work",
            ttl_seconds=180,
            metadata={"scope_manifest": scope},
        )
        with self.assertRaisesRegex(
            nonconflict.NonConflictDenied, "did not attest"
        ):
            self.assess()

    def test_unattested_requested_scope_cannot_receive_or_consume_proof(self) -> None:
        self.acquire_blocker()
        with self.assertRaisesRegex(
            nonconflict.NonConflictDenied, "requesting owner did not attest"
        ):
            resources.assess_nonconflict(
                blocked_resource_key=f"repo:{self.repo}",
                requesting_owner="owner-b",
                resource_keys=[f"path:{self.repo / 'src' / 'b.py'}"],
                purpose="unattested requested work",
                requested_scope=self.scope("b"),
                requested_scope_complete=False,
            )
        assessment = self.assess()
        with self.assertRaisesRegex(
            nonconflict.NonConflictDenied, "requesting owner did not attest"
        ):
            resources.acquire_resources(
                "owner-b",
                [f"path:{self.repo / 'src' / 'b.py'}"],
                purpose="secondary exact work",
                ttl_seconds=30,
                metadata={"scope_manifest": self.scope("b")},
                nonconflict_proof=assessment["proof"],
            )

    def test_exact_work_is_blocked_without_proof(self) -> None:
        self.acquire_blocker()
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "owner-b",
                [f"path:{self.repo / 'src' / 'b.py'}"],
                purpose="secondary exact work",
                ttl_seconds=30,
                metadata={"scope_manifest": self.scope("b")},
            )

    def test_disjoint_proof_allows_exact_acquisition_and_preserves_blocker(self) -> None:
        self.acquire_blocker()
        assessment = self.assess()
        result = resources.acquire_resources(
            "owner-b",
            [f"path:{self.repo / 'src' / 'b.py'}"],
            purpose="secondary exact work",
            ttl_seconds=30,
            metadata={
                "scope_manifest": self.scope("b"),
                "scope_manifest_complete": True,
            },
            nonconflict_proof=assessment["proof"],
        )
        self.assertEqual(result["nonconflict_exception"]["decision"], "allow")
        self.assertEqual(
            result["nonconflict_exception"]["proof_sha256"],
            assessment["proof"]["proof_sha256"],
        )
        blocker = resources.inspect_resource(f"repo:{self.repo}")
        self.assertEqual(blocker["owner_id"], "owner-a")
        self.assertEqual(resources.inspect_resource(f"path:{self.repo / 'src' / 'b.py'}")["owner_id"], "owner-b")

    def test_overlap_axes_fail_closed(self) -> None:
        existing = self.scope(
            "a",
            component="shared-component",
            runtime_resource="service:test",
            process="worker:test",
            deployment="prod:test",
            migration="db:test",
            generated_artifact=str(self.repo / "generated" / "api.json"),
            effects=["write", "generate", "process", "deploy", "migrate", "merge"],
        )
        existing["shared_gates"] = [
            "repository-runtime-deploy",
            "repository-migration",
            "repository-merge",
        ]
        cases = {
            "task": {"task_id": existing["task_id"]},
            "branch": {"branch": existing["branch"]},
            "worktree": {"worktree": existing["worktree"]},
            "paths": {"paths": [str(self.repo / "src")]},
            "components": {"components": existing["components"]},
            "runtime_resources": {"runtime_resources": existing["runtime_resources"]},
            "processes": {"processes": existing["processes"], "effects": ["write", "process"]},
            "deployments": {
                "deployments": existing["deployments"],
                "effects": ["write", "deploy"],
                "shared_gates": ["repository-runtime-deploy"],
            },
            "migrations": {
                "migrations": existing["migrations"],
                "effects": ["write", "migrate"],
                "shared_gates": ["repository-migration"],
            },
            "generated_artifacts": {
                "generated_artifacts": [str(self.repo / "generated")],
                "effects": ["write", "generate"],
            },
            "shared_gates": {"shared_gates": ["repository-merge"], "effects": ["write", "merge"]},
        }
        for expected_axis, changes in cases.items():
            with self.subTest(axis=expected_axis):
                requested = self.scope("b")
                requested.update(changes)
                result = nonconflict.evaluate_scope_manifests(existing, requested)
                self.assertEqual(result["decision"], "deny")
                self.assertIn(expected_axis, result["blocker_axes"])

    def test_unknown_wildcard_and_incomplete_scopes_are_rejected(self) -> None:
        wildcard = self.scope("b")
        wildcard["paths"] = [str(self.repo / "src" / "*.py")]
        with self.assertRaisesRegex(ValueError, "wildcard"):
            nonconflict.normalize_scope_manifest(wildcard)
        unknown = self.scope("b")
        unknown["unexpected"] = []
        with self.assertRaisesRegex(ValueError, "keys invalid"):
            nonconflict.normalize_scope_manifest(unknown)
        deploy_without_target = self.scope("b", effects=["write", "deploy"])
        with self.assertRaisesRegex(ValueError, "requires non-empty deployments"):
            nonconflict.normalize_scope_manifest(deploy_without_target)

    def test_proof_is_bound_to_hash_owner_purpose_resources_and_scope(self) -> None:
        self.acquire_blocker()
        assessment = self.assess()
        proof = deepcopy(assessment["proof"])
        proof["requesting_owner"] = "owner-c"
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            resources.acquire_resources(
                "owner-b",
                [f"path:{self.repo / 'src' / 'b.py'}"],
                purpose="secondary exact work",
                ttl_seconds=30,
                metadata={
                    "scope_manifest": self.scope("b"),
                    "scope_manifest_complete": True,
                },
                nonconflict_proof=proof,
            )
        for label, kwargs in (
            ("owner", {"owner_id": "owner-c"}),
            ("purpose", {"purpose": "changed purpose"}),
            ("resource", {"resource_keys": [f"path:{self.repo / 'docs' / 'b.md'}"]}),
            (
                "scope",
                {
                    "metadata": {
                        "scope_manifest": self.scope("c"),
                        "scope_manifest_complete": True,
                    }
                },
            ),
        ):
            with self.subTest(drift=label), self.assertRaises(nonconflict.NonConflictDenied):
                resources.acquire_resources(
                    kwargs.get("owner_id", "owner-b"),
                    kwargs.get("resource_keys", [f"path:{self.repo / 'src' / 'b.py'}"]),
                    purpose=kwargs.get("purpose", "secondary exact work"),
                    ttl_seconds=30,
                    metadata=kwargs.get(
                        "metadata",
                        {
                            "scope_manifest": self.scope("b"),
                            "scope_manifest_complete": True,
                        },
                    ),
                    nonconflict_proof=assessment["proof"],
                )

    def test_public_proof_schema_is_strict(self) -> None:
        self.acquire_blocker()
        original = self.assess()["proof"]

        missing = deepcopy(original)
        missing.pop("does_not_establish")
        missing_core = {key: value for key, value in missing.items() if key != "proof_sha256"}
        missing["proof_sha256"] = nonconflict._sha256(missing_core)
        with self.assertRaisesRegex(ValueError, "proof keys invalid"):
            nonconflict.validate_public_proof(missing)

        incomplete_axes = deepcopy(original)
        incomplete_axes["axis_results"] = incomplete_axes["axis_results"][:-1]
        core = {
            key: value
            for key, value in incomplete_axes.items()
            if key != "proof_sha256"
        }
        incomplete_axes["proof_sha256"] = nonconflict._sha256(core)
        with self.assertRaisesRegex(ValueError, "axis results are incomplete"):
            nonconflict.validate_public_proof(incomplete_axes)

        invalid_duration = deepcopy(original)
        invalid_duration["expires_at_unix"] = invalid_duration["issued_at_unix"] + 1
        core = {
            key: value
            for key, value in invalid_duration.items()
            if key != "proof_sha256"
        }
        invalid_duration["proof_sha256"] = nonconflict._sha256(core)
        with self.assertRaisesRegex(nonconflict.NonConflictDenied, "invalid duration"):
            nonconflict.validate_public_proof(
                invalid_duration, now=invalid_duration["issued_at_unix"]
            )

    def test_boolean_ttls_and_noncanonical_axis_evidence_are_rejected(self) -> None:
        scope_a = self.scope("a")
        scope_b = self.scope("b")
        lease = {
            "resource_key": f"repo:{self.repo}",
            "owner_id": "owner-a",
            "acquired_at_unix": self.now,
            "updated_at_unix": self.now,
            "expires_at_unix": self.now + 180,
            "metadata_sha256": "c" * 64,
        }
        with self.assertRaisesRegex(ValueError, "proof_ttl_seconds"):
            nonconflict.create_nonconflict_proof(
                blocked_lease=lease,
                existing_scope=scope_a,
                requesting_owner="owner-b",
                resource_keys=[f"path:{self.repo / 'src' / 'b.py'}"],
                purpose="secondary exact work",
                requested_scope=scope_b,
                requested_scope_complete=True,
                proof_ttl_seconds=True,
                now=self.now,
            )

        self.acquire_blocker()
        proof = deepcopy(self.assess()["proof"])
        proof["axis_results"][0]["overlap_sha256"] = "d" * 64
        core = {key: value for key, value in proof.items() if key != "proof_sha256"}
        proof["proof_sha256"] = nonconflict._sha256(core)
        with self.assertRaisesRegex(ValueError, "empty overlap"):
            nonconflict.validate_public_proof(proof)

    def test_live_revalidation_binds_axis_evidence_and_integer_ttl(self) -> None:
        self.acquire_blocker()
        proof = self.assess()["proof"]
        requested_scope = self.scope("b")
        with resources._database() as connection:
            live_lease = connection.execute(
                "SELECT * FROM leases WHERE resource_key=?",
                (f"repo:{self.repo}",),
            ).fetchone()
        live_existing_scope = self.scope("a")
        with self.assertRaisesRegex(ValueError, "positive integer"):
            nonconflict.validate_proof_against_live_lease(
                proof,
                live_lease=live_lease,
                live_existing_scope=live_existing_scope,
                requesting_owner="owner-b",
                resource_keys=[f"path:{self.repo / 'src' / 'b.py'}"],
                purpose="secondary exact work",
                requested_scope=requested_scope,
                requested_ttl_seconds=True,
            )
        original = nonconflict.evaluate_scope_manifests(
            live_existing_scope, requested_scope
        )
        drifted = deepcopy(original)
        drifted["axis_results"][0]["overlap_sha256"] = "e" * 64
        with patch.object(
            nonconflict, "evaluate_scope_manifests", return_value=drifted
        ), self.assertRaisesRegex(nonconflict.NonConflictDenied, "axis evidence"):
            nonconflict.validate_proof_against_live_lease(
                proof,
                live_lease=live_lease,
                live_existing_scope=live_existing_scope,
                requesting_owner="owner-b",
                resource_keys=[f"path:{self.repo / 'src' / 'b.py'}"],
                purpose="secondary exact work",
                requested_scope=requested_scope,
                requested_ttl_seconds=30,
            )

    def test_changed_blocking_lease_invalidates_proof(self) -> None:
        self.acquire_blocker()
        assessment = self.assess()
        resources.renew_resources("owner-a", [f"repo:{self.repo}"], ttl_seconds=240)
        with self.assertRaisesRegex(nonconflict.NonConflictDenied, "changed"):
            resources.acquire_resources(
                "owner-b",
                [f"path:{self.repo / 'src' / 'b.py'}"],
                purpose="secondary exact work",
                ttl_seconds=30,
                metadata={
                    "scope_manifest": self.scope("b"),
                    "scope_manifest_complete": True,
                },
                nonconflict_proof=assessment["proof"],
            )

    def test_expired_or_overlong_proof_and_short_blocker_are_denied(self) -> None:
        scope_a = self.scope("a")
        scope_b = self.scope("b")
        lease = {
            "resource_key": f"repo:{self.repo}",
            "owner_id": "owner-a",
            "acquired_at_unix": self.now,
            "updated_at_unix": self.now,
            "expires_at_unix": self.now + 20,
            "metadata_sha256": "c" * 64,
        }
        with self.assertRaisesRegex(nonconflict.NonConflictDenied, "less than 30"):
            nonconflict.create_nonconflict_proof(
                blocked_lease=lease,
                existing_scope=scope_a,
                requesting_owner="owner-b",
                resource_keys=[f"path:{self.repo / 'src' / 'b.py'}"],
                purpose="secondary exact work",
                requested_scope=scope_b,
                requested_scope_complete=True,
                proof_ttl_seconds=30,
                now=self.now,
            )
        lease["expires_at_unix"] = self.now + 180
        proof = nonconflict.create_nonconflict_proof(
            blocked_lease=lease,
            existing_scope=scope_a,
            requesting_owner="owner-b",
            resource_keys=[f"path:{self.repo / 'src' / 'b.py'}"],
            purpose="secondary exact work",
            requested_scope=scope_b,
            requested_scope_complete=True,
            proof_ttl_seconds=30,
            now=self.now,
        )
        with self.assertRaisesRegex(nonconflict.NonConflictDenied, "expired"):
            nonconflict.validate_public_proof(proof, now=self.now + 31)

    def test_scope_and_resource_keys_must_match_in_both_directions(self) -> None:
        self.acquire_blocker()
        requested = self.scope("b")
        requested["components"] = ["component-b"]
        path_key = f"path:{self.repo / 'src' / 'b.py'}"
        with self.assertRaisesRegex(nonconflict.NonConflictDenied, "scope axis components"):
            resources.assess_nonconflict(
                blocked_resource_key=f"repo:{self.repo}",
                requesting_owner="owner-b",
                resource_keys=[path_key],
                purpose="missing component lease",
                requested_scope=requested,
                requested_scope_complete=True,
            )
        with self.assertRaisesRegex(nonconflict.NonConflictDenied, "scope axis components"):
            resources.assess_nonconflict(
                blocked_resource_key=f"repo:{self.repo}",
                requesting_owner="owner-b",
                resource_keys=[path_key, "component:unexpected"],
                purpose="wrong component lease",
                requested_scope=requested,
                requested_scope_complete=True,
            )
        result = resources.assess_nonconflict(
            blocked_resource_key=f"repo:{self.repo}",
            requesting_owner="owner-b",
            resource_keys=[path_key, "component:component-b"],
            purpose="complete exact scope",
            requested_scope=requested,
            requested_scope_complete=True,
        )
        self.assertEqual(result["decision"], "allow")

    def test_paths_outside_repository_are_rejected(self) -> None:
        requested = self.scope("b")
        requested["paths"] = [str(self.root.parent / "foreign.py")]
        with self.assertRaisesRegex(ValueError, "inside repository"):
            nonconflict.normalize_scope_manifest(requested)

    def test_same_owner_and_broad_exception_request_are_denied(self) -> None:
        self.acquire_blocker()
        with self.assertRaisesRegex(nonconflict.NonConflictDenied, "different owner"):
            resources.assess_nonconflict(
                blocked_resource_key=f"repo:{self.repo}",
                requesting_owner="owner-a",
                resource_keys=[f"path:{self.repo / 'src' / 'b.py'}"],
                purpose="same owner",
                requested_scope=self.scope("b"),
                requested_scope_complete=True,
            )
        with self.assertRaisesRegex(nonconflict.NonConflictDenied, "must not include repository"):
            resources.assess_nonconflict(
                blocked_resource_key=f"repo:{self.repo}",
                requesting_owner="owner-b",
                resource_keys=[f"repo:{self.repo}"],
                purpose="broad request",
                requested_scope=self.scope("b"),
                requested_scope_complete=True,
            )

    def test_exact_conflict_cannot_be_bypassed(self) -> None:
        self.acquire_blocker()
        exact_key = f"path:{self.repo / 'src' / 'b.py'}"
        resources.acquire_resources(
            "owner-a",
            [exact_key],
            purpose="primary exact work",
            ttl_seconds=120,
            metadata={
                "scope_manifest": self.scope(
                    "a", path=str(self.repo / "src" / "b.py")
                )
            },
        )
        assessment = self.assess()
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "owner-b",
                [exact_key],
                purpose="secondary exact work",
                ttl_seconds=30,
                metadata={
                    "scope_manifest": self.scope("b"),
                    "scope_manifest_complete": True,
                },
                nonconflict_proof=assessment["proof"],
            )

    def test_exception_lease_is_nonrenewable(self) -> None:
        self.acquire_blocker()
        assessment = self.assess()
        exact_key = f"path:{self.repo / 'src' / 'b.py'}"
        resources.acquire_resources(
            "owner-b",
            [exact_key],
            purpose="secondary exact work",
            ttl_seconds=30,
            metadata={
                "scope_manifest": self.scope("b"),
                "scope_manifest_complete": True,
            },
            nonconflict_proof=assessment["proof"],
        )
        with self.assertRaisesRegex(RuntimeError, "non-renewable"):
            resources.renew_resources("owner-b", [exact_key], ttl_seconds=60)

    def test_release_and_reacquire_race_invalidates_old_proof(self) -> None:
        self.acquire_blocker()
        assessment = self.assess()
        resources.release_resources("owner-a", [f"repo:{self.repo}"])
        replacement = self.scope("c")
        resources.acquire_resources(
            "owner-c",
            [f"repo:{self.repo}"],
            purpose="replacement repository work",
            ttl_seconds=180,
            metadata={
                "scope_manifest": replacement,
                "scope_manifest_complete": True,
            },
        )
        with self.assertRaises(nonconflict.NonConflictDenied):
            resources.acquire_resources(
                "owner-b",
                [f"path:{self.repo / 'src' / 'b.py'}"],
                purpose="secondary exact work",
                ttl_seconds=30,
                metadata={
                    "scope_manifest": self.scope("b"),
                    "scope_manifest_complete": True,
                },
                nonconflict_proof=assessment["proof"],
            )

    def test_new_broad_repository_lease_is_blocked_by_exact_foreign_scope(self) -> None:
        exact_key = f"path:{self.repo / 'src' / 'b.py'}"
        resources.acquire_resources(
            "owner-b",
            [exact_key],
            purpose="exact work first",
            ttl_seconds=60,
            metadata={"scope_manifest": self.scope("b")},
        )
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "owner-a",
                [f"repo:{self.repo}"],
                purpose="broad work second",
                ttl_seconds=60,
                metadata={"scope_manifest": self.scope("a")},
            )

    def test_main_checkout_blocker_can_allow_disjoint_sibling_worktree(self) -> None:
        existing = self.scope("a")
        existing["worktree"] = str(self.repo)
        resources.acquire_resources(
            "owner-a",
            [f"repo:{self.repo}"],
            purpose="primary work in main checkout",
            ttl_seconds=180,
            metadata={
                "scope_manifest": existing,
                "scope_manifest_complete": True,
            },
        )
        assessment = self.assess()
        self.assertEqual(assessment["decision"], "allow")
        result = resources.acquire_resources(
            "owner-b",
            [f"path:{self.repo / 'src' / 'b.py'}"],
            purpose="secondary exact work",
            ttl_seconds=30,
            metadata={
                "scope_manifest": self.scope("b"),
                "scope_manifest_complete": True,
            },
            nonconflict_proof=assessment["proof"],
        )
        self.assertEqual(result["nonconflict_exception"]["decision"], "allow")
        blocker = resources.inspect_resource(f"repo:{self.repo}")
        self.assertEqual(blocker["owner_id"], "owner-a")

    def test_nested_worktree_roots_conflict(self) -> None:
        existing = self.scope("a")
        requested = self.scope("b")
        requested["worktree"] = str(Path(existing["worktree"]) / "nested")
        result = nonconflict.evaluate_scope_manifests(existing, requested)
        self.assertEqual(result["decision"], "deny")
        self.assertIn("worktree", result["blocker_axes"])

    def test_cross_axis_paths_conflict(self) -> None:
        existing = self.scope(
            "a",
            path=str(self.repo / "src" / "a.py"),
            generated_artifact=str(self.repo / "generated" / "a.json"),
            effects=["write", "generate"],
        )
        requested = self.scope(
            "b",
            path=str(self.repo / "docs" / "b.md"),
            generated_artifact=str(self.repo / "src"),
            effects=["write", "generate"],
        )
        cross = nonconflict.evaluate_scope_manifests(existing, requested)
        self.assertEqual(cross["decision"], "deny")
        self.assertIn("path_generated_cross", cross["blocker_axes"])

    def test_different_baselines_and_noncanonical_paths_fail_closed(self) -> None:
        existing = self.scope("a")
        requested = self.scope("b")
        requested["base_head"] = "f" * 40
        result = nonconflict.evaluate_scope_manifests(existing, requested)
        self.assertEqual(result["decision"], "deny")
        self.assertIn("base_head", result["blocker_axes"])

        invalid_worktree = self.scope("b")
        invalid_worktree["worktree"] = str(self.repo.parent)
        with self.assertRaisesRegex(ValueError, "distinct sibling path"):
            nonconflict.normalize_scope_manifest(invalid_worktree)
        nested_worktree = self.scope("b")
        nested_worktree["worktree"] = str(self.repo / ".worktrees" / "b")
        with self.assertRaisesRegex(ValueError, "distinct sibling path"):
            nonconflict.normalize_scope_manifest(nested_worktree)

        self.acquire_blocker()
        alias = self.root / "repo-alias"
        alias.symlink_to(self.repo, target_is_directory=True)
        requested = self.scope("b", path=str(alias / "src" / "b.py"))
        with self.assertRaisesRegex(
            nonconflict.NonConflictDenied, "canonical paths"
        ):
            resources.assess_nonconflict(
                blocked_resource_key=f"repo:{self.repo}",
                requesting_owner="owner-b",
                resource_keys=[f"path:{alias / 'src' / 'b.py'}"],
                purpose="symlink alias attempt",
                requested_scope=requested,
                requested_scope_complete=True,
            )

    def test_resource_keys_must_match_scope_exactly(self) -> None:
        scope = self.scope("b")
        with self.assertRaisesRegex(
            nonconflict.NonConflictDenied, "scope filesystem entries differ"
        ):
            resources.acquire_resources(
                "owner-b",
                [f"path:{self.repo / 'src'}"],
                purpose="broader key than declaration",
                ttl_seconds=60,
                metadata={"scope_manifest": scope},
            )
        runtime_scope = self.scope("b", runtime_resource="service:test")
        result = resources.acquire_resources(
            "owner-b",
            [f"path:{self.repo / 'src' / 'b.py'}", "service:test"],
            purpose="bound runtime resource",
            ttl_seconds=60,
            metadata={"scope_manifest": runtime_scope},
        )
        self.assertIn("service:test", [item["resource_key"] for item in result["leases"]])

    def test_generated_artifacts_use_path_resources_without_aliases(self) -> None:
        self.acquire_blocker()
        generated = str(self.repo / "generated" / "api.json")
        requested = self.scope(
            "b", generated_artifact=generated, effects=["write", "generate"]
        )
        keys = [f"path:{self.repo / 'src' / 'b.py'}", f"path:{generated}"]
        result = resources.assess_nonconflict(
            blocked_resource_key=f"repo:{self.repo}",
            requesting_owner="owner-b",
            resource_keys=keys,
            purpose="generate disjoint artifact",
            requested_scope=requested,
            requested_scope_complete=True,
        )
        self.assertEqual(result["decision"], "allow")
        with self.assertRaisesRegex(ValueError, "resource kind"):
            resources.normalize_resource_key(f"artifact:{generated}")

    def test_mixed_bureau_and_non_bureau_keys_are_rejected(self) -> None:
        with patch.object(
            resources.bureau_leases,
            "bureau_resource_keys",
            return_value=["path:/home/alex/repos/bureau/registry/tasks/T.json"],
        ), patch.object(
            resources.bureau_leases, "enforce_bureau_lease_contract", return_value=None
        ):
            with self.assertRaisesRegex(ValueError, "must be acquired separately"):
                resources.acquire_resources(
                    "owner-a",
                    [
                        "path:/home/alex/repos/bureau/registry/tasks/T.json",
                        f"path:{self.repo / 'src' / 'a.py'}",
                    ],
                    purpose="mixed contract attempt",
                    ttl_seconds=60,
                )

    def test_emergency_recovery_repository_lease_cannot_be_bypassed(self) -> None:
        resources.acquire_resources(
            "owner-a",
            [f"repo:{self.repo}"],
            purpose="emergency recovery",
            ttl_seconds=180,
            metadata={
                "scope_manifest": self.scope("a"),
                "scope_manifest_complete": True,
                "lease_mode": "emergency-recovery",
            },
        )
        with self.assertRaisesRegex(
            nonconflict.NonConflictDenied, "cannot be bypassed"
        ):
            self.assess()

    def test_global_effects_require_canonical_shared_gates(self) -> None:
        cases = [
            (
                "deploy",
                "repository-runtime-deploy",
                {"deployment": "prod:test"},
            ),
            (
                "migrate",
                "repository-migration",
                {"migration": "db:test"},
            ),
            ("merge", "repository-merge", {}),
            ("worktree-admin", "repository-worktree-admin", {}),
        ]
        for effect, gate, kwargs in cases:
            with self.subTest(effect=effect):
                scope = self.scope(
                    "b", effects=["write", effect], **kwargs
                )
                scope["shared_gates"] = []
                with self.assertRaisesRegex(ValueError, gate):
                    nonconflict.normalize_scope_manifest(scope)

    def test_prefix_sibling_path_does_not_conflict(self) -> None:
        sibling = Path(str(self.repo) + "-other")
        sibling.mkdir()
        resources.acquire_resources(
            "owner-b",
            [f"path:{sibling / 'file.py'}"],
            purpose="sibling path",
            ttl_seconds=60,
            metadata={"scope_manifest": {**self.scope("b"), "repository": str(sibling), "paths": [str(sibling / 'file.py')]}},
        )
        result = resources.acquire_resources(
            "owner-a",
            [f"repo:{self.repo}"],
            purpose="primary repository work",
            ttl_seconds=60,
            metadata={"scope_manifest": self.scope("a")},
        )
        self.assertEqual(result["leases"][0]["owner_id"], "owner-a")


if __name__ == "__main__":
    unittest.main()

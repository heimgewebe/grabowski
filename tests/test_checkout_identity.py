from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
import tempfile
import threading
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


import grabowski_checkout_identity as identity
import grabowski_checkouts as checkouts
import grabowski_worktree_ensure as worktree_ensure


OLD_HEAD = "1" * 40
NEW_HEAD = "2" * 40
OTHER_HEAD = "3" * 40
RECEIPT_SHA256 = "a" * 64


class CheckoutIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.common_dir = self.repo / ".git"
        self.worktrees = self.root / "worktrees"
        self.checkout = self.worktrees / "topic"
        self.checkout_db = self.root / "state" / "checkouts.sqlite3"
        self.now = 1_800_000_000
        self.repo.mkdir()
        self.common_dir.mkdir()
        self.worktrees.mkdir()
        self.patches = [
            patch.object(checkouts, "CHECKOUT_DB", self.checkout_db),
            patch.object(checkouts, "_git_common_dir", return_value=self.common_dir),
            patch.object(identity, "_now", return_value=self.now),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def _checkout_key(self, path: Path | None = None) -> str:
        return checkouts._checkout_key(
            self.common_dir.resolve(), (path or self.checkout).resolve(strict=False)
        )

    def _inputs(
        self,
        *,
        path: Path | None = None,
        owner: str = "owner-new",
        purpose: str = "new checkout identity",
        source_kind: str = "bureau_task",
        source_id: str = "STORAGE-LIFECYCLE-V1-T012",
        artifact_class: str = "implementation_worktree",
        head: str = NEW_HEAD,
        branch: str = "new-topic",
        idempotency_key: str = "identity-case",
    ) -> dict[str, object]:
        return {
            "repo": str(self.repo),
            "target_path": str((path or self.checkout).resolve(strict=False)),
            "branch": branch,
            "base_head": head,
            "lease_owner_id": owner,
            "purpose": purpose,
            "source_kind": source_kind,
            "source_id": source_id,
            "artifact_class": artifact_class,
            "retention_until_unix": self.now + 3600,
            "idempotency_key": idempotency_key,
        }

    def _seed_prior(
        self,
        *,
        path: Path | None = None,
        phase: str = "active",
        active_retention: bool = True,
        archive: bool = False,
        cleaned_archive: bool = False,
        owner: str = "owner-old",
        purpose: str = "old checkout identity",
        source_kind: str = "bureau_task",
        source_id: str = "OLD-TASK",
        artifact_class: str = "implementation_worktree",
        head: str = OLD_HEAD,
        branch: str | None = "old-topic",
    ) -> dict[str, object]:
        checkout_path = (path or self.checkout).resolve(strict=False)
        checkout_key = self._checkout_key(checkout_path)
        retention_until = self.now + 1800 if active_retention else self.now - 1800
        created = self.now - 3600
        terminal_at = None if phase == "active" else self.now - 2400
        archived_at = self.now - 1800 if phase == "archived" else None
        archive_id = f"20260805T000000Z-{checkout_key[:12]}" if archive else None
        recovery_refs = [
            {
                "role": "head",
                "ref": f"refs/grabowski/checkouts/{checkout_key[:16]}/head",
                "target": head,
            }
        ]
        with checkouts._database() as connection:
            connection.execute(
                """
                INSERT INTO lifecycle_bindings(
                    checkout_key, repo_common_dir, repo_path, checkout_path,
                    owner_id, purpose, source_kind, source_id, artifact_class,
                    phase, retention_until_unix, expected_head, expected_branch,
                    created_at_unix, updated_at_unix, terminal_at_unix,
                    archived_at_unix
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    checkout_key,
                    str(self.common_dir.resolve()),
                    str(self.repo.resolve()),
                    str(checkout_path),
                    owner,
                    purpose,
                    source_kind,
                    source_id,
                    artifact_class,
                    phase,
                    retention_until,
                    head,
                    branch,
                    created,
                    created,
                    terminal_at,
                    archived_at,
                ),
            )
            connection.execute(
                """
                INSERT INTO retention(
                    checkout_key, repo_common_dir, repo_path, checkout_path,
                    owner_id, purpose, retention_until_unix, expected_head,
                    expected_branch, created_at_unix, updated_at_unix
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    checkout_key,
                    str(self.common_dir.resolve()),
                    str(self.repo.resolve()),
                    str(checkout_path),
                    owner,
                    purpose,
                    retention_until,
                    head,
                    branch,
                    created,
                    created,
                ),
            )
            if archive_id is not None:
                connection.execute(
                    """
                    INSERT INTO archives(
                        archive_id, checkout_key, repo_common_dir, repo_path,
                        checkout_path, head, branch, owner_id, purpose,
                        retention_until_unix, recovery_refs_json, manifest_path,
                        created_at_unix, cleaned_at_unix, cleanup_plan_id
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        archive_id,
                        checkout_key,
                        str(self.common_dir.resolve()),
                        str(self.repo.resolve()),
                        str(checkout_path),
                        head,
                        branch,
                        owner,
                        purpose,
                        retention_until,
                        json.dumps(recovery_refs, sort_keys=True),
                        str(self.root / "archives" / archive_id / "manifest.json"),
                        created,
                        self.now - 1 if cleaned_archive else None,
                        "cleanup-plan" if cleaned_archive else None,
                    ),
                )
            connection.commit()
        return {
            "checkout_key": checkout_key,
            "archive_id": archive_id,
            "owner_id": owner,
            "purpose": purpose,
            "source_kind": source_kind,
            "source_id": source_id,
            "artifact_class": artifact_class,
            "head": head,
            "branch": branch,
            "recovery_refs": recovery_refs,
        }

    def _archive_existing_prior(
        self,
        prior: dict[str, object],
        *,
        head: str = NEW_HEAD,
        branch: str = "archived-topic",
        owner: str | None = None,
        purpose: str | None = None,
    ) -> dict[str, object]:
        checkout_key = str(prior["checkout_key"])
        archive_owner = owner or str(prior["owner_id"])
        archive_purpose = purpose or str(prior["purpose"])
        archive_id = f"20260806T000000Z-{checkout_key[:12]}"
        recovery_refs = [
            {
                "role": "head",
                "ref": f"refs/grabowski/checkouts/{checkout_key[:16]}/advanced-head",
                "target": head,
            }
        ]
        with checkouts._database() as connection:
            connection.execute(
                """
                UPDATE lifecycle_bindings
                SET owner_id=?, purpose=?, phase='archived',
                    retention_until_unix=?, expected_head=?, expected_branch=?,
                    updated_at_unix=?, terminal_at_unix=?, archived_at_unix=?
                WHERE checkout_key=?
                """,
                (
                    archive_owner,
                    archive_purpose,
                    self.now + 1800,
                    head,
                    branch,
                    self.now,
                    self.now,
                    self.now,
                    checkout_key,
                ),
            )
            connection.execute(
                """
                UPDATE retention
                SET owner_id=?, purpose=?, retention_until_unix=?,
                    expected_head=?, expected_branch=?, updated_at_unix=?
                WHERE checkout_key=?
                """,
                (
                    archive_owner,
                    archive_purpose,
                    self.now + 1800,
                    head,
                    branch,
                    self.now,
                    checkout_key,
                ),
            )
            connection.execute(
                """
                INSERT INTO archives(
                    archive_id, checkout_key, repo_common_dir, repo_path,
                    checkout_path, head, branch, owner_id, purpose,
                    retention_until_unix, recovery_refs_json, manifest_path,
                    created_at_unix, cleaned_at_unix, cleanup_plan_id
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                """,
                (
                    archive_id,
                    checkout_key,
                    str(self.common_dir.resolve()),
                    str(self.repo.resolve()),
                    str(self.checkout.resolve(strict=False)),
                    head,
                    branch,
                    archive_owner,
                    archive_purpose,
                    self.now + 1800,
                    json.dumps(recovery_refs, sort_keys=True),
                    str(self.root / "archives" / archive_id / "manifest.json"),
                    self.now,
                ),
            )
            connection.commit()
        return {
            **prior,
            "archive_id": archive_id,
            "owner_id": archive_owner,
            "purpose": archive_purpose,
            "head": head,
            "branch": branch,
            "recovery_refs": recovery_refs,
        }

    def _supersession(
        self,
        prior: dict[str, object],
        inputs: dict[str, object],
        **overrides: object,
    ) -> dict[str, object]:
        value: dict[str, object] = {
            "schema_version": 1,
            "expected_checkout_key": prior["checkout_key"],
            "expected_generation_id": None,
            "expected_archive_id": prior["archive_id"],
            "expected_owner_id": prior["owner_id"],
            "expected_head": prior["head"],
            "expected_branch": prior["branch"],
            "authorized_by_owner_id": prior["owner_id"],
            "handoff_receipt_sha256": RECEIPT_SHA256,
            "new_owner_id": inputs["lease_owner_id"],
            "reason": "owner-approved exact path handoff",
        }
        value.update(overrides)
        return value

    def _fetchone(self, query: str, parameters: tuple[object, ...]) -> dict[str, object] | None:
        with checkouts._database() as connection:
            identity._ensure_schema(connection)
            row = connection.execute(query, parameters).fetchone()
        return None if row is None else dict(row)

    def test_open_archive_reuse_requires_explicit_supersession(self) -> None:
        self._seed_prior(phase="archived", active_retention=False, archive=True)
        with self.assertRaisesRegex(identity.CheckoutIdentityConflict, "open_archive"):
            identity.prepare(self._inputs())

    def test_active_retention_reuse_requires_explicit_supersession(self) -> None:
        self._seed_prior(phase="active", active_retention=True, archive=False)
        with self.assertRaisesRegex(identity.CheckoutIdentityConflict, "active_retention"):
            identity.prepare(self._inputs())

    def test_identical_active_identity_is_idempotent_replay(self) -> None:
        prior = self._seed_prior(phase="active", active_retention=True)
        inputs = self._inputs(
            owner=str(prior["owner_id"]),
            purpose=str(prior["purpose"]),
            source_kind=str(prior["source_kind"]),
            source_id=str(prior["source_id"]),
            artifact_class=str(prior["artifact_class"]),
            head=str(prior["head"]),
            branch=str(prior["branch"]),
            idempotency_key="exact-replay",
        )
        first = identity.prepare(inputs)
        second = identity.prepare(inputs)
        self.assertEqual("replay", first["action"])
        self.assertEqual("active", first["state"])
        self.assertEqual(first["intent_key"], second["intent_key"])
        self.assertEqual("active", identity.finalize(first)["state"])

    def test_authorized_supersession_is_atomic_and_preserves_archive_evidence(self) -> None:
        prior = self._seed_prior(
            phase="archived", active_retention=False, archive=True
        )
        inputs = self._inputs(idempotency_key="authorized-handoff")
        inputs["identity_supersession"] = self._supersession(prior, inputs)
        reservation = identity.prepare(inputs)
        self.assertEqual("supersession", reservation["action"])
        self.assertEqual("reserved", reservation["state"])

        lifecycle = self._fetchone(
            "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
            (prior["checkout_key"],),
        )
        self.assertIsNotNone(lifecycle)
        assert lifecycle is not None
        self.assertEqual(inputs["lease_owner_id"], lifecycle["owner_id"])
        self.assertEqual(inputs["branch"], lifecycle["expected_branch"])

        archive = self._fetchone(
            "SELECT * FROM archives WHERE archive_id=?", (prior["archive_id"],)
        )
        self.assertIsNotNone(archive)
        assert archive is not None
        self.assertEqual(
            json.dumps(prior["recovery_refs"], sort_keys=True),
            archive["recovery_refs_json"],
        )
        superseded = self._fetchone(
            "SELECT * FROM checkout_identity_archive_supersessions WHERE archive_id=?",
            (prior["archive_id"],),
        )
        self.assertIsNotNone(superseded)
        self.assertIsNone(
            checkouts._latest_archive_for_key(str(prior["checkout_key"]))
        )
        self.assertNotIn(
            prior["checkout_key"],
            checkouts._latest_archives([str(prior["checkout_key"])]),
        )
        archived_evidence = checkouts._load_archive(str(prior["archive_id"]))
        self.assertEqual(prior["recovery_refs"], archived_evidence["recovery_refs"])
        self.assertIsNone(archived_evidence["cleaned_at_unix"])
        self.assertEqual("active", identity.finalize(reservation)["state"])

        generations = []
        with checkouts._database() as connection:
            generations = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM checkout_identity_generations WHERE checkout_key=? ORDER BY created_at_unix, generation_id",
                    (prior["checkout_key"],),
                ).fetchall()
            ]
        self.assertEqual({"active", "superseded"}, {row["state"] for row in generations})

    def test_archived_identity_evolution_reconciles_generation_lineage_before_handoff(self) -> None:
        prior = self._seed_prior(
            phase="active", active_retention=True, archive=False
        )
        prior_inputs = self._inputs(
            owner=str(prior["owner_id"]),
            purpose=str(prior["purpose"]),
            source_kind=str(prior["source_kind"]),
            source_id=str(prior["source_id"]),
            artifact_class=str(prior["artifact_class"]),
            head=str(prior["head"]),
            branch=str(prior["branch"]),
            idempotency_key="seed-old-generation",
        )
        seeded = identity.prepare(prior_inputs)
        self.assertEqual("replay", seeded["action"])
        old_generation_id = str(seeded["generation_id"])

        archived = self._archive_existing_prior(
            prior, head=NEW_HEAD, branch="archived-topic"
        )
        inputs = self._inputs(
            head=OTHER_HEAD,
            branch="replacement-topic",
            idempotency_key="handoff-after-archive-evolution",
        )
        inputs["identity_supersession"] = self._supersession(archived, inputs)
        reservation = identity.prepare(inputs)
        self.assertEqual("supersession", reservation["action"])
        self.assertEqual("reserved", reservation["state"])

        old_generation = self._fetchone(
            "SELECT * FROM checkout_identity_generations WHERE generation_id=?",
            (old_generation_id,),
        )
        baseline_generation = self._fetchone(
            "SELECT * FROM checkout_identity_generations WHERE generation_id=?",
            (reservation["prior_generation_id"],),
        )
        new_generation = self._fetchone(
            "SELECT * FROM checkout_identity_generations WHERE generation_id=?",
            (reservation["generation_id"],),
        )
        self.assertIsNotNone(old_generation)
        self.assertIsNotNone(baseline_generation)
        self.assertIsNotNone(new_generation)
        assert old_generation is not None
        assert baseline_generation is not None
        assert new_generation is not None
        old_identity = json.loads(str(old_generation["identity_json"]))
        baseline_identity = json.loads(str(baseline_generation["identity_json"]))
        self.assertEqual(OLD_HEAD, old_identity["expected_head"])
        self.assertEqual("old-topic", old_identity["expected_branch"])
        self.assertEqual(NEW_HEAD, baseline_identity["expected_head"])
        self.assertEqual("archived-topic", baseline_identity["expected_branch"])
        self.assertEqual("superseded", old_generation["state"])
        self.assertEqual(
            baseline_generation["generation_id"],
            old_generation["superseded_by_generation_id"],
        )
        self.assertEqual(
            old_generation_id, baseline_generation["predecessor_generation_id"]
        )
        self.assertEqual("superseded", baseline_generation["state"])
        self.assertEqual(
            reservation["generation_id"],
            baseline_generation["superseded_by_generation_id"],
        )
        self.assertEqual(
            baseline_generation["generation_id"],
            new_generation["predecessor_generation_id"],
        )
        archive_supersession = self._fetchone(
            "SELECT * FROM checkout_identity_archive_supersessions WHERE archive_id=?",
            (archived["archive_id"],),
        )
        self.assertIsNotNone(archive_supersession)
        assert archive_supersession is not None
        self.assertEqual(
            baseline_generation["generation_id"],
            archive_supersession["prior_generation_id"],
        )

    def test_archived_identity_reconciliation_rolls_back_without_handoff_authority(self) -> None:
        prior = self._seed_prior(
            phase="active", active_retention=True, archive=False
        )
        prior_inputs = self._inputs(
            owner=str(prior["owner_id"]),
            purpose=str(prior["purpose"]),
            source_kind=str(prior["source_kind"]),
            source_id=str(prior["source_id"]),
            artifact_class=str(prior["artifact_class"]),
            head=str(prior["head"]),
            branch=str(prior["branch"]),
            idempotency_key="seed-before-unauthorized-handoff",
        )
        seeded = identity.prepare(prior_inputs)
        archived = self._archive_existing_prior(
            prior, head=NEW_HEAD, branch="archived-topic"
        )
        unauthorized = self._inputs(
            head=OTHER_HEAD,
            branch="replacement-topic",
            idempotency_key="missing-handoff-authority",
        )
        with self.assertRaisesRegex(
            identity.CheckoutIdentityConflict,
            "explicit owner-bound supersession is required",
        ):
            identity.prepare(unauthorized)

        current = self._fetchone(
            """
            SELECT * FROM checkout_identity_generations
            WHERE checkout_key=? AND state IN ('reserved', 'active', 'blocking')
            """,
            (prior["checkout_key"],),
        )
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(seeded["generation_id"], current["generation_id"])
        self.assertEqual("active", current["state"])
        self.assertIsNone(current["superseded_by_generation_id"])
        generation_count = self._fetchone(
            "SELECT count(*) AS total FROM checkout_identity_generations WHERE checkout_key=?",
            (prior["checkout_key"],),
        )
        self.assertIsNotNone(generation_count)
        assert generation_count is not None
        self.assertEqual(1, generation_count["total"])
        lifecycle = self._fetchone(
            "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
            (prior["checkout_key"],),
        )
        self.assertIsNotNone(lifecycle)
        assert lifecycle is not None
        self.assertEqual("archived", lifecycle["phase"])
        self.assertEqual(archived["head"], lifecycle["expected_head"])
        self.assertEqual(archived["branch"], lifecycle["expected_branch"])

    def test_archived_identity_reconciliation_rejects_immutable_owner_drift(self) -> None:
        prior = self._seed_prior(
            phase="active", active_retention=True, archive=False
        )
        prior_inputs = self._inputs(
            owner=str(prior["owner_id"]),
            purpose=str(prior["purpose"]),
            source_kind=str(prior["source_kind"]),
            source_id=str(prior["source_id"]),
            artifact_class=str(prior["artifact_class"]),
            head=str(prior["head"]),
            branch=str(prior["branch"]),
            idempotency_key="seed-before-owner-drift",
        )
        seeded = identity.prepare(prior_inputs)
        self._archive_existing_prior(
            prior,
            head=NEW_HEAD,
            branch="archived-topic",
            owner="owner-tampered",
        )
        tampered_inputs = self._inputs(
            owner="owner-tampered",
            purpose=str(prior["purpose"]),
            source_kind=str(prior["source_kind"]),
            source_id=str(prior["source_id"]),
            artifact_class=str(prior["artifact_class"]),
            head=NEW_HEAD,
            branch="archived-topic",
            idempotency_key="tampered-archive-replay",
        )
        with self.assertRaisesRegex(
            identity.CheckoutIdentityConflict,
            "identity ledger and protected checkout evidence disagree",
        ):
            identity.prepare(tampered_inputs)
        current = self._fetchone(
            """
            SELECT * FROM checkout_identity_generations
            WHERE checkout_key=? AND state IN ('reserved', 'active', 'blocking')
            """,
            (prior["checkout_key"],),
        )
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(seeded["generation_id"], current["generation_id"])
        self.assertEqual("active", current["state"])

    def test_supersession_rejects_wrong_prior_bindings(self) -> None:
        prior = self._seed_prior(
            phase="archived", active_retention=False, archive=True
        )
        cases = {
            "owner": {
                "expected_owner_id": "owner-wrong",
                "authorized_by_owner_id": "owner-wrong",
            },
            "head": {"expected_head": OTHER_HEAD},
            "branch": {"expected_branch": "wrong-branch"},
            "archive": {"expected_archive_id": "archive-wrong"},
            "generation": {"expected_generation_id": "generation-wrong"},
        }
        for index, (name, overrides) in enumerate(cases.items()):
            with self.subTest(name=name):
                inputs = self._inputs(idempotency_key=f"wrong-binding-{index}")
                inputs["identity_supersession"] = self._supersession(
                    prior, inputs, **overrides
                )
                with self.assertRaises(identity.CheckoutIdentityConflict):
                    identity.prepare(inputs)

    def test_concurrent_supersession_allows_only_one_generation(self) -> None:
        prior = self._seed_prior(
            phase="archived", active_retention=False, archive=True
        )
        barrier = threading.Barrier(2)

        def attempt(index: int) -> tuple[str, str]:
            inputs = self._inputs(
                owner=f"owner-new-{index}",
                branch=f"new-topic-{index}",
                source_id=f"NEW-TASK-{index}",
                idempotency_key=f"parallel-{index}",
            )
            inputs["identity_supersession"] = self._supersession(prior, inputs)
            barrier.wait()
            try:
                return "ok", str(identity.prepare(inputs)["generation_id"])
            except identity.CheckoutIdentityConflict as exc:
                return "blocked", str(exc)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(attempt, (1, 2)))
        self.assertEqual(1, sum(result[0] == "ok" for result in results))
        self.assertEqual(1, sum(result[0] == "blocked" for result in results))
        current = self._fetchone(
            """
            SELECT * FROM checkout_identity_generations
            WHERE checkout_key=? AND state IN ('reserved', 'active', 'blocking')
            """,
            (prior["checkout_key"],),
        )
        self.assertIsNotNone(current)

    def test_interrupted_supersession_blocks_new_attempt_and_abort_restores_preimage(self) -> None:
        prior = self._seed_prior(
            phase="archived", active_retention=False, archive=True
        )
        inputs = self._inputs(idempotency_key="interrupted")
        inputs["identity_supersession"] = self._supersession(prior, inputs)
        reservation = identity.prepare(inputs)
        blocked = identity.mark_blocking(reservation, reason="simulated crash")
        self.assertEqual("blocking", blocked["state"])

        other = self._inputs(
            owner="owner-other",
            branch="other-topic",
            source_id="OTHER-TASK",
            idempotency_key="after-crash",
        )
        other["identity_supersession"] = self._supersession(prior, other)
        with self.assertRaisesRegex(identity.CheckoutIdentityConflict, "unfinished"):
            identity.prepare(other)

        aborted = identity.abort(blocked, reason="verified no Git effect")
        self.assertEqual("aborted", aborted["state"])
        lifecycle = self._fetchone(
            "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
            (prior["checkout_key"],),
        )
        self.assertIsNotNone(lifecycle)
        assert lifecycle is not None
        self.assertEqual(prior["owner_id"], lifecycle["owner_id"])
        self.assertEqual(prior["branch"], lifecycle["expected_branch"])
        self.assertIsNone(
            self._fetchone(
                "SELECT * FROM checkout_identity_archive_supersessions WHERE archive_id=?",
                (prior["archive_id"],),
            )
        )
        latest_archive = checkouts._latest_archive_for_key(
            str(prior["checkout_key"])
        )
        self.assertIsNotNone(latest_archive)
        assert latest_archive is not None
        self.assertEqual(prior["archive_id"], latest_archive["archive_id"])

    def test_worktree_reservation_invokes_identity_guard_before_git_effect(self) -> None:
        prior = self._seed_prior(
            phase="archived", active_retention=False, archive=True
        )
        inputs = self._inputs(idempotency_key="worktree-guard")

        with self.assertRaisesRegex(identity.CheckoutIdentityConflict, "open_archive"):
            worktree_ensure._reserve_input_lifecycle(inputs)

        lifecycle = self._fetchone(
            "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
            (prior["checkout_key"],),
        )
        self.assertIsNotNone(lifecycle)
        assert lifecycle is not None
        self.assertEqual(prior["owner_id"], lifecycle["owner_id"])
        self.assertEqual(prior["branch"], lifecycle["expected_branch"])
        self.assertFalse(self.checkout.exists())

    def test_expired_retention_and_cleaned_archive_allow_terminal_reuse(self) -> None:
        prior = self._seed_prior(
            phase="archived",
            active_retention=False,
            archive=True,
            cleaned_archive=True,
        )
        inputs = self._inputs(idempotency_key="terminal-reuse")
        reservation = identity.prepare(inputs)
        self.assertEqual("terminal_reuse", reservation["action"])
        self.assertEqual("reserved", reservation["state"])
        lifecycle = checkouts._reserve_checkout_lifecycle(
            repo_common_dir=self.common_dir.resolve(),
            repo_path=self.repo.resolve(),
            checkout_path=self.checkout.resolve(strict=False),
            owner_id=str(inputs["lease_owner_id"]),
            purpose=str(inputs["purpose"]),
            source_kind=str(inputs["source_kind"]),
            source_id=str(inputs["source_id"]),
            artifact_class=str(inputs["artifact_class"]),
            retention_until_unix=int(inputs["retention_until_unix"]),
            expected_head=str(inputs["base_head"]),
            expected_branch=str(inputs["branch"]),
        )
        self.assertEqual(inputs["lease_owner_id"], lifecycle["owner_id"])
        self.assertEqual("active", identity.finalize(reservation)["state"])
        archive = self._fetchone(
            "SELECT * FROM archives WHERE archive_id=?", (prior["archive_id"],)
        )
        self.assertIsNotNone(archive)
        assert archive is not None
        self.assertIsNotNone(archive["cleaned_at_unix"])

    def test_protected_path_does_not_veto_different_exact_path(self) -> None:
        self._seed_prior(
            phase="archived", active_retention=False, archive=True
        )
        other_path = self.worktrees / "different"
        reservation = identity.prepare(
            self._inputs(path=other_path, idempotency_key="different-path")
        )
        self.assertEqual("new", reservation["action"])
        self.assertEqual(self._checkout_key(other_path), reservation["checkout_key"])

    def test_worktree_input_normalizes_exact_supersession_contract(self) -> None:
        prior = self._seed_prior(
            phase="archived", active_retention=False, archive=True
        )
        inputs = self._inputs(idempotency_key="normalize-contract")
        inputs["identity_supersession"] = self._supersession(prior, inputs)
        with patch.object(
            checkouts,
            "_retention_until",
            side_effect=lambda value: int(value),
        ):
            normalized = worktree_ensure._normalize_inputs(inputs)
        self.assertEqual(
            inputs["identity_supersession"], normalized["identity_supersession"]
        )


if __name__ == "__main__":
    unittest.main()

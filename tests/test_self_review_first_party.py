"""Real signed-ingress and Git-read coverage for first-party semantic review."""
from __future__ import annotations

import hashlib
import secrets
import json
import copy
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import grabowski_self_review_execution as review  # noqa: E402
import grabowski_self_review_producer as producer  # noqa: E402
import grabowski_transport_assertion as assertion  # noqa: E402


SECRET = "first-party-test-connector-secret"
SCOPE_SHA256 = hashlib.sha256(b"first-party-test-scope").hexdigest()
RUNTIME_SHA256 = hashlib.sha256(b"first-party-test-runtime").hexdigest()


class FirstPartySemanticReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("ssh-keygen") is None:
            self.skipTest("OpenSSH is required")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "grabowski"
        self.repo.mkdir(mode=0o700)
        self._git("init", "-q")
        self._git("config", "user.email", "review-test@example.invalid")
        self._git("config", "user.name", "Review Test")
        self._git("remote", "add", "origin", "git@github.com:heimgewebe/grabowski.git")
        source = self.repo / "src" / "reviewed.py"
        self.source_path = "src/reviewed.py"
        source.parent.mkdir()
        source.write_text(
            "\n".join(f"BASE_{number} = {number}" for number in range(1, 31)) + "\n",
            encoding="utf-8",
        )
        self._git("add", "src/reviewed.py")
        self._git("commit", "-qm", "base")
        self.base = self._git("rev-parse", "HEAD").strip()
        source.write_text(
            "\n".join(f"HEAD_{number} = {number * 2}" for number in range(1, 31)) + "\n",
            encoding="utf-8",
        )
        self._git("add", "src/reviewed.py")
        self._git("commit", "-qm", "head")
        self.head = self._git("rev-parse", "HEAD").strip()

        self.key = self.root / "issuer"
        generated = subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            capture_output=True, check=False,
        )
        self.assertEqual(0, generated.returncode, generated.stderr.decode())
        self.signers = self.root / "allowed_signers"
        public = (self.root / "issuer.pub").read_text(encoding="utf-8").strip()
        self.signers.write_text(review.PRINCIPAL + " " + public + "\n", encoding="utf-8")
        self.signers.chmod(0o600)
        self.state = self.root / "first-party-state"
        self.transport_state = self.root / "transport-state"
        self.now = int(time.time())
        self._request_counter = 0
        self.canonical_patch = mock.patch.object(producer, "CANONICAL_REPO", self.repo)
        self.canonical_patch.start()
        self.addCleanup(self.canonical_patch.stop)
        self.managed_root_patch = mock.patch.object(
            producer, "MANAGED_REPOS_ROOT", self.root,
        )
        self.managed_root_patch.start()
        self.addCleanup(self.managed_root_patch.stop)

        self.transport_patches = [
            mock.patch.object(assertion, "STATE_ROOT", self.transport_state),
            mock.patch.object(assertion, "LOCK_PATH", self.transport_state / ".lock"),
        ]
        for patcher in self.transport_patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def _git(self, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout

    def _plan(self) -> dict:
        return producer.plan_review(
            repo=self.repo, pr=1649, base_sha=self.base, head_sha=self.head,
            diff_sha256="c" * 64,
            bwrap="/nix/store/" + "a" * 32 + "-bubblewrap-0.12.0/bin/bwrap",
            python="/nix/store/" + "b" * 32 + "-grabowski-operator-test/bin/python3",
        )

    def _first_party_plan(self) -> dict:
        diff_sha256 = hashlib.sha256(
            review._first_party_diff(
                self.repo, {"base_sha": self.base, "head_sha": self.head},
            )
        ).hexdigest()
        return producer.plan_first_party_review(
            repo=self.repo, pr=1649, base_sha=self.base, head_sha=self.head,
            diff_sha256=diff_sha256,
        )

    def _issuer(self, tool_name: str, arguments: dict) -> dict:
        """Consume a real HMAC assertion; this origin is intentionally not mocked."""
        self._request_counter += 1
        request_id = secrets.token_hex(16)  # A new real request identity per signed invocation.
        arguments_sha256 = assertion.canonical_arguments_sha256(arguments)
        body_sha256 = hashlib.sha256(
            json.dumps(
                {"name": tool_name, "arguments": arguments},
                sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        mac = assertion.assertion_mac(
            secret=SECRET, request_id=request_id, issued_at_unix=self.now,
            audience=assertion.ASSERTION_AUDIENCE, tool_name=tool_name,
            arguments_sha256=arguments_sha256, body_sha256=body_sha256,
            runtime_binding_sha256=RUNTIME_SHA256,
        )
        evidence = assertion.consume_assertion(
            secret=SECRET, client_scope_sha256=SCOPE_SHA256,
            runtime_binding_sha256=RUNTIME_SHA256,
            asserted_runtime_binding_sha256=RUNTIME_SHA256,
            request_id=request_id, issued_at_unix=self.now,
            audience=assertion.ASSERTION_AUDIENCE, tool_name=tool_name,
            arguments_sha256=arguments_sha256, body_sha256=body_sha256,
            mac_sha256=mac, session_id="first-party-review-test",
            now_unix=self.now,
        )
        evidence["client_scope_kind"] = "connector_capability"
        return review.authenticated_first_party_issuer(
            "primary", evidence, expected_tool=tool_name,
        )

    def _start(self) -> tuple[dict, dict]:
        plan = self._plan()
        return plan, self._start_plan(plan)

    def _start_plan(self, plan: dict) -> dict:
        arguments = {
            "review_batch_id": plan["binding"]["review_batch_id"],
            "reason": "Start exact-revision semantic review.",
            "user_intent": "Verify the first-party review workflow.",
        }
        started = review.start_first_party_review_session(
            plan, self._issuer(review.FIRST_PARTY_TOOL_START, arguments),
            root=self.state, key=self.key, signers=self.signers,
            root_owned_signers=False, now_unix=self.now,
        )
        return started

    def _seal_direct(self, plan: dict) -> tuple[dict, Path]:
        receipts = self.root / ("audits-" + plan["binding"]["review_batch_id"])
        sealed = producer._seal_first_party_review(
            plan, signers=self.signers, receipts=receipts,
            first_party_root=self.state, repository=self.repo,
            root_owned_signers=False, now_unix=self.now,
        )
        audit = json.loads(
            Path(sealed["audit_path"]).read_text(encoding="utf-8")
        )
        return audit, receipts

    def _receipt_errors(self, audit: dict, receipts: Path) -> list[str]:
        return review.review_receipt_errors(
            audit, _receipts=receipts, _signers=self.signers,
            _first_party_root=self.state, _repository=self.repo,
            _root_owned_signers=False, _now_unix=self.now,
        )

    def _read(self, started: dict, axis: str, read_kind: str, path: str,
              revision: str, first: int, last: int,
              *, now_unix: int | None = None) -> dict:
        arguments = {
            "review_session_id": started["review_session_id"],
            "session_nonce": started["session_nonce"], "axis": axis,
            "read_kind": read_kind, "path": path, "revision": revision,
            "start_line": first, "end_line": last,
            "reason": "Read exact Git evidence for this semantic axis.",
            "user_intent": "Verify the first-party review workflow.",
        }
        return review.record_first_party_source_read(
            started["review_session_id"], started["session_nonce"], axis,
            read_kind, path, revision, first, last,
            self._issuer(review.FIRST_PARTY_TOOL_READ, arguments),
            root=self.state, key=self.key, signers=self.signers,
            root_owned_signers=False,
            now_unix=self.now if now_unix is None else now_unix,
        )

    def _report(self, axis: str, number: int, refs: list[str], *, reject: bool = False) -> dict:
        prefix = f"Axis {number} {axis}"
        findings = []
        if reject:
            findings = [{
                "id": f"material-{number}", "severity": "high",
                "verdict": "UNRESOLVED",
                "summary": prefix + " identifies an unresolved authority failure whose exploit path remains reachable and therefore requires a source change before this exact revision can pass.",
                "evidence_refs": [refs[0]],
            }]
        return {
            "axis": axis, "verdict": "REJECT" if reject else "PASS",
            "summary": prefix + " performs a semantic review of the concrete control flow, data ownership, failure behavior, and exact-revision interactions. It compares the intended invariant with both changed source regions and explains why the observed implementation does or does not leave a material defect.",
            "axis_observations": [
                prefix + " observes that the first changed region establishes the controlling invariant and follows its values through the relevant failure boundary instead of treating test success as semantic evidence.",
                prefix + " observes that the second changed region has a distinct downstream consequence, including the rejection behavior and the authority boundary that must remain closed for this revision.",
            ],
            "evidence_refs": refs,
            "reviewed_risks": [
                {
                    "risk": prefix + " risk of accepting an unbound or replayed semantic decision",
                    "assessment": prefix + " traces the binding and replay checks across the first source range, evaluates the reachable failure path, and concludes whether a different session, head, or unsigned payload could satisfy the gate.",
                    "verdict": "MATERIAL" if reject else "NON_MATERIAL",
                    "evidence_refs": [refs[0]],
                },
                {
                    "risk": prefix + " risk of losing material findings during producer handoff",
                    "assessment": prefix + " traces the second source range into the immutable receipt handoff and checks that a negative verdict cannot be normalized, overwritten, or replaced by deterministic technical task output.",
                    "verdict": "NON_MATERIAL",
                    "evidence_refs": [refs[1]],
                },
            ],
            "findings": findings,
        }

    def _submit_axis(self, started: dict, axis: str, number: int,
                     *, reject: bool = False, full_diff: bool = True) -> dict:
        lines = review._first_party_diff(
            self.repo, {"base_sha": self.base, "head_sha": self.head},
        ).decode("utf-8").splitlines(keepends=True)
        self._read(
            started, axis, "diff", "", "head", 1,
            len(lines) if full_diff else 1,
        )
        first = self._read(started, axis, "source", self.source_path, "head", 1, 8)
        second = self._read(started, axis, "source", self.source_path, "head", 9, 16)
        report = self._report(axis, number, [first["source_ref"], second["source_ref"]], reject=reject)
        arguments = {
            "review_session_id": started["review_session_id"],
            "session_nonce": started["session_nonce"], "report": report,
            "reason": "Submit substantive source-bound semantic analysis.",
            "user_intent": "Verify the first-party review workflow.",
        }
        return review.submit_first_party_axis_review(
            started["review_session_id"], started["session_nonce"], report,
            self._issuer(review.FIRST_PARTY_TOOL_SUBMIT, arguments),
            root=self.state, key=self.key, signers=self.signers,
            root_owned_signers=False, now_unix=self.now,
        )

    def test_five_real_authenticated_source_read_reports_are_accepted(self) -> None:
        plan, started = self._start()
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            result = self._submit_axis(started, axis, number)
            self.assertEqual("axis_accepted", result["status"])
        accepted = review.verified_first_party_semantic_review_passes(
            plan["binding"], repository=self.repo, root=self.state,
            signers=self.signers, root_owned_signers=False, now_unix=self.now,
        )
        self.assertEqual(set(review.REQUIRED_AXES), set(accepted))
        self.assertTrue(all(
            item["provenance_kind"] == "first_party_authenticated_controller"
            for item in accepted.values()
        ))

    def test_first_party_direct_audit_passes_public_receipt_verifier(self) -> None:
        plan = self._first_party_plan()
        started = self._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            self._submit_axis(started, axis, number)
        audit, receipts = self._seal_direct(plan)
        self.assertEqual([], self._receipt_errors(audit, receipts))

        for field, replacement in (
            ("repo", "heimgewebe/heim-pc"),
            ("base_sha", "1" * 40),
            ("head_sha", "2" * 40),
            ("diff_sha256", "3" * 64),
        ):
            replay = copy.deepcopy(audit)
            replay[field] = replacement
            self.assertTrue(self._receipt_errors(replay, receipts), field)
        altered_proof = copy.deepcopy(audit)
        altered_proof["review_pass_receipts"][0]["axis_report_sha256"] = "4" * 64
        self.assertTrue(self._receipt_errors(altered_proof, receipts))

        persisted_read = next((
            self.state / "sessions" / audit["review_pass_receipts"][0]["session_id"] / "reads"
        ).glob("*.data"))
        persisted_read.write_bytes(b"tampered source bytes")
        self.assertTrue(self._receipt_errors(audit, receipts))

    def test_heim_pc_nix_review_seals_without_grabowski_test_tasks(self) -> None:
        self.repo = self.root / "heim-pc"
        self.repo.mkdir(mode=0o700)
        self.source_path = "flake.nix"
        self._git("init", "-q")
        self._git("config", "user.email", "review-test@example.invalid")
        self._git("config", "user.name", "Review Test")
        self._git("remote", "add", "origin", "git@github.com:heimgewebe/heim-pc.git")
        source = self.repo / self.source_path
        source.write_text(
            "{\n" + "".join(f"  # base nix policy line {n}\n" for n in range(1, 25))
            + "  outputs = { self }: {};\n}\n",
            encoding="utf-8",
        )
        self._git("add", self.source_path)
        self._git("commit", "-qm", "base")
        self.base = self._git("rev-parse", "HEAD").strip()
        source.write_text(
            "{\n" + "".join(f"  # reviewed nix authority line {n}\n" for n in range(1, 25))
            + "  outputs = { self }: {};\n}\n",
            encoding="utf-8",
        )
        self._git("add", self.source_path)
        self._git("commit", "-qm", "head")
        self.head = self._git("rev-parse", "HEAD").strip()
        # Grabowski shares one managed worktree root across repositories.
        shared = self.root / ".grabowski-worktrees"
        shared.mkdir()
        candidate = shared / "heim-pc-high-critical"
        self._git("worktree", "add", "--detach", str(candidate), self.head)
        self.repo = candidate

        plan = self._first_party_plan()
        self.assertEqual("heimgewebe/heim-pc", plan["binding"]["repo"])
        self.assertNotIn("tasks", plan)
        started = self._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            self._submit_axis(started, axis, number)
        audit, receipts = self._seal_direct(plan)
        self.assertEqual([], self._receipt_errors(audit, receipts))

    def test_wrong_remote_and_missing_axis_block_direct_audit(self) -> None:
        self._git(
            "remote", "set-url", "origin", "git@github.com:heimgewebe/heim-pc.git",
        )
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "origin"):
            self._first_party_plan()
        self._git(
            "remote", "set-url", "origin", "git@github.com:heimgewebe/grabowski.git",
        )
        unmanaged = self.root / "unmanaged" / "grabowski"
        unmanaged.mkdir(parents=True)
        subprocess.run(
            ["git", "-C", str(unmanaged), "init", "-q"], check=True,
        )
        subprocess.run(
            ["git", "-C", str(unmanaged), "remote", "add", "origin",
             "git@github.com:heimgewebe/grabowski.git"], check=True,
        )
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "managed checkout"):
            producer._managed_repository_identity(unmanaged)
        plan = self._first_party_plan()
        started = self._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES[:-1], start=1):
            self._submit_axis(started, axis, number)
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "axis coverage"):
            self._seal_direct(plan)

    def test_github_pr_diff_identity_is_distinct_from_local_source_diff(self) -> None:
        # GitHub's canonical PR patch is not byte-identical to git --no-renames
        # for real PRs. The Gate binds it independently from the local diff.
        plan = self._first_party_plan()
        local_sha = hashlib.sha256(
            review._first_party_diff(self.repo, plan["binding"]),
        ).hexdigest()
        self.assertNotEqual("e" * 64, local_sha)
        plan["binding"]["diff_sha256"] = "e" * 64
        started = self._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            self._submit_axis(started, axis, number)
        audit, receipts = self._seal_direct(plan)
        self.assertEqual("e" * 64, audit["diff_sha256"])
        self.assertEqual([], self._receipt_errors(audit, receipts))

    def test_https_origin_is_admitted_as_the_same_github_repository(self) -> None:
        self._git("remote", "set-url", "origin",
                  "https://github.com/heimgewebe/grabowski.git")
        _worktree, slug = producer._managed_repository_identity(
            self.repo, expected_repo="heimgewebe/grabowski",
        )
        self.assertEqual("heimgewebe/grabowski", slug)

    def test_completed_review_remains_valid_after_session_write_deadline(self) -> None:
        # The deadline limits NEW source reads and report submissions. A fully
        # signed, revision-bound completed review is durable Captain evidence.
        plan, started = self._start()
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            self._submit_axis(started, axis, number)
        after_deadline = self.now + review.FIRST_PARTY_SESSION_TTL_SECONDS + 1
        accepted = review.verified_first_party_semantic_review_passes(
            plan["binding"], repository=self.repo, root=self.state,
            signers=self.signers, root_owned_signers=False,
            now_unix=after_deadline,
        )
        self.assertEqual(set(review.REQUIRED_AXES), set(accepted))
        axis = review.REQUIRED_AXES[0]
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "expired"):
            self._read(
                started, axis, "diff", "", "head", 2, 2,
                now_unix=after_deadline,
            )

    def test_partial_canonical_diff_must_not_authorize_five_passes(self) -> None:
        plan, started = self._start()
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            self._submit_axis(started, axis, number, full_diff=False)
        # Each axis saw only the first diff line. The current producer must
        # not infer review of all changed paths from that single observed line.
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "canonical diff coverage incomplete",
        ):
            review.verified_first_party_semantic_review_passes(
                plan["binding"], repository=self.repo, root=self.state,
                signers=self.signers, root_owned_signers=False, now_unix=self.now,
            )

    def test_large_delta_is_verified_from_multiple_bounded_chunks(self) -> None:
        # A real large PR must not be returned as a single truncation-prone
        # MCP response. Verify all Git diff lines across separate read receipts.
        bulk = self.repo / "src" / "bulk.txt"
        bulk.write_text(
            "".join(f"large delta line {line}: sourced review data\n" for line in range(1400)),
            encoding="utf-8",
        )
        self._git("add", "src/bulk.txt")
        self._git("commit", "-qm", "large delta")
        self.head = self._git("rev-parse", "HEAD").strip()
        plan, started = self._start()
        lines = review._first_party_diff(
            self.repo, plan["binding"],
        ).decode("utf-8").splitlines(keepends=True)
        self.assertGreater(len(lines), review.FIRST_PARTY_MAX_READ_LINES)
        axis = review.REQUIRED_AXES[0]
        first = self._read(
            started, axis, "diff", "", "head", 1,
            review.FIRST_PARTY_MAX_READ_LINES,
        )
        self.assertEqual(len(lines), first["diff_total_lines"])
        self.assertLessEqual(
            len(first["content"].encode("utf-8")), review.FIRST_PARTY_MAX_READ_BYTES,
        )
        for start in range(review.FIRST_PARTY_MAX_READ_LINES + 1, len(lines) + 1,
                           review.FIRST_PARTY_MAX_READ_LINES):
            self._read(
                started, axis, "diff", "", "head", start,
                min(start + review.FIRST_PARTY_MAX_READ_LINES - 1, len(lines)),
            )
        for number, each_axis in enumerate(review.REQUIRED_AXES, start=1):
            self._submit_axis(started, each_axis, number, full_diff=False)
        verified = review.verified_first_party_semantic_review_passes(
            plan["binding"], repository=self.repo, root=self.state,
            signers=self.signers, root_owned_signers=False, now_unix=self.now,
        )
        self.assertEqual(set(review.REQUIRED_AXES), set(verified))

    def test_secondary_enrolled_connector_cannot_issue_controller_reviews(self) -> None:
        # A valid transport identity for a different enrolled connector is
        # not the primary Grabowski controller's semantic review authority.
        evidence = {
            "state": "consumed", "single_use": True,
            "transport_mode": "signed-one-call-v1",
            "client_scope_kind": "connector_capability",
            "tool_name": review.FIRST_PARTY_TOOL_START,
            "client_scope_sha256": SCOPE_SHA256,
            "runtime_binding_sha256": RUNTIME_SHA256,
            "arguments_sha256": "a" * 64,
            "consumption_receipt_sha256": "b" * 64,
            "request_id": "c" * 32,
        }
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "controller issuer",
        ):
            review.authenticated_first_party_issuer(
                "unrelated-connector", evidence,
                expected_tool=review.FIRST_PARTY_TOOL_START,
            )

    def test_unsourced_report_and_spoofed_issuer_are_rejected(self) -> None:
        plan = self._plan()
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "issuer"):
            review.start_first_party_review_session(
                plan, {"connector_id": "arbitrary-cli"},
                root=self.state, key=self.key, signers=self.signers,
                root_owned_signers=False, now_unix=self.now,
            )
        _plan, started = self._start()
        axis = review.REQUIRED_AXES[0]
        report = self._report(
            axis, 1, ["src/reviewed.py:L1-L8", "src/reviewed.py:L9-L16"],
        )
        arguments = {
            "review_session_id": started["review_session_id"],
            "session_nonce": started["session_nonce"], "report": report,
            "reason": "Attempt an unsourced semantic submission.",
            "user_intent": "Verify the first-party review workflow.",
        }
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "observed source"):
            review.submit_first_party_axis_review(
                started["review_session_id"], started["session_nonce"], report,
                self._issuer(review.FIRST_PARTY_TOOL_SUBMIT, arguments),
                root=self.state, key=self.key, signers=self.signers,
                root_owned_signers=False, now_unix=self.now,
            )

    def test_duplicate_cross_session_and_revision_drift_are_rejected(self) -> None:
        _plan, started = self._start()
        axis = review.REQUIRED_AXES[0]
        self._submit_axis(started, axis, 1)
        duplicate = self._report(
            axis, 99, ["src/reviewed.py:L1-L8", "src/reviewed.py:L9-L16"],
        )
        duplicate_arguments = {
            "review_session_id": started["review_session_id"],
            "session_nonce": started["session_nonce"], "report": duplicate,
            "reason": "Attempt a duplicate semantic submission.",
            "user_intent": "Verify the first-party review workflow.",
        }
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "duplicated"):
            review.submit_first_party_axis_review(
                started["review_session_id"], started["session_nonce"], duplicate,
                self._issuer(review.FIRST_PARTY_TOOL_SUBMIT, duplicate_arguments),
                root=self.state, key=self.key, signers=self.signers,
                root_owned_signers=False, now_unix=self.now,
            )
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "session"):
            self._read(
                {**started, "session_nonce": "f" * 32},
                review.REQUIRED_AXES[1], "diff", "", "head", 1, 1,
            )
        self._git("commit", "--allow-empty", "-qm", "drift")
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "drift|head changed"):
            self._read(
                started, review.REQUIRED_AXES[1], "diff", "", "head", 1, 1,
            )

    def test_material_finding_blocks_complete_session(self) -> None:
        plan = self._first_party_plan()
        started = self._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            self._submit_axis(started, axis, number, reject=number == 1)
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "material finding unresolved",
        ):
            review.verified_first_party_semantic_review_passes(
                plan["binding"], repository=self.repo, root=self.state,
                signers=self.signers, root_owned_signers=False, now_unix=self.now,
            )
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "material finding unresolved",
        ):
            self._seal_direct(plan)

    def test_expired_session_rejects_fresh_authenticated_read(self) -> None:
        _plan, started = self._start()
        axis = review.REQUIRED_AXES[0]
        arguments = {
            "review_session_id": started["review_session_id"],
            "session_nonce": started["session_nonce"], "axis": axis,
            "read_kind": "diff", "path": "", "revision": "head",
            "start_line": 1, "end_line": 1,
            "reason": "Attempt a source read after expiry.",
            "user_intent": "Verify the first-party review workflow.",
        }
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "expired"):
            review.record_first_party_source_read(
                started["review_session_id"], started["session_nonce"], axis,
                "diff", "", "head", 1, 1,
                self._issuer(review.FIRST_PARTY_TOOL_READ, arguments),
                root=self.state, key=self.key, signers=self.signers,
                root_owned_signers=False,
                now_unix=self.now + review.FIRST_PARTY_SESSION_TTL_SECONDS + 1,
            )


if __name__ == "__main__":
    unittest.main()
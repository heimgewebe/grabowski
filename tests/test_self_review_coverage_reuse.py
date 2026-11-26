"""Prior coverage is reusable only as verified, identical canonical file blocks."""
from __future__ import annotations

import copy
import hashlib
import subprocess
import unittest

import test_self_review_first_party as fixture

review = fixture.review


class FirstPartyCoverageReuseTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.FirstPartySemanticReviewTests()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()

    def _prior(self, *, complete=True, reject=False):
        f = self.f
        generated = f.repo / "generated"
        generated.mkdir()
        (generated / "snapshot.txt").write_text(
            "".join(f"snapshot line {i}\n" for i in range(1, 81)), encoding="utf-8"
        )
        f._git("add", "generated/snapshot.txt")
        f._git("commit", "-qm", "add generated snapshot")
        f.head = f._git("rev-parse", "HEAD").strip()
        plan = f._first_party_plan()
        started = f._start_plan(plan)
        for n, axis in enumerate(review.REQUIRED_AXES, 1):
            if not complete and n > 1:
                break
            f._submit_axis(started, axis, n, reject=reject and n == 1)
        if complete and not reject:
            audit, receipts = f._seal_direct(plan)
            self.assertEqual("PASS", audit["gate_verdict"])
            self.assertEqual([], f._receipt_errors(audit, receipts))
        f.now += 2
        return plan

    def _next(self, name, *, change_generated=None, base=None):
        f = self.f
        pool = f.root / ".grabowski-worktrees"
        pool.mkdir(exist_ok=True)
        current = pool / name
        f._git("worktree", "add", "--detach", str(current), f.head)
        f.repo = current
        if base is not None:
            f.base = base
        source = current / f.source_path
        source.write_text(source.read_text(encoding="utf-8") + f"\n{name.upper()} = 1\n", encoding="utf-8")
        if change_generated:
            change_generated(current / "generated/snapshot.txt")
        f._git("add", "--all")
        f._git("commit", "-qm", "change source " + name)
        f.head = f._git("rev-parse", "HEAD").strip()
        plan = f._first_party_plan()
        return plan, f._start_plan(plan)

    def _submit(self, plan, started, number, *, prior=None, resolve=False):
        f = self.f
        axis = review.REQUIRED_AXES[number - 1]
        diff = review._first_party_diff(f.repo, plan["binding"])
        blocks = review._canonical_file_diff_blocks(diff)
        first, last, _ = next(b for b in blocks if b[2].startswith(
            ("diff --git a/" + f.source_path + " b/" + f.source_path + "\n").encode()
        ))
        f._read(started, axis, "diff", "", "head", first, last)
        one = f._read(started, axis, "source", f.source_path, "head", 1, 8)
        two = f._read(started, axis, "source", f.source_path, "head", 9, 16)
        report = f._report(axis, number, [one["source_ref"], two["source_ref"]])
        if prior is not None:
            report["coverage_reuse_batch_id"] = prior["binding"]["review_batch_id"]
        if resolve:
            rejected = f._report(axis, number, [one["source_ref"], two["source_ref"]], reject=True)
            for item in rejected["findings"]:
                report["findings"].append({
                    **item, "verdict": "RESOLVED",
                    "summary": "The subsequent authenticated source review resolves this earlier material concern against the currently inspected evidence and identifies why the current revised source no longer exhibits the reported problem.",
                })
        return f._submit(started, report)

    def _complete(self, plan, started, *, prior=None, resolve=False):
        first = self._submit(plan, started, 1, prior=prior, resolve=resolve)
        for n in range(2, 6):
            self._submit(plan, started, n)
        return first

    def _verify(self, plan):
        f = self.f
        return review.verified_first_party_semantic_review_passes(
            plan["binding"], repository=f.repo, root=f.state, signers=f.signers,
            root_owned_signers=False, now_unix=f.now,
        )

    def test_complete_prior_unchanged_block_can_fill_current_coverage(self):
        f = self.f
        prior = self._prior()
        plan, started = self._next("current")
        first = self._complete(plan, started, prior=prior)
        self.assertEqual(1, first["coverage_reuse"]["identical_file_count"])
        self.assertGreater(first["coverage_reuse"]["covered_line_count"], 80)
        audited, receipts = f._seal_direct(plan)
        self.assertEqual("PASS", audited["gate_verdict"])
        self.assertEqual([], f._receipt_errors(audited, receipts))
        for item in audited["review_pass_receipts"]:
            self.assertEqual(prior["binding"]["review_batch_id"], item["coverage_reuse_batch_id"])
            self.assertEqual(first["coverage_reuse"]["proof_sha256"], item["coverage_reuse_sha256"])
        forged = copy.deepcopy(audited)
        forged["review_pass_receipts"][0]["coverage_reuse_sha256"] = "0" * 64
        self.assertTrue(f._receipt_errors(forged, receipts))

    def test_no_selector_keeps_old_full_read_requirement(self):
        self._prior()
        plan, started = self._next("current")
        self._complete(plan, started)
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "coverage incomplete"):
            self._verify(plan)

    def test_changed_generated_bytes_are_not_reused(self):
        prior = self._prior()
        plan, started = self._next("current", change_generated=lambda p: p.write_text("changed\n"))
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "no identical file blocks"):
            self._submit(plan, started, 1, prior=prior)

    def test_changed_generated_mode_is_not_reused(self):
        prior = self._prior()
        plan, started = self._next("current", change_generated=lambda p: p.chmod(0o755))
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "no identical file blocks"):
            self._submit(plan, started, 1, prior=prior)

    def test_renamed_generated_path_is_not_reused(self):
        prior = self._prior()
        plan, started = self._next("current", change_generated=lambda p: p.rename(p.with_name("other.txt")))
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "no identical file blocks"):
            self._submit(plan, started, 1, prior=prior)

    def test_base_drift_rejected_even_with_old_identical_content(self):
        prior = self._prior()
        plan, started = self._next("current", base=prior["binding"]["head_sha"])
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "crossed PR/base or time"):
            self._submit(plan, started, 1, prior=prior)

    def test_partial_prior_does_not_establish_coverage(self):
        prior = self._prior(complete=False)
        plan, started = self._next("current")
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "prior review incomplete"):
            self._submit(plan, started, 1, prior=prior)

    def test_rejected_prior_does_not_establish_coverage(self):
        prior = self._prior(reject=True)
        plan, started = self._next("current")
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "material finding unresolved"):
            self._submit(plan, started, 1, prior=prior)

    def test_later_same_pr_reject_cannot_disappear_through_reuse(self):
        f = self.f
        prior = self._prior()
        _, intervening = self._next("intervening")
        f._submit_axis(intervening, review.REQUIRED_AXES[0], 1, reject=True)
        f.now += 2
        plan, started = self._next("current")
        self._complete(plan, started, prior=prior)
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "material finding unresolved"):
            self._verify(plan)

    def _remove(self, path, ref):
        f = self.f
        canonical = f.root/"grabowski"
        assert path.parent==f.root/".grabowski-worktrees"
        assert path.is_dir()
        head=subprocess.check_output(["git","-C",str(path),"rev-parse","HEAD"],text=True).strip()
        subprocess.run(["git","-C",str(canonical),"update-ref","refs/heads/"+ref,head],check=True)
        subprocess.run(["git","-C",str(canonical),"worktree","remove",str(path)],check=True)
        assert not path.exists()
        assert subprocess.check_output(["git","-C",str(canonical),"rev-parse",ref],text=True).strip()==head
        return canonical

    def _linked_prior(self):
        f = self.f
        pool=f.root/".grabowski-worktrees"
        pool.mkdir()
        path=pool/"prior"
        f._git("worktree","add","--detach",str(path),f.head)
        f.repo=path
        return self._prior(),path

    def test_removed_prior_and_current_still_verify(self):
        f = self.f
        prior,prior_path=self._linked_prior()
        plan,started=self._next("current")
        canonical=self._remove(prior_path,"recovery-prior")
        first=self._complete(plan,started,prior=prior)
        self.assertGreater(first["coverage_reuse"]["covered_line_count"],80)
        audit,receipts=f._seal_direct(plan)
        current=f.repo
        # A current review must be able to borrow exact signed earlier
        # coverage even after the earlier physical checkout is gone.
        self.assertEqual(5,len(self._verify(plan)))
        self._remove(current,"recovery-current")
        kwargs=dict(receipts=receipts,outcomes=f.root/"outcomes",signers=f.signers,
                    repository=canonical,now_unix=f.now,root_owned_signers=False,
                    first_party_root=f.state,historical_objects=True)
        review._verify(audit,**kwargs)
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "historical review repository must be canonical"
        ):
            review._verify(audit, **{**kwargs, "repository": prior_path})
        forged=copy.deepcopy(audit)
        forged["review_pass_receipts"][0]["coverage_reuse_sha256"]="0"*64
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "direct first-party audit proof differs from signed records"
        ):
            review._verify(forged, **kwargs)
        historical, historical_root = review._load_first_party_session_record(
            started["review_session_id"], root=f.state, signers=f.signers,
            root_owned_signers=False, now_unix=f.now, require_fresh=False,
        )
        for field, altered, message in (
            ("source_raw_diff_sha256", "0" * 64, "historical raw diff drift"),
            ("changed_paths", [], "historical changed paths drift"),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(
                review.ReviewExecutionRejected, message
            ):
                review._historical_pr_source(
                    {**historical, field: altered}, repository=canonical,
                    session_root=historical_root, signers=f.signers,
                    root_owned_signers=False,
                )
        missing = {**historical, "binding": {**historical["binding"], "head_sha": "0" * 40}}
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "trusted source Git probe failed"
        ):
            review._historical_pr_source(
                missing, repository=canonical, session_root=historical_root,
                signers=f.signers, root_owned_signers=False,
            )
        # Strict live-source admission stays distinct.
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "review source Git checkout identity invalid"
        ):
            review.verified_first_party_semantic_review_passes(
                plan["binding"],repository=None,root=f.state,signers=f.signers,
                root_owned_signers=False,now_unix=f.now)

    def _release_plan(self):
        f = self.f
        _technical, release, diff = f._signed_release_plan()
        return fixture.producer.plan_first_party_review(
            repo=f.repo, pr=1649, base_sha=f.base, head_sha=f.head,
            diff_sha256=diff, purpose="post_merge_release", release_binding=release,
        )

    def test_non_pr_prior_is_not_a_coverage_source(self):
        f = self.f
        prior = self._release_plan()
        f._start_plan(prior)
        f.now += 2
        plan, started = self._next("current")
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "coverage prior crossed PR/base or time"
        ):
            self._submit(plan, started, 1, prior=prior)

    def test_intervening_release_finding_does_not_cross_pr_purpose(self):
        f = self.f
        prior = self._prior()
        self._next("intervening")
        release = self._release_plan()
        started_release = f._start_plan(release)
        f._submit_axis(started_release, review.REQUIRED_AXES[0], 1, reject=True)
        f.now += 2
        plan, started = self._next("current")
        self._complete(plan, started, prior=prior)
        self.assertEqual(5, len(self._verify(plan)))

    def test_removed_intervening_reject_still_blocks(self):
        f = self.f
        prior,prior_path=self._linked_prior()
        _,intervening=self._next("intervening")
        f._submit_axis(intervening,review.REQUIRED_AXES[0],1,reject=True)
        intervening_path=f.repo
        f.now+=2
        plan,started=self._next("current")
        self._complete(plan,started,prior=prior)
        self._remove(prior_path,"recovery-prior")
        self._remove(intervening_path,"recovery-intervening")
        with self.assertRaisesRegex(review.ReviewExecutionRejected,"material finding unresolved"):
            self._verify(plan)


    def _legacy_guard(self, plan, repository):
        f = self.f
        review._assert_no_first_party_reject_for_legacy_review(
            plan["binding"], repository=repository, root=f.state,
            signers=f.signers, root_owned_signers=False,
        )

    def test_removed_legacy_pass_remains_acceptable(self):
        plan, path = self._linked_prior()
        canonical = self._remove(path, "recovery-legacy-pass")
        self._legacy_guard(plan, canonical)
        self._legacy_guard(
            {**plan, "binding": {**plan["binding"], "repo": "heimgewebe/Grabowski"}},
            canonical,
        )
        (self.f.root / "Grabowski").mkdir()
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "historical canonical source ambiguous or absent"
        ):
            self._legacy_guard(plan, canonical)

    def test_removed_legacy_reject_and_resolution_remain_effective(self):
        f = self.f
        pool = f.root / ".grabowski-worktrees"
        pool.mkdir()
        original = pool / "rejected"
        f._git("worktree", "add", "--detach", str(original), f.head)
        f.repo = original
        rejected = self._prior(reject=True)
        canonical = self._remove(original, "recovery-legacy-reject")
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "previous signed material finding unresolved"
        ):
            self._legacy_guard(rejected, canonical)

        newer = pool / "resolution"
        f.repo = canonical
        f._git("worktree", "add", "--detach", str(newer), f.head)
        f.repo = newer
        plan = f._first_party_plan()
        started = f._start_plan(plan)
        for n, axis in enumerate(review.REQUIRED_AXES, 1):
            f._submit_axis(started, axis, n, resolve_ids=("material-1",) if n == 1 else ())
        audit, _ = f._seal_direct(plan)
        self.assertEqual("PASS", audit["gate_verdict"])
        self._remove(newer, "recovery-legacy-resolution")
        self._legacy_guard(plan, canonical)

    def test_large_exact_file_blocks_and_non_lf_separator(self):
        # Representative generated-release shape. A Unicode line separator
        # inside an added source line is NOT an actual Git file header.
        blocks = [
            (f"diff --git a/releases/{n}.txt b/releases/{n}.txt\n"
             f"new file mode 100644\nindex {'0' * 40}..{hashlib.sha1(str(n).encode()).hexdigest()}\n"
             f"--- /dev/null\n+++ b/releases/{n}.txt\n@@ -0,0 +1,85 @@\n"
             + "+content\n" * 85).encode()
            for n in range(1028)
        ]
        old = b"".join(blocks)
        blocks[-1] = blocks[-1].replace(b"+content\n", "+changed\u2028diff --git not-a-real-header\n".encode(), 1)
        current = b"".join(blocks)
        matches = review._identical_file_diff_ranges(current, old)
        self.assertEqual(1027, len(matches))
        self.assertEqual(1028, len(review._canonical_file_diff_blocks(current)))
        self.assertGreater(sum(last - first + 1 for first, last, _ in matches), 90000)
        self.assertFalse(review._first_party_ranges_complete(
            [(first, last) for first, last, _ in matches],
            len(current.decode().splitlines(keepends=True)),
        ))


if __name__ == "__main__":
    unittest.main()

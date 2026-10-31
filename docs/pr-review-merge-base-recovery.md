# PR/Compare merge-base drift: fail-closed settlement recovery

## Safety boundary

GitHub documents that a pull request's **Files changed** presentation and its
generic **Compare** view can use different merge-base anchors after the base
branch advances:
<https://docs.github.com/en/pull-requests/reference/pull-requests#differences-between-commits-on-compare-and-pull-request-pages>.

`tools/codex_review_settlement.py` reads mutable PR-specific GraphQL file paths,
`gh pr diff`, and commit-SHA-addressed Compare file/patch evidence. The latter
authenticates its own base/head pair, **not necessarily the historical merge-base
used by the PR file view**. A workflow rename from
`.github/workflows/ci.yml` to `docs/ci.md` can appear as a modification of
`docs/ci.md` under a newer anchor. Destination-path equality therefore does
not establish rename-origin or semantic diff equality.

If PR and immutable Compare evidence disagree, settlement **must fail closed**.
Never suppress the mismatch, accept REST rename provenance based only on matching
file counts/paths, downgrade critical-path review, or copy an older R3 decision.

This recovery path addresses *availability after base drift*, not the general
problem of authenticating GitHub's historical PR-specific merge base. The
synthetic Git DAG from issue #1596 establishes anchor-dependent rename identity;
it is **not** proof that GitHub chooses the historic anchor in that exact DAG.
Issue: <https://github.com/heimgewebe/grabowski/issues/1596>.

## Deterministic triage (observation only)

1. Record repository, PR number, exact remote `headRefOid`, `baseRefOid`,
   `changedFiles`, main HEAD, and the complete changed-file/diff identities.
   Check unresolved review threads and required CI. Record actual branch,
   checkout identity, dirty state, active owner lane, processes, resource leases,
   and any earlier unknown-outcome fences.
2. Read immutable Compare metadata and patch for the exact head/base SHAs.
   Reject partial pagination, >300 Compare files, truncated patch, missing
   rename/copy previous path, bad compare commit identity, or changed count/path
   disagreement. Preserve canonical patch-content identity and A→B→A guards.
3. If PR and Compare changed-file provenance or canonical patch identity differ,
   **stop settlement**. Do not classify the diff as documentation-only based on
   `docs/` destinations.
4. Verify that a base-drift recovery is appropriate and that the particular
   branch has a live, exclusive, scoped Grabowski owner. On a blocked, dirty,
   foreign-owned, or uncertain lane: do not retry or hand-edit the branch.
5. Use the native Grabowski `pr-base-converge` grip only with the *fresh,
   exact* expected remote PR HEAD and main/base SHA, respecting its admission
   contract. Do not replace it with a force-push, raw rebase, direct main
   mutation, or a GitHub API shortcut. Preserve the original PR and its source
   history. If the grip returns `outcome_unknown`, read its named receipt
   and GitHub branch state before considering any further effect.
6. Read GitHub again: verify the new PR head, base, ancestry, remote SHA,
   unchanged main, and absence of unintended source loss. Convergence can remove
   the anchor divergence for this revision, but **cannot** authenticate all
   historical merge-base cases.
7. On the **new** exact HEAD/base/diff: rerun the relevant focused and full
   tests, GitHub checks, independent high-critical R3, five-pass selfreview,
   and Codex thread triage. Existing review findings still block until
   legitimately resolved. A green Python matrix is not a settlement PASS.
8. Only the protected Captain gate may integrate a ready, current revision.
   Keep issue #1596 open when the general merge-base provenance question remains.

## Required regression invariants

- Same destination path and changed-file count, but different historical
  rename provenance, must **not** imply an authenticated comparison.
- If the mutable PR diff and SHA-pinned Compare diff describe different patch
  content, `_live_state` must raise `SettlementError` **before** policy
  classification or review settlement.
- Canonically identical patches with only index-hash abbreviation or optional
  hunk-context-label differences may match; true content/rename differences may not.
- Critical `.github/workflows/**`, `.github/actions/**` and Nix trust paths
  remain high critical, including rename/copy origins.
- A→B→A head races, ambiguous/incomplete pagination, Compare truncation,
  >300-file limits, and missing revision bindings must remain fail-closed.

## Authentic executed recovery example (historical, not reusable authority)

On 2026-10-21, PR #1594 advanced from
`4f1d90936bca9bf6e6f37e1bb890cc8211186d47` to
`dd455fecf126b8b47cbcc4af12f3d9e6dddc285a` using Grabowski
`pr-base-converge`, with main/base
`c9aa2fc3934a0e3353557ceff780bd6233eb7ddb`.
Receipt SHA-256:
`d91dba13153c1b3405be90b34bb4b462752815a95395a07ace2752adcfabb55c`.
GitHub confirmed a pushed new head, retained original PR, and unchanged main.
The PR remained Draft; `Codex review settled` remained failed.
These immutable historical values are **not** admissible as preconditions for
any future mutation, reviewer decision, or Captain merge.

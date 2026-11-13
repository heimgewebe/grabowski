# Terminal owner hygiene permission

`worktree-hygiene-reconcile` defaults `include_terminal_owners` to false.
Setting it to true is operator-level opt-in to consider owner-bound terminal
checkouts. It does not grant permission on behalf of the original source.
The original authenticated lane worktree lifecycle receipt must explicitly
set `automatic_cleanup_authorized` to true before either archival or cleanup.
False or absent values cause `source_automatic_cleanup_not_authorized` and a
blocked receipt, including for historical lanes. No global override is implied.

Eligibility also requires authenticated `pr_merged`, `deployed`, or
`no_change_proven` terminal evidence. `pr_opened` and `pr_updated` require a
live, unambiguous merged GitHub PR matching the checkout branch, exact head,
and canonical repository default branch. Unavailable or mismatched evidence
blocks the candidate. Successor handoff, durable follow-up, and unknown states
are ineligible, including when an archive already exists.

These checks precede both archival and automatic cleanup and supplement the
existing owner, binding, original physical identity, dirty state, coordination,
retention, grace period, and cleanup plan checks. Active lanes remain ineligible
even after a retention or lease expires. Archive and cleanup remain separate
invocations. A blocked candidate is reported explicitly; it is not successful
cleanup.

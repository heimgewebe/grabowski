# Terminal owner hygiene permission

The generic \`worktree-hygiene-reconcile\` Grip defaults
\`include_terminal_owners\` to false. The existing periodic maintenance runner
enables this mode by default; the CLI also supports
\`--no-worktree-hygiene-include-terminal-owners\` for explicit opt-out.

Newly created, ordinary \`implementation-worktree\` checkouts acquired through
a Work Lane with its own \`work_lane\` lifecycle source carry prospective
\`automatic_cleanup_authorized: true\` in the original immutable receipt.
The owner, lane id and work-acquire idempotency identity must agree. Use a
different artifact class (for example \`retained-worktree\`) when automatic
retirement is not desired. Other source kinds, existing checkouts, historical
receipts and ambiguous interrupted creations do not acquire permission merely
by replaying or being observed. False or absent opt-in is a normal exclusion,
not permission to rewrite an old receipt.

This is not a deletion authorization for active work. Eligibility still
requires authenticated \`pr_merged\`, \`deployed\`, or \`no_change_proven\`
terminal evidence. \`pr_opened\` and \`pr_updated\` require a live, unambiguous
merged GitHub PR matching the checkout branch, exact head and canonical
repository default branch. Unmerged PRs, successor handoffs and durable
follow-ups remain ineligible. Unavailable or ambiguous evidence is reported
as blocked rather than successful cleanup.

The existing owner, lifecycle binding, original physical identity, clean
status, coordination, retention, grace period and CAS cleanup-plan checks
remain in force. Foreign terminal owners are not processed during live
retention. Already eligible archives are prioritized; archival and cleanup
remain separate bounded invocations. Both branch and recovery refs survive
checkout removal.

The NixOS worktree-hygiene service uses the pinned Grabowski retention
module's default. A repository merge alone does not change that service:
the new operator package must be activated and the periodic path observed.

### Physical review-source dependencies

The existing signed review verifier reopens its original checkout. Hygiene
therefore skips exact paths named by a started first-party review session or
legacy role/task review execution plan. The native cleanup plan and its apply
path independently recheck the same dependency. An unstarted first-party
plan alone is not a retention claim. This is an observed dependency of the
current verifier, not another review or approval requirement. Recovery refs
preserve Git content but do not by themselves make a path-bound review
verifiable. Decoupling historical verification from the physical checkout is
the longer-term way to retire these dependencies without retaining worktrees.

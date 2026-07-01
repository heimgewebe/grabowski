# Worktree Hygiene Audit v1

## These / Antithese / Synthese

These: Grabowski worktree hygiene is needed because the previous deploy failed when `main` was checked out in a secondary worktree.

Antithese: Automatic cleanup is unsafe in the current state: several worktrees are dirty, and the inventory reports live shell processes associated with the canonical checkout.

Synthese: This slice records a dry-run classification only. It does not archive, remove, or prune any worktree. Cleanup remains a separate reviewed operation.

## Evidence

Generated from:

- `grabowski_checkout_summary`
- `grabowski_checkout_inventory(include_processes=true, include_tasks=true, include_resources=true)`
- `steuerboard operator report --branch-warning-threshold 5 --json`

Steuerboard usage probe:

- operation: worktree-hygiene-v1
- target_repo: /home/alex/repos/grabowski
- useful_signal: branch_drift_warning_triggered=true; non_default_branch_count=84; detached_head_count=7
- changed_decision: no
- noise: medium

## Current healthy baseline

- Canonical checkout: `/home/alex/repos/grabowski`
- Canonical branch: `main`
- Canonical HEAD: `4811b0bbd5b869a3683268b79c46f1c5b7559810`
- Runtime match: true
- Runtime matching worktree count: 2
- Total worktrees: 23

The previous `main` conflict is currently resolved: `/home/alex/grabowski-workspace/operator-relay-context-gate` is detached at the live head.

## Classification

### Keep / active baseline

| Path | Reason |
|---|---|
| `/home/alex/repos/grabowski` | canonical checkout, branch `main`, clean, matches runtime |
| `/home/alex/grabowski-workspace/operator-relay-context-gate` | detached, clean, matches runtime; do not remove until its former purpose is explicitly closed |

### Dirty retain

These must not be cleaned up automatically.

| Path | Branch | Dirty evidence |
|---|---|---|
| `/home/alex/grabowski-workspace/worktree-lifecycle` | `feat/worktree-lifecycle` | 15 entries, 3 untracked |
| `/home/alex/repos/.bureau-worktrees/BUR-RUN-20260627T181543Z-817653cf4c` | `fix/gui-worker-terminal-classification` | 1 entry |
| `/home/alex/repos/grabowski-gui-fix-v2` | `feat/observer-shutdown-hygiene-v1` | 1 entry, 1 untracked |
| `/home/alex/repos/operator-workspace-v1` | `feat/operator-workspace-v1` | 2 entries, 2 untracked |

### Clean review candidates

These are clean but still require branch/PR purpose review before archive or cleanup.

| Path | Branch / state | Head |
|---|---|---|
| `/home/alex/.local/state/grabowski/deploy-checkouts/8fe6eea5` | detached | `8fe6eea5d93a6a4db4cec6885f83c5305a27b561` |
| `/home/alex/grabowski-workspace/continuity-bootstrap-v1` | `feat/continuity-bootstrap-v1` | `105f15dce0ba86d16a96ac66cbdd0e81224af71c` |
| `/home/alex/grabowski-workspace/friction-capability-v2` | `fix/friction-record-capability-v2` | `8b17f658a24d711d217eb0f15d2d15c597e0349c` |
| `/home/alex/grabowski-workspace/operator-friction-ledger-v1` | `fix/friction-record-capability-v1` | `d422d54527599fe302173155584530daa9da6bb2` |
| `/home/alex/grabowski-workspace/operator-relay-routing-roles` | `feat/operator-relay-routing-roles` | `205259759f5630b6de5bc102cdf935226e042c0e` |
| `/home/alex/grabowski-workspace/systemd-safe-descriptions` | `fix/systemd-safe-transient-descriptions` | `cc3a27c036aa7cdb7450b63ffcc32c3c5f71c717` |
| `/home/alex/repos/.grabowski-autonomy-001` | `feat/grabowski-autonomy-001` | `2949f670a8487a824a33ec7d944f6643add85543` |
| `/home/alex/repos/.grabowski-deploy-f1dd99e` | detached | `f1dd99e293a3d9300a5538c450cf82a513b34584` |
| `/home/alex/repos/.grabowski-durable-runtime` | `feat/grabowski-durable-runtime` | `5c0a3519097c9300915a967e8ba72f4f6fd294f5` |
| `/home/alex/repos/.grabowski-local-evidence` | `integration/grabowski-operator-context` | `2db89b0b5f1ba6289ec29691eccda4b414d6cbbc` |
| `/home/alex/repos/.grabowski-omniperator-v1` | `feat/omniperator-control-plane-v1` | `54065e247fa442237350d570da5e2fed34f26874` |
| `/home/alex/repos/.grabowski-operator-v2` | `feat/grabowski-operator-v2` | `6464d4537aa8f8e5827fbb1b93c025f25eb57645` |
| `/home/alex/repos/.grabowski-operator-v2-port` | `integration/grabowski-operator-v2` | `d94f243e5acae90c29f6ad179eb8b05ff04cb16e` |
| `/home/alex/repos/grabowski-autonomy-pr` | `feat/grabowski-autonomy-pr-v1` | `126c9bfbfd4b0a21a47f7d520eae3f98bb581424` |
| `/home/alex/repos/grabowski-compact-read-surface` | `feat/compact-read-surface-v1` | `8fe6eea5d93a6a4db4cec6885f83c5305a27b561` |
| `/home/alex/repos/grabowski-power-policy-v1` | `fix/connector-contract-probe-v2` | `615c9be9399696418019e3d308827dd8836adfe5` |
| `/home/alex/repos/grabowski-worker-fix` | `fix/gui-worker-terminal-state` | `30fbbab63bd6154c3e88ca34604e2656170cba44` |

## Blocking observations

The inventory currently reports shell processes with cwd `/home/alex/repos/grabowski`. Because those are attached to the canonical checkout, cleanup should not be applied until the operator shell/session situation is understood or quieted.

## Recommended next action

Do not delete anything in this slice.

Next reviewed slice:

1. For each clean review candidate, query PR/branch state.
2. Mark candidates as `retain`, `archive`, or `cleanup-dry-run`.
3. Run `grabowski_checkout_archive` only for clean, closed-purpose worktrees.
4. Run `grabowski_checkout_cleanup` first with `dry_run=true`.
5. Apply cleanup only after reviewing the persisted dry-run plan.

## Does not establish

- No worktree was removed.
- No branch was deleted.
- No archive ref was created.
- No cleanup plan was applied.
- Dirty worktrees remain untouched.

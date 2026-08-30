# P9 mutation-tool classification — 2026-08-30

## Binding

- repository: `heimgewebe/grabowski`
- current-main revision: `30ccbe9b49f794fc4ffe1cbb2062e5d9fbf0dfca`
- M1 report SHA-256: `7105f30c7c11b40ecc19e9016436d1782f0464d135336d7dd8f91c556046c769`
- measurement window: 168 hours
- public tools: **198**
- mutating tools: **94**
- mutation-usage-measurable tools: **93**
- read-only tools: **104**
- observed mutating tools: **61**
- unobserved mutating tools: **32**
- explicit mutation-usage evidence gap: `grabowski_recovery_provenance_repair`

The M1 analyzer explicitly does not establish redundancy or safe public-tool removal. This note applies the P9 semantic classification rule to the 32 currently unobserved mutating tools; zero usage alone is not treated as a removal signal.

## Classification contract

- **A** — necessary emergency, recovery or safety tool.
- **B** — rare but independent authority boundary.
- **C** — compatibility-only public path.
- **D** — effect can be safely composed behind another canonical public authority without hiding a user decision.
- **E** — true public duplicate with an already-proven replacement path.
- **F** — measurement artifact or evidence insufficient for a usage-based removal decision.

Only C–E are P9 reduction candidates from this null-usage set.

## Result

| class | count |
| --- | ---: |
| A | 9 |
| B | 13 |
| C | 0 |
| D | 0 |
| E | 0 |
| F | 10 |

**Result: the current 32-tool null-usage set yields no evidence-backed C–E removal candidate.**

## Per-tool classification

| tool | class | reason |
| --- | --- | --- |
| `grabowski_agent_workspace_close` | B | Explicit lifecycle close authority; may stop tasks, remove tmux state and release leases while preserving branch/worktree evidence. |
| `grabowski_agent_workspace_reconcile_idle_tmux` | A | Recovery path for a provably inactive stale workspace; removes only the non-authoritative idle tmux session before stale reconciliation. |
| `grabowski_agent_workspace_reconcile_stale` | A | Non-destructive stale-workspace recovery/terminalization path with retained evidence. |
| `grabowski_agent_workspace_role_retry` | A | Bounded recovery for one failed read-only workspace role, bound to the frozen writer snapshot. |
| `grabowski_checkout_binding_identity_rebind_apply` | A | CAS recovery for lifecycle/retention identity after a verified branch rename; removing it would remove a safe repair path. |
| `grabowski_chronik_outbox_import` | B | Distinct append-only import authority into optional Chronik, not equivalent to task execution or ordinary audit reads. |
| `grabowski_destroy_path` | B | Explicit irreversible destruction authority separated from reversible quarantine/removal paths. |
| `grabowski_gui_worker_start` | B | Independent GUI-process/display authority; not equivalent to browser-worker start. |
| `grabowski_gui_worker_stop` | B | Independent GUI-worker stop and cleanup authority paired with GUI-worker start. |
| `grabowski_job_notification_ack` | B | Explicit acknowledgement state transition for durable operator-outbox receipts. |
| `grabowski_juno_pair` | B | Local-consent device-pairing and secret-creation authority; intentionally rare. |
| `grabowski_operator_blockade_disarm` | A | Safety recovery path that removes one exact root-owned blockade only after recovery evidence passes. |
| `grabowski_operator_blockade_engage` | A | Safety control-plane authority to establish a fail-closed blockade. |
| `grabowski_operator_blockade_migrate_legacy` | A | Recovery/migration path that moves a legacy blockade into the canonical root-owned authority without opening a mutation gap. |
| `grabowski_restore_removed_path` | A | Canonical recovery path for reversible audited filesystem removal. |
| `grabowski_secret_export` | B | Explicit secret-copy authority with source-hash precondition; not interchangeable with secret use or reveal. |
| `grabowski_secret_reveal` | B | Deliberate break-glass context-exposure authority with acknowledgement and hash binding. |
| `grabowski_task_resume` | A | Recovery authority for recreating a missing or stopped persistent task unit. |
| `grabowski_tmux_send` | B | Explicit interactive-input authority; composing it invisibly behind another tool would hide command-dependent effects. |
| `ipad_bluetooth_inspect` | F | Domain operation is read-only GATT metadata inspection; it appears mutating because a device job/receipt is created. |
| `ipad_bluetooth_read` | F | Domain operation is a bounded read; device-job execution and receipt creation make ordinary null-usage mutation evidence misleading. |
| `ipad_bluetooth_scan` | F | Domain operation is observation-only BLE scanning; device-job/receipt effects dominate the annotation. |
| `ipad_directory_list` | F | Domain operation lists granted metadata only; device-job/receipt creation is not evidence that the public read path is redundant. |
| `ipad_file_create` | B | Real create-only device-file authority with payload hash binding. |
| `ipad_file_read` | F | Domain operation is bounded file reading; device-job/receipt creation causes mutation-side attribution. |
| `ipad_file_replace` | B | Real hash-bound file replacement authority with preimage recheck and post-readback. |
| `ipad_file_stat` | F | Domain operation is metadata-only observation; mutation-side attribution comes from the device execution receipt. |
| `ipad_native_permission_request` | B | Real native permission-request authority with platform-side user interaction and post-readback. |
| `ipad_native_permission_status` | F | Domain operation is permission-state observation only; receipt creation is not a removal signal. |
| `ipad_permission_probe` | F | Domain operation checks one grant and current access without writing; device-job receipt creates the apparent mutation. |
| `ipad_storage_grant_status` | F | Domain operation is bounded grant-status observation with private bookmark bytes withheld. |
| `ipad_storage_inventory` | F | Domain operation inventories granted storage access; device-job/receipt semantics make usage absence non-comparable with ordinary mutating tools. |

## Evidence interpretation

### A: preserve unless the recovery requirement disappears

The A tools are not evaluated by ordinary frequency. Their value is the existence of a narrow, evidence-bound path when abnormal state occurs. Removal requires proof that the abnormal state is impossible or that another canonical recovery path provides the same authority and evidence contract.

### B: preserve unless semantic overlap and replacement are proven

The B tools represent user-visible or security-relevant authority boundaries: lifecycle close, irreversible deletion, device pairing, GUI process control, secret handling, interactive input and real device writes. Low frequency is expected for several of them. A future P9 reduction must compare authority and replacement semantics, not invocation counts.

### F: do not use M1 null usage as a removal signal

Ten iPad operations are classified as F because their domain action is read-only while the transport records a device job and receipt as an effect. Their placement in the mutating half of M1 is therefore useful for transport accounting but unsuitable as direct evidence that the public read operation is unused or redundant.

## P9 decision for this cohort

Do not remove, deprecate or merge any of these 32 tools on null-usage evidence alone.

A later C–E candidate must additionally prove:

1. semantic overlap with an existing canonical public path;
2. equivalent or narrower authority;
3. a working replacement call chain;
4. no loss of recovery or explicit user decision points;
5. compatibility impact and transition plan;
6. fresh usage evidence appropriate to the tool's actual domain semantics.

## Remaining evidence gap

The **104 read-only tools remain outside reliable usage measurement**. M1 states this explicitly as `read_only_tool_usage` evidence gap. Therefore this classification closes the null-usage review of the mutation-side cohort only; it does not authorize a whole-surface P9 reduction.

Until a trustworthy read-only evidence source exists, preserve read-only public paths unless redundancy is independently proven from semantics, call-chain analysis and replacement evidence.

# P9 mutation-tool classification — 2026-08-30

## Binding

- repository: `heimgewebe/grabowski`
- current-main revision: `30ccbe9b49f794fc4ffe1cbb2062e5d9fbf0dfca`
- M1 report SHA-256: `7105f30c7c11b40ecc19e9016436d1782f0464d135336d7dd8f91c556046c769`
- captured canonical report file SHA-256: `42ec390ffb18eb8151e66173272f98799a1b0b2085305f298f56a9d4b4537879`
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

## Canonical M1 report

The following JSON is the exact canonical analyzer output captured for this decision. It makes the audit-chain identity, observation/cutoff timestamps, admission counts and exact 32-tool null-usage input set repository-visible. To verify `report_sha256`, parse this object, remove its `report_sha256` member, encode it with the analyzer's `canonical_json_bytes` contract, and SHA-256 the result.

```json
{"audit":{"chain_content_sha256":"b1e7482b528901a08aa27f917f47cfdc3372680e232e1db73b47d4c8b67d6b79","chain_materialization_sha256":"ebcd82b74c2b784535f6fadccdca48fec399dc4ed4a2160b60d5f054974cb9ad","last_record_sha256":"ab48ce5c812f40a6dcd2dc2ceccce964f3147eedcb6cde56e22e9efff8caba13","segment_count":43,"total_records":673849},"authority":"derived_from_verified_grabowski_audit_chain","cutoff_unix":1787472044,"does_not_establish":["successful domain effects from admission counts","read-only tool usage or non-usage","tool redundancy","safe public tool removal","causality or user intent"],"effect_admission_count":71284,"evidence_gaps":[{"kind":"read_only_tool_usage","needed_for":"treating absence of a public tool from this report as evidence for P9 removal","reason":"The durable effect-admission audit records mutation admission, not ordinary read-only tool invocations."},{"kind":"mutation_tool_usage","needed_for":"classifying this mutation tool as observed or unobserved usage","reason":"Successful integrity repair deliberately bypasses transport roundtrip evidence, so it does not emit effect-admission; any admission count for this tool does not establish successful recovery mutation usage.","tool":"grabowski_recovery_provenance_repair"}],"kind":"grabowski_tool_surface_usage_v1","mutation_usage":{"observed_expected_tool_count":62,"observed_mutating_tool_count":61,"rare_mutation_tools":[{"count":1,"tool":"grabowski_agent_workspace_cleanup"},{"count":2,"tool":"grabowski_agent_workspace_writer_handoff"},{"count":2,"tool":"grabowski_browser_worker_stored_form_action"},{"count":2,"tool":"grabowski_checkout_binding_terminal_apply"},{"count":1,"tool":"grabowski_recovery_provenance_repair"},{"count":1,"tool":"grabowski_task_reconcile"},{"count":1,"tool":"grabowski_task_reconcile_resume"},{"count":1,"tool":"ipad_capability_manifest"}],"top_mutation_admissions":[{"count":39882,"tool":"grabowski_terminal_run"},{"count":8131,"tool":"grabowski_github"},{"count":6497,"tool":"grabowski_task_start"},{"count":4081,"tool":"grabowski_git"},{"count":2865,"tool":"grabowski_job_start"},{"count":1305,"tool":"grip_run"},{"count":1145,"tool":"grabowski_fleet_run"},{"count":969,"tool":"grabowski_resource_acquire"},{"count":803,"tool":"grabowski_bureau_candidate_record"},{"count":604,"tool":"grabowski_resource_release"},{"count":600,"tool":"grabowski_bureau_pickup_execute"},{"count":584,"tool":"grabowski_work_acquire"},{"count":475,"tool":"grabowski_create_text"},{"count":371,"tool":"grabowski_agent_competition_start"},{"count":356,"tool":"grabowski_bureau_task_propose"},{"count":353,"tool":"grabowski_replace_text"},{"count":297,"tool":"grabowski_power_run"},{"count":273,"tool":"grabowski_checkout_cleanup"},{"count":134,"tool":"grabowski_resource_renew"},{"count":115,"tool":"grabowski_friction_record"},{"count":112,"tool":"grabowski_browser_worker_semantic"},{"count":108,"tool":"grabowski_bureau_task_review"},{"count":108,"tool":"grabowski_bureau_task_publish"},{"count":107,"tool":"grabowski_remove_path"},{"count":94,"tool":"grabowski_job_cancel"},{"count":86,"tool":"grabowski_bureau_pickup_release"},{"count":84,"tool":"grabowski_reposkop_context"},{"count":74,"tool":"grabowski_runtime_deploy_schedule"},{"count":59,"tool":"grabowski_browser_worker_start"},{"count":56,"tool":"grabowski_checkout_archive"},{"count":55,"tool":"grabowski_text_artifact_publish"},{"count":54,"tool":"grabowski_task_cancel"},{"count":47,"tool":"grabowski_agent_workspace_create"},{"count":46,"tool":"grabowski_browser_worker_stop"},{"count":44,"tool":"grabowski_resource_nonconflict_assess"},{"count":43,"tool":"grabowski_resource_reconcile_obsolete_path_leases"},{"count":42,"tool":"grabowski_task_reconcile_refresh"},{"count":34,"tool":"grabowski_runtime_refresh_lease_release"},{"count":33,"tool":"grabowski_git_branch"},{"count":26,"tool":"grabowski_checkout_retain"},{"count":26,"tool":"grabowski_user_service"},{"count":23,"tool":"grabowski_friction_resolve"},{"count":11,"tool":"grabowski_secret_use"},{"count":10,"tool":"grabowski_artifact_push"},{"count":8,"tool":"grabowski_juno_run"},{"count":7,"tool":"grabowski_rollback_text"},{"count":6,"tool":"grabowski_process_signal"},{"count":6,"tool":"grabowski_merge_delivery_record"},{"count":5,"tool":"grabowski_recovery_server_probe"},{"count":5,"tool":"grabowski_task_routing_shadow_seal"},{"count":4,"tool":"grabowski_agent_workspace_collect"},{"count":4,"tool":"grabowski_operation_run"},{"count":3,"tool":"grabowski_artifact_pull"},{"count":3,"tool":"grabowski_execution_outcome_record"},{"count":2,"tool":"grabowski_agent_workspace_writer_handoff"},{"count":2,"tool":"grabowski_checkout_binding_terminal_apply"},{"count":2,"tool":"grabowski_browser_worker_stored_form_action"},{"count":1,"tool":"grabowski_task_reconcile"},{"count":1,"tool":"ipad_capability_manifest"},{"count":1,"tool":"grabowski_recovery_provenance_repair"},{"count":1,"tool":"grabowski_task_reconcile_resume"},{"count":1,"tool":"grabowski_agent_workspace_cleanup"}],"unexpected_admission_tools":[],"unobserved_mutating_tool_count":32,"unobserved_mutating_tools":["grabowski_agent_workspace_close","grabowski_agent_workspace_reconcile_idle_tmux","grabowski_agent_workspace_reconcile_stale","grabowski_agent_workspace_role_retry","grabowski_checkout_binding_identity_rebind_apply","grabowski_chronik_outbox_import","grabowski_destroy_path","grabowski_gui_worker_start","grabowski_gui_worker_stop","grabowski_job_notification_ack","grabowski_juno_pair","grabowski_operator_blockade_disarm","grabowski_operator_blockade_engage","grabowski_operator_blockade_migrate_legacy","grabowski_restore_removed_path","grabowski_secret_export","grabowski_secret_reveal","grabowski_task_resume","grabowski_tmux_send","ipad_bluetooth_inspect","ipad_bluetooth_read","ipad_bluetooth_scan","ipad_directory_list","ipad_file_create","ipad_file_read","ipad_file_replace","ipad_file_stat","ipad_native_permission_request","ipad_native_permission_status","ipad_permission_probe","ipad_storage_grant_status","ipad_storage_inventory"]},"observed_at_unix":1788076844,"repo_dirty":false,"repo_head":"30ccbe9b49f794fc4ffe1cbb2062e5d9fbf0dfca","report_sha256":"7105f30c7c11b40ecc19e9016436d1782f0464d135336d7dd8f91c556046c769","repository":"/home/alex/repos/.grabowski-worktrees/tool-surface-p9-classification-20260830","schema_version":1,"surface":{"declared_expected_tool_count":198,"expected_tool_count":198,"missing_declarations":[],"mutating_tool_count":94,"mutation_usage_gap_tool_count":1,"mutation_usage_gap_tools":["grabowski_recovery_provenance_repair"],"mutation_usage_measurable_tool_count":93,"read_only_tool_count":104,"staged_unpublished_tools":["grabowski_agent_workspace_adopt"],"unknown_annotation_tool_count":0,"unknown_annotation_tools":[]},"time_range_unix":{"maximum":1788076844,"minimum":1787472044},"tool_attribution_missing_count":0,"window_hours":168}
```

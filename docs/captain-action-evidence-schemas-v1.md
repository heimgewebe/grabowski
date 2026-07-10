# Captain action evidence schemas v1

Status: active
Bureau task: `GRIP-ROADMAP-V1-T012`

Captain action envelopes now expose an `evidence_schema` record. The schema is descriptive and binding-oriented: it tells the operator and downstream gates which evidence objects must be bound to the concrete action target before a future executor may mutate anything. It does not add deploy, restart, fleet, cleanup or secret authority.

Every schema has:

- `schema_version`: currently `1`.
- `action`: one of the Captain high-impact actions.
- `target_binding`: the concrete target fields that the evidence must refer to.
- `required_evidence`: evidence object names, required fields, exact required values, one-of alternatives, required top-level parameters, parameter-to-object hash bindings, conditional requirements, binding fields and purpose.
- `digest_bindings`: the common `actions_sha256`, `action_sha256` and `target_sha256` fields.
- `risk_binding`: whether the action requires a recovery path or irreversibility record.
- `does_not_establish`: non-claims preserved by the schema.

## Action requirements

- `pr-merge` binds `repo`, `pr`, `base`, `expected_head`, `diff_sha256`, `status_projection`, a passing `grabowski_self_review_audit` as `review_evidence`, `ci_evidence` and `human_authorization`. The self-review audit records risk-scaled review depth, terminal triage and exact repo/PR/head/diff binding without posting review prose to the PR. Status projection evidence requires one replay field (`receipt_ref`, `run_id` or `nonce`) and the top-level `status_projection_sha256` parameter covering the projection object. Manual authorization requires `authorized_by` plus either `statement` or `reference`.
- `runtime-deploy` binds the concrete `repo` or `service`, the concrete `environment` or `runtime_target`, `status_projection`, `deployment_boundary` and `rollback_plan`.
- `service-restart` binds `host`, `unit`, `status_projection`, `restart_budget` and `recovery_path`.
- `fleet-mutation` binds `fleet_target`, `operation`, `status_projection`, `dry_run_or_projection` and recovery or irreversibility evidence.
- `cleanup-apply` binds `cleanup_target` and every supplied concrete location (`repo`, `checkout_path` or both), plus `status_projection`, `dry_run_or_projection` and recovery or irreversibility evidence.

These schemas are intentionally not proof of semantic correctness, runtime safety or authorization. They are a typed contract for what evidence must say and bind to before a Captain execution path may be considered.

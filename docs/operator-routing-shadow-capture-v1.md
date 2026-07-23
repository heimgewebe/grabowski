# Operator Routing Shadow Capture v1

Status: core contract implemented; explicit local capture only

## Purpose

`OPERATOR-ML-READINESS-V1-T001` needs one trustworthy join between an eligible Grabowski task, canonical route evidence and either a reviewed semantic outcome or an explicit abstention. This contract creates that join without granting machine learning, Vibe-Lab or the capture tool any execution authority.

The machine-readable contracts are `contracts/operator-routing-shadow-eligibility.v1.schema.json` for the pre-outcome eligibility freeze and `contracts/operator-routing-shadow-record.v1.schema.json` for the sealed outcome record. The create-only implementation is `tools/operator_routing_shadow_capture.py`.

## Authority boundaries

The capture tool does not decide or reconstruct a route. It imports Grabowski's existing Agent Workspace route validator and accepts route evidence only after the deterministic policy replay and recommendation hash checks already enforced by `grabowski_agent_workspace._normalize_route_evidence()`.

A valid record states the following no-effect boundary literally:

- `proposal_only: true`
- `routing: false`
- `policy: false`
- `queue: false`
- `merge: false`
- `runtime: false`

The record is evidence for later Vibe-Lab analysis only. It cannot change the route used by Grabowski, mutate Bureau truth, authorize a merge or deployment, or become a runtime policy by existing.

## Prospective eligibility freeze and eligible-case identity

Capture is deliberately two-stage. `freeze` runs before outcome review and writes one create-only eligibility receipt containing the eligible case, canonical route reference, bounded pre-outcome features, `frozen_at` and the no-effect boundary. `seal` later consumes that immutable receipt plus the reviewed outcome or explicit abstention. It does not reread or reinterpret the live workspace manifest.

The final record requires `frozen_at <= outcome.observed_at <= captured_at`. This makes the experiment's prospective eligibility rule machine-checkable instead of relying on a later narrative claim.

Every eligibility receipt binds exactly one Grabowski task reference present in the source Agent Workspace manifest to exactly one canonical `recommendation_id`.

`case_id` is a deterministic SHA-256 over:

- schema version `1` of the case binding;
- the eligible Grabowski `task_id`;
- the canonical route `recommendation_id`.

The eligibility receipt separately stores SHA-256 identities for the normalized canonical route evidence and the complete source manifest. `eligibility_id` hashes the entire frozen eligibility payload. The final record copies the frozen bounded fields and binds them back to `eligibility_id`; any later field drift fails validation. Neither artifact copies the unrestricted manifest into the learning record.

## Canonical route evidence

Accepted route evidence must be readable by the current Grabowski validator and return:

- `status: verified`;
- `evidence_complete: true`.

Both legacy route schema 1 and current route schema 2 are supported, but their feature shapes remain separate. No semantic equivalence is invented between legacy `parallel_work` and the newer schema-2 concurrency or parallelization fields.

### Schema 1 bounded features

- `task_kind`
- `changed_file_estimate`
- `expected_duration_minutes`
- `novelty`
- `risk_flags`
- `connector_instability`
- `parallel_work`
- `user_requested_external`

### Schema 2 bounded features

- `task_kind`
- `changed_file_estimate`
- `expected_duration_minutes`
- `novelty`
- `risk_flags`
- `risk_tier`
- `connector_instability`
- `concurrent_external_activity`
- `parallelization_candidate`
- `decision_fork`
- `architecture_hypotheses`
- `user_requested_external`

`available_external_agents`, raw argv, prompts, transcripts, private notes and unrestricted manifest content are deliberately excluded from the shadow feature record.

## Semantic outcome and abstention

Task lifecycle state is not accepted as semantic correctness.

A non-abstaining record must carry a reviewed outcome with:

- `kind`: `task_correctness` or `decision_quality`;
- `label`: `success`, `partial` or `failure`;
- an observation timestamp;
- one bounded review authority;
- at least one primary evidence reference.

Permitted primary evidence reference classes are:

- `github-ci:`
- `diff-review:`
- `operator-decision:`
- `chronik:`
- `artifact:`

When no trustworthy semantic label exists, the record must abstain explicitly with one of:

- `no_semantic_review`
- `non_semantic_task`
- `insufficient_primary_evidence`
- `ambiguous_outcome`

An abstention is preserved as missing label information. It is not converted into failure or success.

## Integrity and privacy

The tool fails closed when:

- the task id is not referenced by the source manifest;
- route evidence is missing, incomplete, malformed or fails deterministic replay;
- an outcome has an unknown shape or value;
- a reviewed outcome has no primary evidence reference;
- the eligibility, record or case hash does not match its canonical payload;
- an outcome is observed before `frozen_at` or after `captured_at`;
- the no-effect boundary is altered;
- unknown top-level fields are added;
- input or output paths traverse symlink components;
- an output path already exists.

Records are written create-only with mode `0600`. The output contains bounded allowlisted fields and hashes, not unrestricted source payloads.

## Invocation surface

The core slice is an explicit local two-stage tool.

### 1. Freeze eligibility before outcome review

`freeze` requires:

- `--manifest`: one Agent Workspace `manifest.json`;
- `--task-id`: one task referenced by that manifest;
- `--output`: a new eligibility receipt path;

It writes one create-only `operator-routing-shadow-eligibility.v1` receipt with mode `0600`. `frozen_at` is generated by the capture tool; the operational CLI does not accept a caller-supplied backdated timestamp.

### 2. Seal the independently observed outcome

`seal` requires:

- `--eligibility`: the previously frozen eligibility receipt;
- `--outcome`: a JSON object containing exactly `outcome` and `primary_evidence_refs`;
- `--output`: a new final record path;

It writes one create-only `operator-routing-shadow-record.v1` object with mode `0600` and refuses overwrite. `captured_at` is generated by the sealing tool; the operational CLI does not accept a caller-supplied timestamp. The sealed record is valid only when its embedded frozen fields reproduce the referenced `eligibility_id`.

## Current limitation

This core contract does not register a new MCP tool, alter the Grabowski runtime surface or automatically harvest records. Runtime exposure and automated prospective cohort capture remain separate follow-up work and must preserve the same no-effect, privacy and authority boundaries.

The existence of this core contract therefore establishes a safe prospective eligibility freeze, a deterministic create-only sealing path and an explicit abstention path. It does **not** by itself establish that the readiness cohort is sufficiently complete, representative or semantically labeled for supervised routing training.

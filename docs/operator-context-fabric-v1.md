# Operator Context Fabric V1

The Operator Context Fabric is a compact read-only composition surface. It binds observations that existing Grabowski authorities have already produced to one explicit target, labels each of them with the authority that owns the truth, and returns a sealed context. It owns no lifecycle truth of its own.

The pilot covers exactly three profiles: `pr`, `bureau` and `deployment`. No fourth profile exists, and the surface refuses any profile name outside that set.

## What the fabric is not

- It is not a memory database. Nothing is stored, indexed or carried between calls.
- It is not chat persistence. Free-form notes are rejected; every observation field is allowlisted.
- It is not a write-back path. No authority is updated, no receipt is published, no file is touched.
- It is not a policy or routing authority. It grants no merge, deployment, pickup, retry or publication permission.
- It never returns secret content.

`grabowski_context_fabric_compose` performs no I/O at all. It is a pure function of its arguments, which is what makes its results deterministic and hash-bindable.

## Authorities are preserved, not copied

The fabric does not read GitHub, Bureau or the runtime. The caller reads those surfaces with the existing typed tools and passes the result back as bounded observations. Each observation must name its `source_tool`, and the fabric maintains a fixed registry that declares, per source:

- the `authority` label and the `truth_owner`,
- the profiles the source may serve,
- the exact `claim_type` values that authority is allowed to establish,
- whether the source is historical or live,
- its sensitivity ceiling,
- what the source explicitly does not establish.

An observation that claims a `claim_type` its declared authority does not own is rejected. This is the mechanism that stops the fabric from promoting one authority's statement into another's domain.

| Profile | Required authority | Optional authorities |
|---|---|---|
| `pr` | `grabowski_github_pr_view` | `grabowski_github_checks`, `grabowski_git_status`, `grabowski_chronik_history` |
| `bureau` | `grabowski_bureau_pickup_status` | `grabowski_bureau_candidate_assess`, `grabowski_bureau_task_publish_preview`, `grabowski_chronik_history` |
| `deployment` | `grabowski_deployment_identity` | `grabowski_runtime_health`, `grabowski_service_status`, `grabowski_contract_drift`, `grabowski_chronik_history` |

## Claim shape

Every emitted claim carries `claim_type`, `authority`, `authority_tool`, `truth_owner`, `scope`, `binding`, `binding_sha256`, `temporal_marker`, `observed_at` or the historical marker, `age_seconds`, `status`, `freshness`, `observation_requirement`, `sensitivity`, `evidence_refs`, `conflicts` and `does_not_establish`. A claim without at least one concrete evidence reference is rejected.

`temporal_marker` is `observed` for live sources and `historical` for Chronik-backed sources. A historical observation may not carry `observed_at`, and a live observation must carry one. An `observed_at` later than the caller-supplied `as_of` is rejected rather than silently accepted.

Freshness is derived from `as_of` and the profile's declared bands, never from a hidden clock:

| Profile | `fresh` up to | `aging` up to | beyond |
|---|---:|---:|---|
| `pr` | 900 s | 3600 s | `stale` |
| `bureau` | 600 s | 1800 s | `stale` |
| `deployment` | 300 s | 900 s | `stale` |

Historical claims are always `historical` and never `fresh`. Every live claim also derives an `observation_requirement` from the same profile bands: `observed` through the fresh boundary, `due` between the fresh and aging boundaries, and `missed` beyond the aging boundary. `due_at`, `missed_after` and bounded `overdue_seconds` make that transition explicit without adding a scheduler or persistent state.

The context additionally emits `observation_adherence` for **required** authorities only. It uses the newest accepted observation for each required source, reports `observed`/`due`/`missed` counts and an `observed_ratio` for the current bounded context. This is not a historical success rate. Optional stale evidence remains visible and labelled stale; it never blocks merely because it is old. A required authority that reaches `missed` does fail composition closed, because the owning source must be re-read before the context can support an effect decision.

## Fail-closed behaviour

Composition fails closed, returning `composed=false`, an empty `claims` list and a machine-readable `failure.code`, when:

- a required binding field for the profile is missing (`missing_required_binding_fields`),
- a required authoritative source produced no accepted observation (`missing_required_authoritative_sources`),
- the newest accepted observation from a required authority is beyond the profile aging boundary (`stale_required_authoritative_observations`),
- the claim budget cannot carry every required authority (`claim_budget_excludes_required_authority`).

A fail-closed context keeps the most restrictive sensitivity ceiling. Structurally invalid input — an unknown profile, a malformed timestamp, an out-of-range budget or a payload key that could carry a secret — raises instead of producing a partial result. A single malformed observation inside an otherwise valid call is not fatal: it is dropped into `rejected_observations` with a bounded reason, and the fail-closed checks then decide whether the remaining evidence is sufficient.

## Contradictions are preserved

Claims are grouped by `claim_type` and `scope`. When a group holds more than one distinct assertion, every claim in that group keeps its own value and lists the contradicting claim ids in `conflicts`. The context reports `contradictions`, `contradiction_count` and `conflict_resolution="not_performed"`. The fabric never picks a winner, never orders authorities by trust and never drops the minority statement.

## Secret boundary

Evidence references use a closed key allowlist (`type`, `id`, `repo`, `url`, `sha256`, `head_sha`) and a closed type allowlist. `repo` and digest fields are format-checked, URLs must use HTTPS, and local filesystem paths or `file:` URLs are not accepted. Before any parsing, the whole payload is scanned for keys that could carry secret material (`token`, `secret`, `password`, `credentials`, `authorization`, `value`, `content` and similar); such a payload is rejected outright. No declared source may exceed the `internal_operational` sensitivity ceiling, and `secret_content_returned` is a constant `false`.

## Tools

- `grabowski_context_fabric_plan` — answers which binding fields and which authorities a profile requires, before any source has been read. It composes nothing.
- `grabowski_context_fabric_compose` — validates, binds, labels, derives required-authority observation adherence, packs and seals one context. `claim_budget` bounds the packed size; dropped optional claims are reported, a missed required observation fails closed, and a budget too small for the required authorities fails closed.
- `grabowski_context_fabric_explain` — verifies the context digest and explains, per claim, why it was included, which authority owns it, how fresh it is, which claims contradict it and which surface must be re-read before acting.
- `grabowski_context_fabric_compare` — verifies both digests and reports added, removed and changed claims for one identical target binding. Different profiles or different bindings are not comparable and fail closed. The comparison explicitly does not establish progress, regression or approval to proceed.

## Sealing and reuse

Every context carries `context_sha256`, the canonical digest of all of its other fields. `explain` and `compare` recompute that digest and refuse to work on a modified context, so a context cannot be edited between composition and interpretation.

The digest is a self-consistency binding, not a signature. It detects accidental modification only when its expected value is held separately; anyone can recompute it. It does not authenticate the producer, attest that the underlying sources were authentic or make an observation current again. `explain` therefore never trusts a context's own labelling for the parts it can derive itself: the inclusion reason is recomputed from the profile's source registry rather than copied.

## Acting on a context

A context is evidence for a decision, not permission for an action. A `due` required observation is an explicit warning but may still compose; a `missed` required observation prevents composition until the owning authority is re-read. Before any effect, re-read the owning authority named in `reread_before_acting` and pass the normal authorization gates. Every claim repeats this boundary in its own `does_not_establish` list, which always includes `lifecycle_truth_ownership`, `current_truth_after_observation`, `merge_readiness`, `deployment_authorization`, `bureau_publication_authority`, `task_completion`, `policy_change`, `routing_authority`, `retry_permission`, `secret_content_access`, `global_operator_memory`, `chat_persistence` and `write_back_to_any_authority`.

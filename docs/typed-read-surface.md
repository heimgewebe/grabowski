# Typed Read Surface

Status: typed read tools implemented; publication profiles remain a design and evaluation mechanism.

## Motivation

Legitimate diagnostics previously depended on generic tools whose static MCP annotation must cover both reads and mutations. A fixed repository status query performed through a tool that can also change history is still presented as a mutating operation. Service inspection had the same ambiguity when status and restart shared one tool.

The typed read surface removes that ambiguity without removing existing operator capability.

## Invariants

1. Existing generic operator tools remain available as fallback tools.
2. Typed read tools accept no arbitrary argv or shell fragments.
3. Local reads are annotated read-only, non-destructive, idempotent, and closed-world.
4. GitHub reads are read-only and idempotent but open-world because they contact an external service.
5. Git reads disable pagers, prompts, external diff commands, text conversion, hooks, and file-protocol access where applicable.
6. Outputs are bounded and redacted.
7. This change does not register a second connector.

## Narrow context tools

- `grabowski_runtime_health`
- `grabowski_deployment_identity`
- `grabowski_contract_drift`
- `grabowski_checkout_summary`

These tools replace broad context retrieval when only health, identity, drift, or checkout state is required.

## Repository read tools

- `grabowski_git_status`
- `grabowski_git_diff`
- `grabowski_git_log`
- `grabowski_git_show`

Command shapes are fixed. Revisions are validated and option injection is rejected. Diff and show disable external helpers and text conversion.

## GitHub read tools

- `grabowski_github_pr_view`
- `grabowski_github_checks`

JSON fields are fixed. Pull-request bodies, comments, reviews, and caller-selected fields are excluded.

## Service read tools

- `grabowski_service_status`
- `grabowski_service_logs`

Status uses a fixed `systemctl show` property set. Logs use bounded user-journal output. Neither operation can change unit state.

## Selection rule

Use the narrowest typed read tool that answers the question. Use a generic operator tool only when no typed operation expresses the required action. Repeated identical failures are recorded and reviewed rather than automatically retried.

## Publication profiles

Profiles are projections of the single canonical tool contract in `config/runtime-entrypoint.json` and its generated capability catalog. The deterministic projection is stored in `contracts/publication-profiles.v1.json` and checked by `make profiles-check`. Profiles are not separate backend implementations.

### `full`

Select every tool in `expected_tools`. This is the current surface.

### `core`

Derive a conservative canary surface using all of these predicates:

- `read_only == true`
- `risk_class` is `low` or `medium`
- category is not `secret`
- declared effects are empty or only `remote-read`
- broad legacy context tools, browser-profile reading, and privileged-reference creation are excluded explicitly

The projection retains narrow health and drift checks, repository inspection, bounded pull-request inspection, service observation, task logs and lists, audit verification, and other operations whose catalog declares no state-changing effect. It excludes read-annotated tools that refresh persistent state, reconcile leases, or create reference records. It also excludes `grabowski_status` and `grabowski_context`; the narrow context tools replace them in the canary.

### `operator`

Select every canonical tool not selected by `core`, plus `grabowski_runtime_health` and `grabowski_contract_drift` for orientation. This projection contains mutations, state-refreshing observations, broad context, and generic fallback tools and is not intended as the default diagnostic surface.

## Canary decision gate

A separate `Grabowski Core` connector may be registered only as a reversible canary after the typed read surface is deployed. It does not replace the full operator initially.

For matched legitimate read tasks, compare:

- upstream block rate
- connector-session termination rate
- successful completion rate
- incorrect tool-selection rate
- median number of tool calls
- maintenance and snapshot drift

Each matched case is attempted once per surface. A durable second connector is justified only when the core projection materially improves successful completion without significant selection or maintenance drift.

## Epistemic limit

The platform's internal classification reason and account-level risk state are not observable from the local runtime. This architecture improves semantic correctness and measurement, but it cannot guarantee a particular upstream decision.

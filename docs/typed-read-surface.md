# Typed Read Surface

Status: typed read tools implemented and hardened; publication profiles remain generated projections and a separate Core connector remains canary-gated.

## Motivation

Legitimate diagnostics previously depended on generic tools whose static MCP annotation had to cover reads and mutations together. A fixed repository status query performed through a tool that can also rewrite history is still presented to the client as a mutating operation. Service inspection had the same ambiguity when status and restart shared one tool.

The typed read surface removes that ambiguity without removing operator capability.

## Invariants

1. Existing generic operator tools remain available in the full surface.
2. Typed read tools accept no arbitrary argv or shell fragments.
3. Local reads are read-only, non-destructive, idempotent and closed-world.
4. GitHub reads are read-only and idempotent but open-world because they contact an external service.
5. Git reads disable prompts, pagers, optional locks, filesystem monitors, hooks, external diff commands, text conversion and file-protocol access where applicable.
6. Process output is bounded while pipes are drained; it is not collected without limit and clipped afterwards.
7. Numeric and string bounds are present in the MCP input schemas, not only checked after invocation.
8. This change does not register a second connector.

## Narrow context tools

- `grabowski_runtime_health`
- `grabowski_deployment_identity`
- `grabowski_contract_drift`
- `grabowski_checkout_summary`

These replace broad context retrieval when only health, identity, drift or checkout state is required.

`grabowski_status` additionally returns a live tool-contract summary with expected and registered counts, name-set hashes and bounded missing/unexpected lists. The runtime cannot inspect ChatGPT's frozen connector snapshot, but a client can compare its loaded tool count or hash with this summary and detect that a refresh is required.

## Repository read tools

- `grabowski_git_status`
- `grabowski_git_diff`
- `grabowski_git_log`
- `grabowski_git_show`

Command shapes are fixed. `git show` validates the caller input, resolves it with `rev-parse --verify --end-of-options` to exactly one object ID and displays that ID. Revision ranges and other multi-object selections therefore cannot expand silently.

Diff and show disable external helpers and text conversion. Git reads run with `GIT_OPTIONAL_LOCKS=0` and `core.fsmonitor=false`, preventing ordinary diagnostics from refreshing the index or invoking a configured filesystem monitor.

## GitHub read tools

- `grabowski_github_pr_view`
- `grabowski_github_checks`

JSON fields are fixed. Pull-request bodies, comments, reviews and caller-selected fields are excluded. Valid JSON is retained even when `gh pr checks` uses a nonzero status to represent pending or failing checks.

## Service read tools

- `grabowski_service_status`
- `grabowski_service_logs`

Status uses a fixed `systemctl show` property set. Logs use bounded, redacted user-journal output. Neither operation can change unit state.

## Selection rule

Use the narrowest typed read tool that answers the question. Use a generic operator tool only when no typed operation expresses the required action. Repeated identical failures are recorded and reviewed rather than retried through a disguised broader command.

## Publication profiles

Profiles are deterministic projections of the single canonical tool contract in `config/runtime-entrypoint.json` and its generated capability catalog. The generated result is stored in `contracts/publication-profiles.v1.json` and checked by `make profiles-check`. Profiles are not separate backend implementations.

### `full`

Select every tool in `expected_tools`. It retains all generic reads, mutations and escape hatches.

### `core`

The Core canary uses all of these predicates:

- the tool belongs to an explicit 17-tool Canary set
- `read_only == true`
- `risk_class` is `low` or `medium`
- declared effects are empty or only `remote-read`

The explicit set prevents a newly added tool from entering Core merely because it shares a category. Generic filesystem reading, tmux capture, process inventory, job/task logs, operation plans, resources, artifacts and browser/GUI worker inventory are intentionally absent. Core retains audit verification, narrow runtime and deployment identity, contract and checkout drift, typed Git and GitHub reads, service status/logs, ports, fleet identity, privileged-broker status and recovery status. The current projection contains 17 tools.

### `operator`

Select every canonical tool not selected by Core, plus `grabowski_runtime_health` and `grabowski_contract_drift` for orientation. It contains mutations, state-refreshing observations, broad context and generic fallback tools.

## Delayed self-deployment

`grabowski_runtime_deploy_schedule(expected_head, delay_seconds=8)` is an operator-only mutation. It accepts no repository path or arbitrary command. Before scheduling it verifies:

- the fixed canonical checkout exists without path indirection,
- `HEAD` equals the caller-bound object ID,
- the checkout is on `main`,
- `origin/main` equals the same object ID,
- the worktree is clean,
- the versioned runner exists as a regular file.

The tool starts an independent durable systemd job and returns its unit and log paths before the runner's delay expires. The runner then rechecks the repository, runs `make validate`, rechecks drift, runs the atomic deployment and verifies the resulting live manifest. Operator and tunnel may restart without terminating the deployment job. Existing `grabowski_job_status` and `grabowski_job_logs` provide post-reconnect evidence.

## Canary decision gate

A separate `Grabowski Core` connector may be registered only as a reversible canary. For matched legitimate read tasks compare:

- upstream block rate
- connector-session termination rate
- successful completion rate
- incorrect tool-selection rate
- median number of tool calls
- maintenance and snapshot drift

Each matched case is attempted once per surface. A durable second connector is justified only when Core materially improves successful completion without significant selection or maintenance drift.

## Epistemic limit

The platform's internal classification reason and account-level risk state are not observable from the local runtime. This architecture improves semantic correctness, resource bounds and measurement, but it cannot guarantee a particular upstream decision.

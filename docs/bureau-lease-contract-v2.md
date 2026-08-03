# Bureau lease contract v2 consumer

Grabowski treats Bureau as an always-open coordination node. Resource acquisition and renewal
apply the deployed Bureau lease contract before opening the resource SQLite transaction.

## Scope

The consumer applies to:

- `repo:/home/alex/repos/bureau`;
- paths inside `/home/alex/repos/bureau`;
- linked worktree paths inside `/home/alex/repos/.bureau-worktrees`;
- `service:bureau-status-capsule`.

Other repositories retain the normal typed-resource contract.

## Rules

- Normal Bureau work uses exact object, file or component keys.
- The broad Bureau repository key is refused for normal work and cannot be renewed.
- Worktree administration and main merge use their dedicated gates with a maximum TTL of
  300 seconds.
- Broad-key emergency recovery requires `bureau_phase=emergency-recovery`, an explicit
  `bureau_justification`, an expected head or state, and a maximum TTL of 300 seconds. It is
  exclusive against every active Bureau lease, including leases held by the same owner.
- Contract unavailability, timeout, invalid JSON, wrong schema, changed release components, mismatched
  resource set, canonical gate keys, phase, TTL or recovery boundary, and unhealthy findings all fail
  closed before SQLite mutation.
- The canonical `venv-<40-hex-commit>` release, Python interpreter, `pyvenv.cfg`, CLI module and
  lease-contract module are hash-bound before and after execution; the child imports the exact bound
  modules in isolated mode.
- Merge, worktree-admin and broad emergency leases are non-renewable. Reacquiring the same active
  gate as the same owner is also rejected, so every effect requires a genuinely new contract check.
- Canonical Bureau repository, worktree and runtime roots are compiled into the deployed consumer and cannot be redirected by process environment.
- Release remains available so obsolete or invalid leases can always be removed.

Recovery justification and expected-state text are SHA-256-tokenized before subprocess invocation
and before persistence. Public results and audit records contain only contract hashes and finding
codes.

## Metadata

`grabowski_resource_acquire` accepts these Bureau-specific metadata fields:

- `bureau_phase`: `work`, `worktree-admin`, `merge`, or `emergency-recovery`;
- `bureau_justification`;
- `bureau_expected_head`;
- `bureau_expected_state`.

The phase is inferred for the merge and worktree-admin gate. A conflicting explicit phase is
rejected. Merge and worktree-admin gates cannot be acquired together.

## Runtime-refresh terminal lease release

A Bureau runtime refresh owns exactly five canonical path leases: the installed `bureau` and
`bureau-runtime-refresh` entrypoints, the immutable Bureau prefix, the canonical runtime-refresh
state root, and the commit-bound workspace. Those leases may be released only through
`runtime-refresh-lease-release` or the equivalent typed MCP tool
`grabowski_runtime_refresh_lease_release`.

The caller supplies only the observation target SHA-256 and the terminal result SHA-256. Grabowski
reads the private, owner-only receipts below the compiled canonical state root
`~/.local/state/bureau/runtime-refresh` and derives the owner, task, resources and lease snapshots
from them. It verifies the observation, target, intent, attempt-start, terminal result, merge commit,
source identity, installed-runtime readback, resource database identity and all five snapshots before
opening the release transaction.

Release is permitted for:

- `deployed` with `effect_started=true` and a valid source/readback binding;
- `already_current` with `effect_started=false`;
- `failed` with `effect_started=false` and a structured pre-effect error.

`unclear`, missing or ambiguous receipts, digest drift, a noncanonical state root, inconsistent
timestamps, changed lease snapshots and foreign replacement owners fail closed. Changed or foreign
rows remain leased and are reported as retained; no force-release path is used. Replaying a valid
terminal receipt is idempotent because already absent rows are returned without mutation.

The historical pre-approval cutover format is accepted only when its digest-bound intent has no typed
runtime approval fields, the aggregate resource schema is version `3`, and the lease-contract field
is absent. New typed intents require resource lease contract version `1`.

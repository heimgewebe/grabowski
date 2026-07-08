# Non-Heimserver Recovery Boundary

## Status

Accepted for Grabowski PR #107.

## Context

Grabowski can be runtime-healthy while high-impact recovery-gated paths remain blocked. Runtime health, audit validity, deployment provenance and connector/tool visibility do not prove backup restoreability.

The default recovery evidence path is Heimserver-backed:

- `GRABOWSKI_SERVER_RECOVERY_HOST=heimserver`
- `GRABOWSKI_SERVER_RECOVERY_TARGET=heimserver:rest-server/grabowski-recovery-probe`

When Heimserver is unavailable, this path must stay fail-closed. Do not run Heimserver probes merely to make the gate green.

## Decision

`grabowski_recovery_status` reports a separate `recovery_evidence_boundary` object. The boundary is an explanation and diagnostic surface; it does not activate recovery, power-worker or privileged paths.

Fresh server recovery evidence is valid only for the currently configured recovery target. A fresh marker for one target does not authorize another target.

Server recovery evidence is accepted only if all of the following are true:

1. The server recovery marker is formally valid and fresh.
2. The marker records a successful backup snapshot.
3. The marker records restore sentinel validation.
4. The marker records a repository check.
5. The marker target exactly matches the current `GRABOWSKI_SERVER_RECOVERY_TARGET`.
6. `grabowski_recovery_status` reports `checks.server_recovery_fresh=true`.

A configured non-Heimserver target alone is not enough. Fresh backup, restore and repository-check evidence against that exact target is required.

## Heimserver backend detection

Grabowski does not use free substring matching for Heimserver detection.

Default-Heimserver backends are detected by exact host alias matching:

- Alias env: `GRABOWSKI_HEIMSERVER_RECOVERY_ALIASES`
- Default alias list: `heimserver`
- Format: comma-separated host aliases
- Matching inputs:
  - normalized `GRABOWSKI_SERVER_RECOVERY_HOST`
  - normalized host part of `GRABOWSKI_SERVER_RECOVERY_TARGET`

Examples:

- `heimserver` matches by default.
- `non-heimserver-backup` does not match by default.
- `heimserver-prod` matches only if explicitly listed, for example `GRABOWSKI_HEIMSERVER_RECOVERY_ALIASES=heimserver,heimserver-prod`.

## Operational meaning

If the default Heimserver backend is configured and no fresh matching server recovery marker exists, `grabowski_recovery_status` must report the boundary explicitly:

- `recovery_evidence_boundary.uses_default_heimserver_backend=true`
- `recovery_evidence_boundary.custom_recovery_target_configured=false`
- `recovery_evidence_boundary.status=blocked_on_default_heimserver_or_alternate_recovery_target`
- `ready_for_user_power_worker=false`
- `ready_for_privileged_actions=false`

If a custom recovery target is configured but no fresh matching marker exists, the status remains fail-closed:

- `recovery_evidence_boundary.custom_recovery_target_configured=true`
- `recovery_evidence_boundary.status=blocked_until_configured_target_probe_succeeds`
- `ready_for_user_power_worker=false`
- `ready_for_privileged_actions=false`

If a marker is fresh but belongs to a different target, it is rejected:

- `server_recovery.target_matches_configured=false`
- `server_recovery.error=server recovery target does not match configured target`
- `checks.server_recovery_fresh=false`

## Alternatives considered

- **Substring detection for Heimserver-like names:** rejected. It would classify names such as `non-heimserver-backup` incorrectly.
- **Configured custom target unlocks the gate:** rejected. Configuration is not evidence.
- **Runtime health as recovery readiness proxy:** rejected. It conflates service liveness with restoreability.
- **Dataclass-only boundary object:** deferred. The MCP surface is JSON-like, and this PR keeps the output as a dict while adding constants and tests. A dataclass can be introduced later if the boundary grows.

## Non-claims

This boundary does not establish:

- that the Runtime is broken when recovery is stale,
- that a stale marker can authorize privileged actions,
- that a configured non-Heimserver target is valid before a restore probe succeeds,
- that server recovery evidence for one target authorizes another target,
- that Heimserver should be probed while it is known unavailable.

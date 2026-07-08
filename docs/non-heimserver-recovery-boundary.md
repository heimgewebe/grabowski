# Non-Heimserver Recovery Boundary

## Decision

Grabowski may be healthy while high-impact recovery-gated paths remain blocked. Runtime health, audit validity and connector/tool visibility do not prove backup restoreability.

The current default recovery evidence path is Heimserver-backed:

- `GRABOWSKI_SERVER_RECOVERY_HOST=heimserver`
- `GRABOWSKI_SERVER_RECOVERY_TARGET=heimserver:rest-server/grabowski-recovery-probe`

When Heimserver is unavailable, this path must stay fail-closed. Do not run Heimserver probes merely to make the gate green.

## Accepted evidence path without Heimserver

A non-Heimserver target is acceptable only if all of the following are true:

1. Grabowski is configured with a non-Heimserver `GRABOWSKI_SERVER_RECOVERY_HOST` and `GRABOWSKI_SERVER_RECOVERY_TARGET`.
2. The fixed SSH-tunnelled Restic probe runs against that target.
3. The probe writes a fresh server recovery marker.
4. The marker records a successful backup snapshot, restore sentinel validation and repository check.
5. `grabowski_recovery_status` reports `server_recovery_fresh=true`.

A configured non-Heimserver target alone is not enough. Fresh backup, restore and repository-check evidence is required.

## Current operational meaning

If the default Heimserver target is still configured and no fresh server recovery marker exists, `grabowski_recovery_status` must report the boundary explicitly:

- `recovery_evidence_boundary.requires_heimserver=true`
- `recovery_evidence_boundary.status=blocked_on_heimserver_or_alternate_recovery_target`
- `ready_for_user_power_worker=false`
- `ready_for_privileged_actions=false`

This means: runtime/tool health may be green, but high-impact paths remain blocked until either Heimserver recovery evidence is fresh again or a non-Heimserver target is configured and proven.

## Non-claims

This boundary does not establish:

- that the Runtime is broken when recovery is stale,
- that a stale marker can authorize privileged actions,
- that a non-Heimserver target is valid before a restore probe succeeds,
- that Heimserver should be probed while it is known unavailable.

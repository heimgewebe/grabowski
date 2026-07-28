# Runtime deployment admission drain v1

## Purpose

A Grabowski self-deployment must not depend on the operator manually keeping every connector quiet. The deployment path therefore separates three different signals:

1. the deployment lock serializes deployment mutations;
2. the operator admission gate stops new MCP tool calls before tool execution while existing calls finish;
3. tunnel queue and conserved command counters prove that no accepted command remains unfinished before services stop.

`dispatcher_worker_pool_occupancy` remains visible only as diagnostic pool capacity. The running tunnel-client uses `ants.Pool.Running()`, which counts live worker goroutines even while they are parked idle. It is not in-flight command authority.

## Marker contract

The deployer creates `~/.local/state/grabowski/deployment-admission-drain.json` with create-only semantics, mode `0600`, no symlink following, one link, owner UID binding, a maximum thirty-minute lifetime and exact fields for token, expected repository head, source-identity digest and timestamps. Its lifetime is derived from all six dynamic deployment/recovery waits, six stop operations, four start operations, twelve bounded systemd-query windows and a 120-second recovery margin. Deploy timeouts above 120 seconds or a derived lifetime above thirty minutes are rejected before publication. Existing active, malformed or foreign markers fail closed. Expired valid markers may be removed only through the same token-, identity- and inode-bound release path.

The operator reads the marker at the FastMCP tool-call boundary. It increments an active-call counter before reading the marker, so a call cannot slip between the drain decision and accounting. Active or invalid markers reject new tool calls before the registered tool function runs. Calls already admitted continue and decrement the counter on completion.

The loopback-only `/_grabowski/deployment-admission` route exposes bounded marker state and the active-call count for the deployment process. HTTP 404 alone means that the predecessor runtime predates this contract. Transport errors, malformed responses and other status codes are failures, not compatibility signals.

## Deployment sequence

1. Build and validate the exact source snapshot.
2. Re-read source and host-asset identity.
3. Create the source-bound admission marker.
4. Require two operator samples with the exact token, head and source digest and zero active tool calls.
5. Require tunnel queue zero and `polled == enqueued == final responses`. Counters may advance only in balanced form while the admission gate rejects new tool effects.
6. Re-run operator and tunnel final guards immediately before service stop.
7. Stop tunnel, then operator; activate and start the replacement operator.
8. Require the replacement operator to attest the exact active marker before the tunnel starts and again immediately after tunnel startup.
9. Release the marker only after the new runtime is healthy and identity-bound; marker absence is drift, never success.

The first deployment from a predecessor runtime uses the legacy stable-counter drain only after the status route explicitly returns 404. Transient transport failures are retried for up to the smaller of the deployment timeout and thirty seconds; they never establish legacy compatibility. If no explicit 404 or valid admission response becomes observable inside that bound, deployment fails closed before service stop. Every later deployment uses the admission-aware path.

## Failure and rollback

Before service stop, failure releases the exact marker and leaves the healthy runtime untouched. After service stop, rollback restores the previous pointer and operator, then requires that restored operator to attest the exact active marker before the tunnel may restart. A predecessor runtime without the admission contract therefore remains fail-closed with both the tunnel and restored loopback operator stopped instead of admitting work during an incomplete rollback. Only a marker-aware, identity- and readiness-verified rollback may release the marker. Missing or drifted markers are failures, not successful cleanup.

## Non-claims

The admission marker does not authorize deployment, bypass the deployment lock, prove connector delivery, cancel accepted commands, kill workers, or weaken review, recovery, kill-switch or privileged-execution gates. A scheduled deployment receipt still does not prove completion; exact runtime identity and health readback remain required.

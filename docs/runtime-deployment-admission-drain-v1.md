# Runtime deployment admission drain v1

## Purpose

A Grabowski self-deployment must not depend on the operator manually keeping every connector quiet. The deployment path therefore separates three different signals:

1. the deployment lock serializes deployment mutations;
2. the operator admission gate stops new MCP tool calls before tool execution while existing calls finish;
3. tunnel queue and conserved command counters prove that no accepted command remains unfinished before services stop.

`dispatcher_worker_pool_occupancy` remains visible only as diagnostic pool capacity. The running tunnel-client uses `ants.Pool.Running()`, which counts live worker goroutines even while they are parked idle. It is not in-flight command authority.

## Marker contract

The deployer creates `~/.local/state/grabowski/deployment-admission-drain.json` with create-only semantics, mode `0600`, no symlink following, one link, owner UID binding, a maximum thirty-minute lifetime and exact fields for token, expected repository head, source-identity digest and timestamps. Its lifetime is derived from all six dynamic deployment/recovery waits, six stop operations, four start operations, twelve bounded systemd-query windows and a 120-second recovery margin. Deploy timeouts above 120 seconds or a derived lifetime above thirty minutes are rejected before publication. Existing active, malformed or foreign markers fail closed. Expired valid markers may be removed only through the same token-, identity- and inode-bound release path.

The operator reads the marker at the FastMCP tool-call boundary. Normal calls increment an active-call counter before the marker decision, so a call cannot slip between drain admission and accounting. Active or invalid markers reject them before the registered tool function runs. Calls already admitted continue and decrement the counter on completion.

## Bound deployment observer

`grabowski_runtime_deploy_schedule` may issue one short-lived random observer capability for the newly created deployment job. Only its SHA-256 digest is stored in durable job metadata. The contract also binds the exact job unit, operation `grabowski_job_status`, expected head, source-identity digest, argv digest, origin digest, issue and expiry timestamps and, when FastMCP exposes one, the requesting client identifier. The raw capability is returned only in the schedule result and cannot be recovered from job state after loss or expiry.

Before the admission marker exists, the exact capability-bound status call remains a normal counted read. This lets the deployer wait for any already-running observation before entering the drain and prevents an old capability from becoming neutral during a later deployment. Once the marker is active, the call becomes drain-neutral only with a create-only `0600` activation record in the exact job directory. That record is bound to the current marker token, job contract, head, source identity and the shorter of marker and capability lifetimes. The marker remains the only admission truth; the activation record is evidence for one observer operation and cannot admit work.

A wrong, expired, reused, foreign-job, foreign-client, head-drifted, source-drifted, argv-drifted, origin-drifted or non-allowlisted request follows the normal admission path. During an active drain it is counted and rejected. Other read-only tools, mutating tools, job logs and watchdog-generated markers receive no exemption. Missing or malformed activation evidence also fails closed. The status response remains job-, release- and receipt-bound and does not claim deployment success before final runtime readback.

The loopback-only `/_grabowski/deployment-admission` route exposes bounded marker state and the active-call count for the deployment process. HTTP 404 alone means that the predecessor runtime predates this contract. Transport errors, malformed responses and other status codes are failures, not compatibility signals.

## Deployment sequence

1. Build and validate the exact source snapshot.
2. Re-read source and host-asset identity.
3. Create the source-bound admission marker and, only for an exactly bound scheduled job, its observer activation record.
4. Require two operator samples with the exact token, head and source digest and zero active normal tool calls.
5. Require tunnel queue zero and `polled == enqueued == final responses`. Counters may advance only in balanced form while the admission gate rejects new tool effects.
6. Re-run operator and tunnel final guards immediately before service stop.
7. Stop tunnel, then operator; activate and start the replacement operator.
8. Require the replacement operator to attest the exact active marker before the tunnel starts and again immediately after tunnel startup.
9. Release the marker only after the new runtime is healthy and identity-bound; marker absence is drift, never success.

The first deployment from a predecessor runtime uses the legacy stable-counter drain only after the status route explicitly returns 404. Transient transport failures are retried for up to the smaller of the deployment timeout and thirty seconds; they never establish legacy compatibility. If no explicit 404 or valid admission response becomes observable inside that bound, deployment fails closed before service stop. Every later deployment uses the admission-aware path. A predecessor may complete a scheduled deployment without an observer contract; such a deployment remains safe but cannot be polled through the drain.

## Failure and rollback

Before service stop, failure releases the exact marker and leaves the healthy runtime untouched. If observer activation fails after marker creation, the deployer releases that exact marker before returning failure. After service stop, rollback restores the previous pointer and operator, then requires that restored operator to attest the exact active marker before the tunnel may restart. A predecessor runtime without the admission contract therefore remains fail-closed with both the tunnel and restored loopback operator stopped instead of admitting work during an incomplete rollback. Only a marker-aware, identity- and readiness-verified rollback may release the marker. Missing or drifted markers are failures, not successful cleanup.

## Non-claims

The admission marker and observer capability do not authorize deployment, bypass the deployment lock, prove connector delivery, admit other work, cancel accepted commands, kill workers, or weaken review, recovery, kill-switch or privileged-execution gates. A scheduled deployment receipt or observer response still does not prove completion; exact runtime identity and health readback remain required.

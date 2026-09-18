# Transport roundtrip gate v1

## Purpose

Local process health and a matched connector snapshot do not prove that a client received a response through the complete transport path. This contract therefore adds a single-use prerequisite for every public tool whose MCP annotation declares `readOnlyHint=false`.

The check is installed at the central FastMCP `call_tool` boundary. A mutating tool cannot reach its implementation until its transport scope has completed a fresh challenge bound to the exact deployed runtime and mutation intent. The verification is atomically consumed before that one mutation and records the tool name plus canonical argument hash.

## Scope and trust level

FastMCP exposes `_meta.client_id`, but the installed SDK documents it as request metadata supplied by the client, not OAuth identity. Grabowski therefore treats it only as a **client-declared scope label**. It is never described as authentication or authorization.

When `_meta.client_id` is absent, the production stateless HTTP transport uses the explicit `shared_unlabeled` scope. That scope uses a bounded shared token pool: exact challenges and reservations coexist under one lock, concurrent handshakes do not overwrite one another, and every admitted mutation still consumes exactly one verification. The pool proves only possession within the shared transport boundary; it neither attributes a token to one caller nor distinguishes concurrent unauthenticated clients.

## Shared-unlabeled handshake

The normal path is deliberately two-step and keeps the first target call effect-free:

1. Invoke the mutating MCP tool normally. Central admission computes the exact tool name and canonical argument hash and creates a durable challenge. Grabowski may also retain an exact JSON copy of the target **in process memory only** as an optimization while that pending challenge remains retained. No domain effect is admitted. Pending retained entries may be evicted under bounded-pool pressure because they have admitted no effect.
2. Call `grip_run` → `transport-roundtrip` with `action=execute`, the returned `challenge_receipt_sha256`, the exact `target_tool_name`, and the exact unchanged `target_arguments` JSON object from the first call. This explicit target form is the canonical cross-call path because it does not depend on the next connector request reaching the same serving process or retained-target pool.
3. The transport layer verifies that the supplied target hashes to the mutation intent already bound into the durable challenge, reserves that challenge for the exact target, and dispatches it under a challenge-derived in-process ownership tag. The tag is deterministic and is not an authentication secret; authority comes from the private execution context.
4. Central admission consumes the reservation before the domain effect. A matching retained target, when still present in the same process, may be claimed and discarded as an additional consistency check; it is not required for the canonical explicit execute path.

Challenge-only `action=execute` remains accepted as an opportunistic same-process optimization when the exact retained target is still available. Clients must not depend on that optimization across connector calls, process changes, deploys, restarts, or retention eviction.

If the process restarts, the retained target expires or is safely evicted, or the target exceeds its bounded per-object size, the explicit execute path remains available because the durable challenge already binds the tool name and canonical argument hash. The resubmitted target must match that exact binding before any reservation or domain effect is admitted. A missing retained target matters only for challenge-only execute. In that case the server atomically cancels the durable challenge only if it is still pending and unreserved; only that successful cancellation proves a fresh retry is safe. Reserved, consumed, runtime-mismatched, or otherwise unknown state requires target-specific readback before any retry.

## Stable client-declared scope

A stable client-declared scope may use `action=begin`, then `action=ack`, then invoke the exact mutation once. `action=ack` remains fail-closed for `shared_unlabeled` because a shared label is not caller identity.

## Bound evidence

Each durable transport receipt binds the scope kind and hash, release id, full repository head, registered tool-name hash, agent-instruction hash, timestamps, receipt chain, and canonical receipt hash. The consumption receipt additionally binds the mutating tool name and canonical argument SHA-256. Release, head, catalog, instruction, time, receipt, file-owner, permission, symlink, or hardlink drift closes the gate.

Challenges expire after five minutes. Stable client-declared verifications expire after fifteen minutes and are single-use. Shared atomic execution reservations expire after 30 seconds; an expired reservation still present in durable state proves it was never consumed, so it can be removed under the state lock and retried with a fresh challenge. Consumption is serialized under the same private state lock. The stateless shared scope is capped at 32 pending challenges and 32 verified receipts. When the pending challenge pool is full, the oldest still-pending effect-free challenge is evicted instead of blocking all callers. The in-memory retained-target pool is capped to the same pending count, each retained argument object is bounded to 4 MiB, and aggregate canonical retained argument bytes are capped at 16 MiB; bounded pressure evicts only still-pending targets and never an in-flight claim.

Durable handshake state lives below `~/.local/state/grabowski/transport-roundtrip/` with a private directory, private regular files, a 512 KiB per-scope JSON bound, serialized writers, atomic replacement, and file plus directory synchronization. Retained raw target arguments are **not** written there; they exist only in the serving process until claimed or expired. The canonical explicit execute path therefore resubmits those arguments and relies on the challenge-bound canonical digest rather than cross-call process memory.

Self-hashes detect corruption and inconsistent rewriting. They do not claim resistance to code already running as the same operating-system user.

## Central admission

- exact handshake grip and marker-bound deployment observer: narrowly exempt;
- `readOnlyHint=true`: no mutation gate;
- `readOnlyHint=false`: fresh exact verification is atomically consumed;
- missing or malformed `readOnlyHint`: reject before tool effect.

The complete runtime inventory must classify every public tool explicitly. Explicit `action=begin` on the MCP surface validates that its named target exists and declares `readOnlyHint=false` before it is allowed to occupy transport state.

## Failure semantics

The gate proves that a challenge response was received before one admitted mutation. It does not prove the result of that mutation or exclude response loss afterwards. A timeout or 502 after execution therefore still requires the tool-specific status, target readback, operation identity, or reconciliation path. A new challenge never authorizes blind replay.

A missing retained target is not by itself safe-retry evidence for challenge-only execute. Shared pooled status reports expose aggregate counts without projecting another unlabeled caller's target tool, argument digest, or last-consumption identity. The server may authorize a fresh retry only by atomically removing the exact challenge while it is still pending and unreserved. If the challenge is reserved, consumed, belongs to another runtime, cannot be found, or cannot be inspected, the outcome is treated as potentially ambiguous and requires target-specific readback. During an in-process execute, any retained entry that is claimed remains marked claimed until dispatch returns, so a concurrent duplicate cannot cancel the challenge out from under the active call.

## Cutover evidence

A release is transport-verified only when the exact merged head has passed validation, all public tools have explicit annotations, deployment integrity and connector snapshot match, a real connector-origin shared mutation produces a challenge without effect, explicit `action=execute` with the challenge plus exact unchanged target succeeds even when no retained target is available in process, status exposes the matching consumption receipt, and a second use of that challenge cannot produce another effect.

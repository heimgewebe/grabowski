# Transport roundtrip gate v1

## Purpose

Local process health and a matched connector snapshot do not prove that a client received a response through the complete transport path. This contract therefore adds a single-use prerequisite for every public tool whose MCP annotation declares `readOnlyHint=false`.

The check is installed at the central FastMCP `call_tool` boundary. A mutating tool cannot reach its implementation until its transport scope has completed a fresh challenge bound to the exact deployed runtime and mutation intent. The verification is atomically consumed before that one mutation and records the tool name plus canonical argument hash.

## Scope and trust level

FastMCP exposes `_meta.client_id`, but the installed SDK documents it as request metadata supplied by the client, not OAuth identity. Grabowski therefore treats it only as a **client-declared scope label**. It is never described as authentication or authorization.

When `_meta.client_id` is absent, the production stateless HTTP transport uses the explicit `shared_unlabeled` scope. That scope uses a bounded shared token pool: exact challenges and reservations coexist under one lock, concurrent handshakes do not overwrite one another, and every admitted mutation still consumes exactly one verification. The pool proves only possession within the shared transport boundary; it neither attributes a token to one caller nor distinguishes concurrent unauthenticated clients.

## Shared-unlabeled handshake

The normal path is deliberately two-step and keeps the first target call effect-free:

1. Invoke the mutating MCP tool normally. Central admission computes the exact tool name and canonical argument hash, creates a challenge, and retains an exact JSON copy of the target **in process memory only** for at most the challenge lifetime. No domain effect is admitted.
2. Call `grip_run` → `transport-roundtrip` with `action=execute` and only the returned `challenge_receipt_sha256`. The MCP wrapper claims the retained target and injects its exact tool name and arguments server-side.
3. The transport layer reserves that challenge for the injected exact target and dispatches it under a challenge-derived in-process execution capability.
4. Central admission consumes the reservation before the domain effect. The retained target is single-claim and cannot be reused for a second minimal execute.

This removes the client-visible mutation-inside-mutation payload without collapsing the two-step response proof. The client no longer has to resend `target_tool_name` or `target_arguments` merely to complete a shared-scope challenge.

If the process restarts, the retained target expires, the retention pool fills, or the target exceeds its bounded memory size, the original target call still has admitted no effect. That fact alone is not enough to authorize replay after an `execute` attempt: an execute may already have reserved or consumed the challenge. When retained state is missing, the server atomically cancels the durable challenge only if it is still pending and unreserved. Only that successful cancellation proves a fresh retry is safe. Reserved, consumed, runtime-mismatched, or otherwise unknown state requires target-specific readback before any retry. The compatibility path remains available: explicit `action=begin` with `target_tool_name` and `target_arguments`, followed by `action=execute` carrying the challenge and the unchanged target.

## Stable client-declared scope

A stable client-declared scope may use `action=begin`, then `action=ack`, then invoke the exact mutation once. `action=ack` remains fail-closed for `shared_unlabeled` because a shared label is not caller identity.

## Bound evidence

Each durable transport receipt binds the scope kind and hash, release id, full repository head, registered tool-name hash, agent-instruction hash, timestamps, receipt chain, and canonical receipt hash. The consumption receipt additionally binds the mutating tool name and canonical argument SHA-256. Release, head, catalog, instruction, time, receipt, file-owner, permission, symlink, or hardlink drift closes the gate.

Challenges expire after five minutes. Completed verification expires after fifteen minutes but is single-use. Consumption is serialized under the same private state lock. The stateless shared scope is capped at 32 pending challenges and 32 verified receipts. The in-memory retained-target pool is capped to the same pending count, each retained argument object is bounded to 4 MiB, and aggregate canonical retained argument bytes are capped at 16 MiB.

Durable handshake state lives below `~/.local/state/grabowski/transport-roundtrip/` with a private directory, private regular files, bounded JSON, serialized writers, atomic replacement, and file plus directory synchronization. Retained raw target arguments are **not** written there; they exist only in the serving process until claimed or expired.

Self-hashes detect corruption and inconsistent rewriting. They do not claim resistance to code already running as the same operating-system user.

## Central admission

- exact handshake grip and marker-bound deployment observer: narrowly exempt;
- `readOnlyHint=true`: no mutation gate;
- `readOnlyHint=false`: fresh exact verification is atomically consumed;
- missing or malformed `readOnlyHint`: reject before tool effect.

The complete runtime inventory must classify every public tool explicitly.

## Failure semantics

The gate proves that a challenge response was received before one admitted mutation. It does not prove the result of that mutation or exclude response loss afterwards. A timeout or 502 after execution therefore still requires the tool-specific status, target readback, operation identity, or reconciliation path. A new challenge never authorizes blind replay.

A missing retained target is not by itself safe-retry evidence. The server may authorize a fresh retry only by atomically removing the exact challenge while it is still pending and unreserved. If the challenge is reserved, consumed, belongs to another runtime, cannot be found, or cannot be inspected, the outcome is treated as potentially ambiguous and requires target-specific readback. During an in-process execute, the retained entry is marked claimed until dispatch returns, so a concurrent duplicate cannot cancel the challenge out from under the active call.

## Cutover evidence

A release is transport-verified only when the exact merged head has passed validation, all public tools have explicit annotations, deployment integrity and connector snapshot match, a real connector-origin shared mutation produces a challenge without effect, challenge-only `action=execute` dispatches the retained exact target once, status exposes the matching consumption receipt, and a second use of that challenge cannot produce another effect.

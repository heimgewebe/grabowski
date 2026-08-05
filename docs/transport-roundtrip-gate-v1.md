# Transport roundtrip gate v1

## Purpose

Local process health and a matched connector snapshot do not prove that a client received a response through the complete transport path. This contract therefore adds a single-use prerequisite for every public tool whose MCP annotation declares `readOnlyHint=false`.

The check is installed at the central FastMCP `call_tool` boundary. A mutating tool cannot reach its implementation until its transport scope has completed a fresh challenge and acknowledgement bound to the exact deployed runtime. The verification is atomically consumed before that one mutation and records the tool name plus canonical argument hash.

## Scope and trust level

FastMCP exposes `_meta.client_id`, but the installed SDK documents it as request metadata supplied by the client, not OAuth identity. Grabowski therefore treats it only as a **client-declared scope label**. It is never described as authentication or authorization.

Transport authority requires a stable **connector session** identity (T142): the
Streamable HTTP `mcp-session-id` header or an explicit context `session_id`,
combined with the server process instance and optional `_meta.client_id`. The
HTTP transport is stateful so protocol sessions can span begin, ack and the
bound mutation when the client returns the header. A bounded token pool exists
only inside one connector session. There is no global `shared_unlabeled`
authorization pool; missing identity fails closed before handshake creation or
consumption. Python object identity and weakrefs are not authority.

See `docs/transport-roundtrip-v3.md` and
`docs/proofs/transport-connector-session-v1-t142.md`.

## Handshake

The existing `grip_run` surface exposes the operator-only `transport-roundtrip` grip; no new public MCP tool is added.

1. Run `transport-roundtrip` with `action=begin`.
2. A connector session may reuse its still-current, unconsumed verification for the exact same intent. Distinct exact intents inside one session coexist under the session-private pool limit.
3. Acknowledge the returned `challenge_receipt_sha256` with `action=ack`; only that pending entry becomes a verification.
4. Invoke exactly one mutating tool. Central admission consumes the verification before tool effect.
5. Repeat the handshake before every later mutation.

The caller cannot inject the server-reserved scope object or runtime binding through grip parameters. The server derives the scope from request metadata or the explicit shared fallback and adds the exact runtime binding immediately before grip dispatch.

## Bound evidence

Each receipt binds the scope kind and hash, release id, full repository head, registered tool-name hash, agent-instruction hash, timestamps, receipt chain, and canonical receipt hash. The consumption receipt additionally binds the mutating tool name and canonical argument SHA-256. Release, head, catalog, instruction, time, receipt, file-owner, permission, symlink, or hardlink drift closes the gate.

Challenges expire after five minutes. Completed verification expires after fifteen minutes but is single-use. Consumption is serialized under the same private state lock, preventing two admitted mutations from using one verification. Each connector session is capped at 32 pending challenges and 32 verified receipts; stale or runtime-mismatched entries are pruned on the next mutation, and a full live pool blocks fail-closed.

State lives below `~/.local/state/grabowski/transport-roundtrip/` with a private directory, private regular files, bounded JSON, serialized writers, atomic replacement, and file plus directory synchronization. Legacy single-slot state is validated and migrated on the next mutation. Status reads do not create or rewrite state.

Self-hashes detect corruption and inconsistent rewriting. They do not claim resistance to code already running as the same operating-system user.

## Central admission

- exact handshake grip and marker-bound deployment observer: narrowly exempt;
- `readOnlyHint=true`: no mutation gate;
- `readOnlyHint=false`: fresh verification is atomically consumed;
- missing or malformed `readOnlyHint`: reject before tool effect.

The complete runtime inventory must classify every public tool explicitly.

## Connector snapshot renewal

The tunnel snapshot observer uses one MCP session and one explicit client-declared scope for tool listing, status, handshake, and snapshot binding. It obtains or reuses a fresh verification; `connector-snapshot-bind` then consumes that verification.

## Failure semantics

The gate proves that the challenge response was received before one admitted mutation. It does not prove the result of that mutation or exclude response loss afterwards. A timeout or 502 therefore still requires the tool-specific status, target readback, operation identity, or reconciliation path. A new handshake never authorizes blind replay.

Missing, consumed, or stale verification is not watchdog restart authority. It can simply mean that no mutation is currently admitted. Watchdogs continue to use process, listener, event-loop, MCP lifecycle, queue, and runtime-integrity evidence.

## Cutover evidence

A release is transport-verified only when the exact merged head has passed full validation, all public tools have explicit annotations, deployment integrity and connector snapshot match, a real connector-origin begin/ack sequence opens the gate, one harmless leased mutation consumes it, status exposes the matching consumption receipt, and a second mutation is rejected until another handshake.

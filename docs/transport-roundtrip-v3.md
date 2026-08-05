# Transport roundtrip v3 / connector session v1 (T142)

Mutating MCP calls are admitted only by a single-use verification bound to all
of the following inputs:

- the server process instance (`_TRANSPORT_SERVER_INSTANCE_ID`);
- the FastMCP client identifier when present in request `_meta`;
- a **stable protocol connector session identity**:
  - explicit `session_id` on the live MCP context when exposed, otherwise
  - the Streamable HTTP `mcp-session-id` request header;
- the integrity-valid runtime contract (release, head, tool catalog, agent
  instructions);
- the exact target tool name;
- the canonical SHA-256 of the exact target arguments;
- challenge and verification expiry;
- single use under the private state lock.

The state file is selected by the hash of that `connector_session` scope. Two
connector sessions therefore cannot acknowledge, consume, replace or invalidate
each other's challenges or verifications. A bounded pool exists only **inside**
one connector session so concurrent exact mutations from that same session can
progress independently.

## Identity authority (and non-authority)

| Input | Authority? |
| --- | --- |
| Streamable HTTP `mcp-session-id` | yes (protocol session) |
| Explicit context `session_id` string | yes |
| FastMCP `_meta.client_id` | scope salt only, not sole authority |
| Python object identity / `id(session)` | **no** |
| Weakref-bound opaque tokens | **no** |
| Per-call Context wrappers that invent stability | **no** |
| Global `shared_unlabeled` pool | **no** — rejected fail-closed |

Without a stable protocol identity, mutation admission fails closed **before**
any handshake state is created or consumed. Read-only tools never consult the
gate and never rewrite handshake state.

## Why not the T139 weakref path

The first T139 candidate bound authority to the FastMCP session **object** via
identity-checked weakrefs and briefly required stateful HTTP. The production
ChatGPT connector did not preserve one MCP session across begin and ack under
stateless HTTP, so #610 reverted that path. T139 was then closed by exact intent
binding alone (`#613`), which still left two concurrent unlabeled callers of the
same exact intent indistinguishable under `shared_unlabeled`.

T142 restores isolation without reintroducing object identity as authority:

1. HTTP is stateful again so `mcp-session-id` can be stable across three calls
   when the client preserves the protocol header.
2. Scope derivation uses only that protocol string plus server instance and
   optional client id.
3. Exact intent binding from `#613` is retained.
4. Legacy schema v1/v2/v3 and legacy scope kinds authorize nothing after load.

## Migration

State schema versions 1 (single-slot), 2 (`shared_unlabeled` pools) and 3
(object/weakref-bound `caller_session`) are never converted into v4 authority.
When encountered at a v4 scope path they are treated as an empty closed gate and
replaced only by a new exact handshake under a real connector session.

Legacy scope kinds `shared_unlabeled`, `client_declared_meta` and
`caller_session` are rejected by `validate_client_scope`.

## Failure contract

| Condition | Effect |
| --- | --- |
| Missing connector session identity | fail closed before handshake |
| Foreign connector session | cannot ack/consume/replace owner state |
| Exact intent mismatch | fail closed; foreign verification not consumed |
| Expiry / runtime drift | fail closed |
| Replay after consumption | fail closed; new handshake required |
| Server process restart | new server instance id; prior scopes useless |
| Effect failure after admission | no reusable proof (consume-before-effect) |

## Operator handshake

1. `grip_run(name=transport-roundtrip, action=begin, target_tool_name=…, target_arguments=…)`
2. `grip_run(name=transport-roundtrip, action=ack, challenge_receipt_sha256=…)`
3. Invoke exactly that mutating tool with the same arguments once.

The grip contract is version `1.2` with acceptance ids
`exact-target-bound` and `connector-session-bound`.

## Residual external proof

Deterministic tests and the dual-client harness prove isolation and the three
call sequence for protocol-session-bound clients. A live ChatGPT connector proof
requires a **deployed** revision that issues and preserves `mcp-session-id`
across begin, ack and mutation. That operator-side procedure is documented in
`docs/proofs/transport-connector-session-v1-t142.md` and is **not** claimed by
this repository change alone.

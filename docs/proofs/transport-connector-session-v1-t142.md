# T142: Connector-session transport identity

## Binding

- Bureau task: `GRABOWSKI-OPERATOR-SURFACE-V1-T142`
- Baseline head (standalone clone start): `eb71cc00122915507c765b3b301765bdb2564f08`
- Branch: `fix/t142-connector-session-v1`
- Candidate head: the Git commit containing this proof

## Belegt (live code / tests)

### Cause

1. After `#613` the production path without `_meta.client_id` used
   `shared_unlabeled` with a bounded shared token pool. Exact intent binding
   stopped unbound handshakes from authorizing arbitrary tools, but **two
   concurrent connectors with the same exact intent remained indistinguishable**.
   One connector's verification could admit the other's mutation.
2. The earlier T139 path that bound authority to the FastMCP session **object**
   via weakrefs failed for the ChatGPT connector (`#610`): separate HTTP calls
   did not share one session object under the then-stateless runtime.
3. Python object identity, weakrefs and per-call context wrappers therefore must
   not be treated as identity authority. A global shared pool must not either.

### Decision

Implement `connector_session` scope (state schema **v4**):

- Scope label = SHA-256 of
  `{client_id, connector_session_id, server_instance_id}`.
- `connector_session_id` comes only from:
  - explicit context `session_id`, or
  - Streamable HTTP header `mcp-session-id`.
- Stateful Streamable HTTP (`HTTP_STATELESS_MODE = False`) so protocol sessions
  can remain stable across begin, ack and the bound mutation when the client
  returns the header.
- Exact target binding, consume-before-effect, TTLs and single-use unchanged.
- Per-session bounded pool only; no global shareable pool.
- Legacy schemas 1–3 and legacy scope kinds authorize no mutation.

### Verification (deterministic)

Focused suites:

- `tests/test_transport_roundtrip.py`
- `tests/test_transport_roundtrip_intent_replacement.py`
- `tests/test_transport_gate_integration.py`
- operator HTTP mode assertion in `tests/test_operator_contract.py`

Covered behaviors:

| Class | Evidence |
| --- | --- |
| Identity authority | protocol session / header binding; missing identity fails before consume/begin; weakref/object/shared_unlabeled non-claims |
| Parallelism / races | concurrent consumers admit exactly one; session pool coexists for distinct intents; foreign session cannot ack/consume |
| Replay / crash / expiry | ack replay idempotent before consume; post-consume closed; expired challenge/verification fail closed; server-instance restart isolates |
| Read-only / compatibility | read-only tools skip gate; status without session reports `unavailable` without state writes; grip v1.2 contract |
| Generated contracts / migration | schema v1/v2/v3 discarded; legacy scopes rejected; operator context regenerated |

Dual-client harness
(`DualConnectorSessionHarnessTests.test_two_clients_complete_isolated_three_call_roundtrips`):
two distinct connector sessions complete begin → ack → mutation through the
central gate with identical target arguments; cross-session theft is refused.

## Plausibel

- Stateful HTTP plus client-preserved `mcp-session-id` is the smallest coherent
  identity that works for any compliant Streamable HTTP client without inventing
  object-tied authority.
- If a remote platform drops the session header between tool calls, mutations
  fail closed honestly rather than silently sharing a pool.

## Spekulativ / Nichtaussagen

- This change does **not** claim that the currently deployed production
  ChatGPT connector already preserves `mcp-session-id` across three calls.
- It does not claim OAuth or human identity.
- It does not change lease, review, merge, deployment, recovery or kill-switch
  boundaries.
- It does not claim resistance to compromised same-UID code.
- Full network load with two external MCP clients against production is not
  claimed; the dual-client harness is revision-bound and in-process/gate-level.

## Operator-side live connector proof (post-deploy only)

Do **not** claim success until each step is observed on the **deployed** head.

1. Deploy the merged T142 head (out of scope for this PR).
2. From one ChatGPT connector conversation, run:
   - `grip_run` / `transport-roundtrip` `action=begin` with an exact
     `target_tool_name` and `target_arguments` for a **harmless leased** mutation;
   - `action=ack` with the returned `challenge_receipt_sha256`;
   - the exact mutation once.
3. Record: `client_scope_kind=connector_session`,
   `pool_mode=connector-session-token-pool`,
   `mutation_intent_bound=true`, consumption receipt present, second identical
   mutation refused until a new handshake.
4. From a **second concurrent connector**, attempt the same exact intent without
   that connector's own handshake: admission must fail closed and must not
   consume the first connector's verification.
5. Capture status/readback after any timeout or 502; never treat a new handshake
   as blind replay authority.

Until steps 2–4 are observed on the deployed head, the live ChatGPT proof
remains **outstanding**.

## Self-reviews performed

1. Identity authority — protocol only; weakref/object/shared pool non-authority.
2. Parallelism/races — flock + per-session pool + dual-client isolation.
3. Replay/crash/expiry — single-use, TTL, restart server-instance binding.
4. Read-only/compatibility — gate skip, status unavailable, exact intent retained.
5. Generated contracts/backward compatibility — grip 1.2, schema v4, legacy discard.

## Residual risk

Orphaned stateful HTTP sessions remain until process restart (no idle timeout
wave). A later hardening may add inventory/cap without reintroducing global
pools or object-tied authority.

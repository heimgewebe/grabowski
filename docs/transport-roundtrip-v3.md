# Transport roundtrip v3

Mutating MCP calls are admitted only by a single-use verification bound to all
of the following inputs:

- the server process instance;
- the FastMCP client identifier when present;
- an explicit session identifier when exposed, otherwise an opaque random token
  retained only for the lifetime of the actual FastMCP session object;
- the integrity-valid runtime contract;
- the exact target tool name;
- the canonical SHA-256 of the exact target arguments;
- challenge and verification expiry.

The state file is selected by the hash of that caller-session scope. Two
sessions therefore cannot acknowledge, consume, replace or invalidate each
other's challenges or verifications. A private bounded pool exists only inside
one caller-session scope so concurrent exact mutations from that same session
can progress independently under the existing file lock.

## Missing identity

`client_id` alone is not sufficient because it can span multiple sessions. The
currently installed FastMCP `Context` exposes the underlying session object but
no `session_id` property. Grabowski therefore assigns that object an opaque
random token through an identity-checked weak reference. A later object that
reuses the same Python object ID receives a new token and cannot inherit old
authority. The server-instance nonce prevents all such tokens from surviving a
process restart. If no session object exists or it cannot be weakly referenced,
mutation admission fails closed before a handshake is created.

## Migration

State schema v1 and v2 may contain unbound or globally shared authorization.
They are never converted into v3 authority. When encountered at a v3 scope
path, they are treated as an empty closed gate and replaced only by a new exact
handshake. Existing shared-unlabeled state remains unreachable because that
scope kind is rejected.

The migration deliberately trades one interrupted handshake for removal of
cross-client authorization. Read-only tools remain independent of the
transport gate.

## Failure contract

Expiry, runtime drift, foreign session scope, missing exact intent and replay
after consumption all fail closed. A mismatch does not consume or delete a
verification for another exact mutation.

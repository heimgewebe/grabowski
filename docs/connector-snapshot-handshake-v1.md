# Connector snapshot handshake v1

## Purpose

The server tool registry and a connector's frozen client tool view are different states. A successful runtime deployment proves the server release and its registered tool contract. It does not prove that an already-open connector has refreshed its local tool catalog.

Connector snapshot handshake v1 binds one bounded client declaration to the current server release without adding another public MCP tool. The existing `grip_run` surface exposes the mutating `connector-snapshot-bind` grip, so the public tool budget remains unchanged.

## Bound fields

The client declares:

- a bounded client identifier;
- a bounded session identifier;
- observed tool count;
- SHA-256 of the sorted tool-name list using `sha256-json-sorted-utf8-v1`;
- observed runtime release id;
- observed agent-instruction SHA-256.

The server ignores client-supplied internal binding fields and injects:

- current registered tool count and tool-name SHA-256;
- current release id and repository head;
- current agent-instruction SHA-256;
- whether the server runtime matches its deployment tool contract.

A matched declaration is stored as a private mode-0600, owner-bound, self-hashed receipt under the Grabowski state root. Publication is lock-serialized and uses atomic replacement. The receipt expires after one hour and becomes stale immediately when the release, repository head, tool count, tool-name hash, or instruction hash changes.

## Status model

`grabowski_status` exposes the connector snapshot under `tool_contract.client_snapshot`:

- `missing`: no valid receipt exists;
- `invalid`: the receipt or private-file contract failed validation;
- `stale`: the receipt exceeded its validity interval;
- `mismatch`: the declaration does not match the current server contract;
- `matched`: the receipt is fresh and all bound values match.

`client_snapshot_observable=true` means only that a fresh client declaration was compared with and matched the current server contract. It does not mean the platform independently attested the client process.

## Consolidated operator overview

The `standard` and `evidence` status views include `system_overview`. It is a read-only projection over existing sources:

- runtime integrity;
- connector snapshot state;
- task state and active/attention/terminal projection counts;
- bounded active lease count;
- bounded operator-obligation attention and integrity counts;
- an explicit source registry for Bureau, GitHub/CI, RepoBrief, Systemkatalog, and Chronik.

Target-bound external sources are marked `target_required` until a repository, pull request, bundle, system, task, operation, or receipt identity is supplied. Their freshness is never inferred from the global status call.

The overview stores no second status truth. Component errors and truncation make `operator_ready=false`. Attention work remains visible but does not by itself imply that a retry is safe.

## Trust boundary

The verification model is `client-declared-server-compared-v1`.

It establishes:

- the exact declaration persisted in the receipt;
- equality of the declared values and the server-owned values at binding time;
- receipt integrity, freshness, and current-release binding when later read.

It does not establish:

- platform-enforced client snapshot identity;
- that the connector actually exposed or invoked every declared tool;
- client compliance with agent instructions;
- isolation from compromised same-UID code that can rewrite both payload and self-hash;
- future mutation authority;
- correctness of individual tool behavior.

A future platform-attested connector identity can strengthen this boundary without changing the receipt's server-side count, hash, release, and instruction bindings.

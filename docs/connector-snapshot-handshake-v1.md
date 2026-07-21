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

## Automatic renewal

The tunnel semantic watchdog runs every 30 seconds. When the tunnel is healthy, it asks the release-bound `grabowski_client_snapshot` module to decide whether renewal is due. Renewal is triggered when the local tunnel process lifetime changes, the bound runtime release changes, the snapshot is missing or invalid, or the receipt enters a 15-minute pre-expiry window.

Renewal does not copy server contract values into a fresh receipt. A real loopback MCP client session performs `tools/list`, computes the canonical tool-name hash from the returned names, reads `grabowski_status` through the same MCP session, and submits that client-observed declaration through the existing `connector-snapshot-bind` grip. The grip performs the independent server-side comparison and persists only its receipt. A mismatch remains fail-closed.

A fresh externally supplied connector snapshot is preserved until it needs renewal because it may represent stronger evidence than the local observer. A separate private scheduling marker remembers the last observed local tunnel process lifetime, so a later tunnel restart still triggers renewal without immediately replacing stronger external evidence. The automatic observer identifies its own evidence as `grabowski-tunnel-watchdog-observer-v1` and binds its session identifier to the concrete `tunnel-client` process lifetime (PID plus process start ticks, hashed into a bounded identifier).

The automatic observer still does not establish platform-enforced ChatGPT connector identity, an individual remote conversation/session identity, or that the remote platform exposed every locally observed tool. Those non-claims remain part of `client-declared-server-compared-v1`; automatic renewal removes stale local evidence without upgrading it into stronger evidence than the system can actually observe.

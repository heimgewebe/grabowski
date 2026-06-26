# Grabowski Operator Entry

Grabowski is the local MCP operator for the user's home PC. Its purpose is to let ChatGPT diagnose, change, validate and operate the local environment with explicit effects, evidence and bounded rollback rather than artificial weakness.

## Start here

For a complex task, first call:

```text
grabowski_context(profile="concise")
```

Then select a task profile when useful:

```text
grabowski_context(profile="repository-work")
grabowski_context(profile="host-operations")
grabowski_context(profile="full")
```

The live context is authoritative for the running deployment, active policy, available capabilities and checkout drift. The generated repository documents describe the intended contract:

- `docs/generated/operator-context.md`
- `docs/generated/operator-context.v1.json`
- `contracts/capability-catalog.v1.json`

## Truth hierarchy

1. Running MCP tool contract and deployment provenance.
2. Active access policy on the host.
3. Versioned runtime contract and source declarations.
4. Generated capability catalog.
5. Narrative documentation and roadmap.

A mismatch must remain visible. Do not silently treat an older checkout or connector snapshot as current.

## Operating rule

Before a mutation establish the target, current state, intended result, validation, stop condition and rollback path. Prefer typed operations over generic shell or Git commands when a typed operation exists.

`~/repos/merges` is immutable evidence. Secret values and browser profiles are not exposed. Privileged or secret-backed effects should eventually be delegated through typed brokers rather than by revealing credentials to ChatGPT.

## Self-update contract

`make context-refresh` regenerates the capability catalog and repository context from the runtime entrypoint contract and actual MCP declarations.

`make validate` and `make deploy-check` fail when:

- generated context is stale;
- expected tools are not declared;
- declared tools are missing from the runtime contract;
- capability profiles are missing or orphaned;
- duplicate tools are present.

The `grabowski_context` tool computes live runtime and checkout state on every call. Static prose is therefore not trusted as a substitute for current evidence.

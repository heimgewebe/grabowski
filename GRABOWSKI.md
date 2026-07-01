# Grabowski Operator Entry

Grabowski is the local MCP operator for the user's home PC. Its purpose is to let ChatGPT diagnose, change, validate and operate the local environment with explicit effects, evidence and bounded rollback rather than artificial weakness.

## Start here

For ordinary orientation, prefer the narrow read tools:

```text
grabowski_runtime_health()
grabowski_contract_drift()
```

Add only the context required by the task:

```text
grabowski_deployment_identity()
grabowski_checkout_summary()
```

Use the broad live context only when the task actually needs the combined policy, capability and checkout inventory:

```text
grabowski_context(profile="concise")
grabowski_context(profile="repository-work")
grabowski_context(profile="host-operations")
grabowski_context(profile="full")
```

The live tools are authoritative for the running deployment, active policy, available capabilities and checkout drift. The generated repository documents describe the intended contract:

- `docs/generated/operator-context.md`
- `docs/generated/operator-context.v1.json`
- `contracts/capability-catalog.v1.json`
- `docs/control-plane.md`
- `docs/checkout-lifecycle.md`
- `docs/typed-read-surface.md`
- `docs/blocked-action-protocol-v0.md`
- `docs/privileged-broker-bootstrap.md`

## Truth hierarchy

1. Running MCP tool contract and deployment provenance.
2. Active access policy on the host.
3. Versioned runtime contract and source declarations.
4. Generated capability catalog.
5. Narrative documentation and roadmap.

A mismatch must remain visible. Do not silently treat an older checkout or connector snapshot as current.

`grabowski_status` exposes the live registered/expected tool counts and name hashes. A client-side count or hash mismatch requires a connector refresh; the runtime cannot refresh ChatGPT's frozen snapshot itself.

## Operating rule

Use the narrowest typed read operation that can establish current state. Before a mutation establish the target, intended result, validation, stop condition and rollback path. Prefer typed operations over generic shell, Git, GitHub or service commands when a typed operation exists.

Operator Relay v0 is the fallback rule for blocked ChatGPT/Grabowski actions: try a typed Grabowski tool first; if that is blocked, use one bounded Grabowski Micro-Task; then read status, logs, diff or another receipt before deciding the next step. For helper routing, use Codex as the default for complex code or repo tasks, agy `--print` for quick light reasoning, Ollama API with qwen coder for local micro-reasoning, Claude for review, tmux first for session/resume, Bureau for prioritization, and Grabowski + Git for audit. Local patch files should go through `tools/operator_patch_relay.py` for check/apply receipts before asking the user to download and run a patch manually. Aider remains a bounded patch fallback with no auto-commit. Details: `docs/blocked-action-protocol-v0.md`.

Generic operator tools remain available as fallback mechanisms; they are not the default diagnostic route. A failed read is classified and reviewed rather than automatically repeated through a broader tool.

For a self-update that restarts operator and tunnel, prefer `grabowski_runtime_deploy_schedule` over a foreground `make deploy`. It binds the expected commit and returns a durable job before the delayed cutover begins.

`~/repos/merges` is immutable evidence. Secret values and browser profiles are not exposed. Privileged or secret-backed effects should eventually be delegated through typed brokers rather than by revealing credentials to ChatGPT.

## Publication profiles

`core`, `operator` and `full` are projections of the single runtime contract and capability catalog, not duplicated implementations. No second connector is registered merely because the projections exist. A separate core connector requires a measured canary advantage first.

## Self-update contract

`make context-refresh` regenerates the capability catalog and repository context from the runtime entrypoint contract and actual MCP declarations.

`make validate` and `make deploy-check` fail when:

- generated context is stale;
- expected tools are not declared;
- declared tools are missing from the runtime contract;
- capability profiles are missing or orphaned;
- duplicate tools are present.

The live context tools compute runtime and checkout state on every call. Static prose is therefore not trusted as a substitute for current evidence.

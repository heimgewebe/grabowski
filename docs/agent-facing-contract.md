# Agent-facing Contract v1

## Purpose

Grabowski exposes a short, versioned instruction contract through the MCP
`initialize` result. The contract tells an agent how to use the operator surface
without granting any new authority.

The contract is part of the immutable deployment identity. Runtime state and
concrete receipts remain higher-authority than this document or any other prose.

## Canonical runtime source

For version `grabowski-agent-facing-contract-v1`, the canonical rules and
renderer live in `src/grabowski_mcp.py`:

- `AGENT_INSTRUCTIONS_SCHEMA_VERSION`
- `AGENT_INSTRUCTIONS_VERSION`
- `AGENT_INSTRUCTIONS_MAX_BYTES`
- `AGENT_INSTRUCTION_RULES`
- `_render_agent_instructions()`

The current code-owned representation is deliberate for v1. Moving the rules to
a separate artifact is only safe when that artifact becomes a required,
schema-validated and hash-bound runtime input. A freely reloadable text file
would weaken the deployment identity.

## Contract rules

The rendered contract requires the agent to:

1. treat live runtime state and concrete receipts as higher-authority than prose;
2. use the narrowest typed read tool that can answer the question before broader
   surfaces, without adding a connectivity-only health ping when that required
   read can serve as the probe;
3. for a host-local capability intent, resolve the installed host contract first
   through `grabowski_host_capability_resolve`, follow its canonical authority and
   reread that authority's policy at execution time; Grabowski must not duplicate
   provider or model choices from the owning host contract;
4. determine mutation target, expected result, validation, stop condition and
   rollback before changing state;
5. verify target state after transport, platform-filter or policy failures and
   avoid unchanged retries without state evidence;
6. when ChatGPT or another upstream platform refuses a call before host dispatch
   and no Grabowski receipt exists, classify it as `platform_filter`, do not
   attribute it to the Grabowski runtime, do not retry the blocked call unchanged,
   and resume from existing lane or task receipts in a supported conversation when
   present;
7. after readback proves an upstream platform filter caused no effect, continue
   the authorized goal through an existing semantically narrower typed operation
   when available; never weaken, disguise, bypass or repackage the platform
   safeguard;
8. treat `platform_publication_pending` as nonblocking by default and fail closed
   only the operation whose required tool or schema field is not visible in the
   active client catalog; seek fresh request-bound catalog evidence instead of
   blocking unrelated Grabowski work;
9. use the normal mutating MCP call path and the server-owned transport-roundtrip
   continuation when a fresh challenge is returned; ambiguous mutation outcomes
   still require target readback before any retry;
10. prefer typed operations to generic terminal, Git or GitHub calls when both can
    express the effect;
11. for nontrivial operator work, use the durable operator-obligation lifecycle to
    resume matching unfinished work and close only with completed, explicitly
    blocked or durably delegated evidence;
12. bind and assess risk-adaptive convergence evidence before claiming systemic
    convergence when the convergence plan requires it; ordinary work completion is
    not itself a systemic-convergence claim;
13. treat the instructions as non-authoritative: they grant no action, merge,
    deploy, secret or retry authority.

The executable rules in `AGENT_INSTRUCTION_RULES` are the source of truth if
this explanatory list drifts.

A refusal that occurs before host dispatch cannot be observed or recorded by the
Grabowski server itself. The client/controller must therefore keep that boundary
explicit: absence of a Grabowski receipt plus an upstream refusal is evidence of a
pre-runtime platform filter, not evidence that the Grabowski runtime rejected the
operation.

Likewise, platform publication is an operation-local compatibility concern. A
pending platform publication does not globally disable an otherwise healthy
runtime; only an operation that depends on a tool or schema field missing from the
active client catalog must stop until fresh catalog evidence exists.

The obligation lifecycle is durable server-side state, not proof that a client
actually followed the rule. An open obligation reports `response_may_end=false`;
completed and blocked evidence is SHA-256-bound, while the close grip itself
live-observes and binds a durable task, workspace or job before delegation. See
`docs/operator-obligation-contract-v1.md`.

## Rendering invariants

The renderer fails closed unless:

- every rule identifier is unique;
- identifiers and rule text are non-empty single lines;
- the UTF-8 result is at most 4,096 bytes;
- the first line identifies the contract version and schema.

The v1 header has this form:

```text
Grabowski agent-facing contract <version> (schema <positive integer>).
```

Changing the header grammar or its interpretation is a breaking contract change
and requires an explicit schema/version migration. Existing manifests must not
be silently reinterpreted.

## Deployment binding

The deployment tool reads the exact instructions returned by a real MCP
`initialize` request and derives this identity:

- schema version;
- contract version;
- SHA-256 of the UTF-8 bytes;
- actual byte length;
- maximum byte length.

That identity is stored in deployment-manifest schema 6. The same manifest also
binds declared non-Python runtime assets, including the canonical coding-agent
catalog, to their release-relative paths and SHA-256 values. Deployment
validation, pre-activation probing, post-activation probing, deploy-check and
runtime status compare the exact identities. Any mismatch blocks or marks the
deployment as invalid rather than accepting instruction, source or runtime-asset
drift.

The MCP `InitializeResult.instructions` field is optional at protocol level.
Grabowski deliberately makes a valid, exact value mandatory for its own runtime.
If the framework stops returning the configured value, deployment fails closed.

## Independent validation boundary

The runtime producer and deployment verifier intentionally retain independent
validation logic. Importing all verifier expectations from the producer would
allow a shared defect to validate itself. Constant drift can therefore cause a
safe deployment failure; it must not cause silent acceptance of a different
contract.

## What the contract establishes

A healthy runtime with a valid manifest establishes that:

- the server rendered one known contract version;
- the deployed manifest records the exact instruction identity;
- the live MCP initialize response matches that identity;
- runtime status can detect server-side instruction drift.

## What the contract does not establish

It does not prove that:

- a connector has a fresh client-side snapshot;
- the client inserted the instructions into the model context;
- an agent read, understood or followed the instructions;
- an individual tool behaves correctly;
- a future action is authorized.

Runtime status therefore reports `client_compliance_observable: false` and lists
`client_instruction_compliance` among the claims it does not establish.

## Client behavior evidence

Future observability should report evidence per rule rather than a misleading
single compliance boolean. Potentially observable signals include typed versus
generic tool selection, unchanged retries after ambiguous failures and mutation
readback. Internal intent, comprehension and complete optimal-tool selection are
not directly observable.

Any future implementation must expose:

- which rule is being evaluated;
- the concrete events used as evidence;
- coverage and unobservable dimensions;
- false-positive and false-negative limits;
- no inference about private reasoning.

## Verification

Focused tests are in `tests/test_agent_instructions.py`. Deployment-path tests
cover manifest validation, real initialize probing and exact identity drift.
Run the repository validation suite before merge and the deployment check before
activation.

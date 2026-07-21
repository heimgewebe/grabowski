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
   surfaces;
3. determine mutation target, expected result, validation, stop condition and
   rollback before changing state;
4. verify target state after transport, platform-filter or policy failures and
   avoid unchanged retries without state evidence;
5. prefer typed operations to generic terminal, Git or GitHub calls when both can
   express the effect;
6. for nontrivial operator work, first call `operator-obligation-list` through
   `grip_run` to find matching interrupted work, then call
   `operator-obligation-open` or resume the matching obligation, read
   `operator-obligation-status` before ending the response, and end only after
   `operator-obligation-close` records `completed`, explicitly `blocked`, or
   durably `delegated`;
7. treat the instructions as non-authoritative: they grant no action, merge,
   deploy, secret or retry authority.

The executable rules in `AGENT_INSTRUCTION_RULES` are the source of truth if
this explanatory list drifts.

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

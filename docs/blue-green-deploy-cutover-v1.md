# Blue-Green Deployment and Connector Convergence Cutover v1

## Purpose

The stop-the-world dual-service deploy path stops tunnel and operator, switches
the release pointer, then starts the replacement. That path depends on a global
admission drain that waits for every active tool call, including long-lived
reads.

Blue-green cutover v1 separates those concerns for the agent-driven execution
fabric:

1. start a green runtime in parallel with blue;
2. verify green against manifest identity, tool names, schemas, sentinels and
   the agent-facing Bedienvertrag;
3. switch the connector atomically;
4. rebind the connector snapshot as part of that cutover;
5. close blue for new mutations while admitted reads drain;
6. terminalize only active effect-bearing calls before retirement;
7. emit one deployment receipt that binds runtime, names, schemas/sentinels,
   snapshot and Bedienvertrag without rewriting manifest, provenance or audit
   history.

## Roles

| Role | Meaning |
| --- | --- |
| `active` | Current authoritative serving process (blue before cutover, green after). |
| `standby` | Parallel green process under verification. |
| `retiring` | Former blue process closed for new mutations after cutover. |

## Drain policy

- New effect-bearing calls on blue are refused after `close_for_mutations`.
- Already admitted reads may continue and never block retirement.
- Only active effect-bearing identities are terminalized before blue stops.
- There is no global dependency on long-lived reads becoming zero.

`grabowski_serving_process.is_stale` remains the operator mutation gate: after
mutations are closed, or after the deployed manifest identity diverges from the
process freeze, mutations are refused. Reads stay available.

## Phases

```text
prepare
  -> start_green
  -> verify_green
  -> pre_cutover_ready
  -> cutover            # atomic connector switch + snapshot rebind
  -> post_cutover       # close blue mutations
  -> terminalize_effects
  -> retire_blue
  -> completed
```

Failure classification:

- **Pre-cutover** (`prepare` … `pre_cutover_ready`): rollback green, leave blue
  authoritative, outcome `rolled_back`.
- **Post-cutover** (`cutover` … `retire_blue`): do not invent automatic pointer
  reversal; outcome `outcome_unknown` and recovery readback are required.

## Deployment receipt

Kind: `grabowski_blue_green_deployment_receipt`.

Bound fields include:

- cutover id and generation;
- expected repository head;
- blue and green release ids;
- source-identity digest;
- tool-name digest;
- Bedienvertrag (`agent_instructions_sha256`);
- required schema sentinels;
- green readiness probe;
- snapshot rebind receipt hashes;
- effect-terminalization counts;
- ordered cutover observations.

The receipt preserves manifest, provenance and audit integrity by reference. It
does not rewrite those stores.

## Connector snapshot rebind

Snapshot rebind is not a later best-effort refresh. `rebind_for_cutover` binds
the client-declared tool surface and optional schema sentinels to the green
server contract with an explicit `cutover_id` and `cutover_generation`. A
mismatch fails closed before cutover completion evidence is emitted.

## Convergence

`build_blue_green_deployment_profile` and `build_blue_green_assessment_request`
project a receipt into the existing convergence request shape. Supplied
evidence still cannot, by itself, claim terminal closure; authoritative
readback remains required for high-risk completion.

## Module map

| Module | Responsibility |
| --- | --- |
| `grabowski_serving_process` | Process freeze, role, mutation close, effect-bearing registry and terminalization |
| `grabowski_connector_contract` | Green readiness against names, schemas, sentinels and Bedienvertrag |
| `grabowski_client_snapshot` | Cutover-bound snapshot rebind |
| `grabowski_deployment_observer` | Phase classification and cutover observations |
| `grabowski_self_deploy` | Plan, execute, receipt construction |
| `grabowski_convergence` | Receipt-bound convergence profile and assessment request |

## Non-claims

This cutover protocol does not:

- grant deploy, merge, secret or privileged authority;
- prove platform-enforced remote connector identity;
- wait for every long-lived read to finish;
- rewrite deployment manifests, provenance or audit chains;
- automatically reverse a post-cutover connector switch on failure.

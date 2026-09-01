# Blue-Green Production Cutover v1

## Authority and topology

The normal scheduled deployment is a real blue-green cutover. The public
connector path remains continuously authoritative:

```text
tunnel -> signed ingress 127.0.0.1:18180
                         |-- canonical operator 127.0.0.1:18181
                         `-- transient green  127.0.0.1:18182
```

Ingress accepts exactly those two loopback operator slots. It does not accept
an operator URL from a request, environment variable, or general-purpose
configuration. OAuth discovery, the connector capability, and signed mutation
assertions remain at the existing ingress boundary.

The ingress user unit is independent of `grabowski-operator.service`: it has no
`Wants`, `After`, or `PartOf` relationship to that service. Stopping the
canonical operator therefore does not stop ingress or the tunnel-facing
authority.

## Routing selector

Ingress reads
`~/.local/state/grabowski/transport-connectors/operator-routing-selector.json`
for every proxied request. The selector is an owner-only, bounded JSON file and
contains:

- a monotonic generation and one of the fixed slots `canonical` or `green`;
- the corresponding fixed port, 18181 or 18182;
- release id, repository head, registered-name hash, and agent-instruction
  hash;
- the hash of that runtime binding;
- cutover id and predecessor selector hash;
- a hash over the complete unsigned selector.

Writers serialize with an owner-only lock, require the expected current
selector hash (CAS), publish by atomic replace, fsync the file and directory,
and read it back. Ingress health reports the same selector and binding so the
deployment can compare storage authority with live routing authority.

An installation that predates the selector-aware ingress must be migrated once
through the explicit bootstrap/recovery path. `make deploy-apply` is gated by
`BOOTSTRAP_RECOVERY=1`; it may initialize the canonical selector while the old
ingress is stopped. The scheduled path never invokes this stop-the-world path.

## Productive sequence

`tools/run_scheduled_deploy.py` validates the exact source and calls
`run_production_blue_green_cutover` directly under the existing deployment
lock. The sequence is:

1. Verify the canonical blue selector, ingress health, source identity,
   runtime manifest/provenance, connector surface continuity, and a fresh
   authentic external connector snapshot.
2. Build the immutable release and start a transient user service from that
   release's Python on 127.0.0.1:18182.
3. Probe green through real MCP `initialize`, paginated `tools/list`, and
   read-only `grabowski_status`. Bind release, head, tool names, complete
   schemas, required sentinels, and agent instructions.
4. If the Green agent-instruction hash differs from Blue, build a read-only
   instruction-transition preflight before any drain or selector mutation. The
   transition binds the exact Blue and Green release/head/instruction identities
   to independently verified Green readiness and to the scheduled deployment
   source-identity hash. A missing or mismatched source identity fails while Blue
   is still authoritative. The historical Blue client declaration is not
   rewritten and is never treated as evidence that a client observed Green.
5. Engage the current operator's deployment admission marker. The cross-process
   status endpoint reads the live registry in `grabowski_operator.py`. New
   normal calls are rejected while promotion is in progress; only previously
   admitted effect-bearing calls block settlement. Previously admitted read-only
   calls remain non-blocking. The marker stays active until routing is back on
   canonical and transient Green is confirmed stopped.
6. CAS-switch ingress to green and verify selector-file plus live ingress
   readback. Probe green again through 18180.
7. Rebind the connector snapshot using the exact declaration and hashes from a
   fresh, previously observed external-client receipt. Tool/schema transitions
   retain their Publication-v2 authorization. An agent-instruction transition
   must reproduce the exact pre-switch transition record and source-identity
   binding; the preserved Blue declaration remains historical evidence only.
8. Activate the stable runtime pointer, replace the canonical operator behind
   still-authoritative green, verify it, CAS-switch ingress to canonical, and
   complete MCP initialize/tools-list/minimal-status readiness through 18180 while
   Green is still live and mutation admission remains closed. Only then retire
   transient Green and reopen normal admission.
9. Persist the blue-green receipt and expose its SHA in scheduled logs and job
   finalization.

## Call-registry truth

`grabowski_operator.py` owns the actual admitted-call registry at the MCP tool
execution boundary. Its observation separates drain-blocking effect calls from
read-only calls and includes an observation hash, authority label, and
terminalization state. Deployment receipts hash the marker-bound observation
and final guard.

`grabowski_serving_process.py` remains useful for local process modeling and
generic orchestration tests. Its bookkeeping is not production evidence for
the live operator and is never cited as such by the productive cutover.

## Snapshot authenticity

Production rebind requires all of the following:

- a hash-valid, unexpired receipt with external-client observation scope;
- schema probe evidence that matched the declared server surface;
- the observed blue release and repository head;
- a complete Blue tool/schema declaration. Tool-count/name/schema changes require
  the existing Publication-v2 transition contract; legacy snapshots without the
  complete schema identity remain readable but cannot authorize such a cutover;
- for a changed agent-instruction hash, a separate self-hashed transition bound
  to the exact deployment source identity, Blue release/head/instruction hash,
  Green release/head/instruction hash, and independently observed Green readiness;
- non-degenerate declaration, receipt, artifact, names, instruction, and
  deployment-source hashes;
- independently observed green readiness.

The instruction transition is deliberately not a client observation. After a
successful transition the runtime binding may be `matched`, but the preserved
Blue declaration remains historical: external-client observability for the new
Green instructions is false and `fresh_client_observation_required` remains true
until a real client observation is bound. Mid-cutover recovery obtains the exact
deployment source identity from the durable cutover receipt and must satisfy the
same canonical snapshot inspector; recovery does not receive a weaker transition
rule.

Missing or stale evidence, server-loopback-only evidence, and zero or other
single-character synthetic hashes fail closed. A preflight failure still
produces a typed `failed_pre_cutover` receipt with expected head, source
identity, error evidence, and `blue_preserved=true`.

## Failure and recovery semantics

- Before selector publication, failures release the admission marker, stop
  transient green, restore projected watchdog assets, and preserve blue.
- If selector publication reports an error, the selector is read immediately.
  Only an unchanged readable predecessor proves a pre-switch failure. A changed
  or unreadable selector is treated as a possible external effect.
- After a possible or confirmed connector switch, no automatic rollback is
  attempted. The outcome is `outcome_unknown`; selector storage and live ingress
  are read back and operator recovery is required.
- A completed outcome requires final canonical selector authority, live ingress
  agreement, canonical MCP readiness, transient-green retirement, tunnel and
  ingress service health, and stable runtime identity.

## Receipts

The durable `grabowski_blue_green_deployment_receipt` binds:

- expected head and scheduled source-identity hash;
- blue and green release ids;
- tool-name, schema-sentinel, and agent-instruction identities;
- green readiness;
- admission marker and live operator drain evidence;
- selector switch and its authoritative readback;
- authentic snapshot source and transition receipt hashes, including the
  self-hashed agent-instruction transition when instruction identity changes;
- stable promotion, final routing, final MCP readiness, and green retirement;
- ordered, individually hashed observations, outcome, and recovery action.

Receipts are owner-only, bounded, create-once files under
`~/.local/state/grabowski/blue-green-deployment-receipts/`. The receipt hash is
also included in the scheduled deployment summary and finalization receipt.

The receipt does not prove application success for already admitted mutations,
that the external platform refreshed after rebind, or resistance to compromised
same-uid code.

## Preserved gates

The cutover retains exact source identity, the deployment lock and contention
preflight, watchdog and safety-observer assets, transport OAuth, signed mutation
assertions, sidecar reconciliation, runtime manifest/provenance verification,
audit handling, and existing recovery gates. It does not deploy, push, merge,
or change Fleet registration by itself.

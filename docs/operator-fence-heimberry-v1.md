# Heimberry Operator Fence v1

Status: G6.3 production transport plus terminal G6.4 shadow contract. G6.5 adds opt-in fail-closed mutation enforcement; automatic failover routing remains out of scope.

## Purpose

Heimberry is the single online authority for which operator may perform globally fenced mutations. The durable state is owned only by a dedicated Heimberry fence account and uses `OperatorFenceStore` from `src/grabowski_operator_fence.py`.

The two callers are exactly:

- `grabowski` on heim-pc;
- `der-kleine-maulwurf` on wg-prod-1.

The transport deliberately adds no TCP daemon and no shared filesystem. Each request is one bounded JSON document over an SSH connection whose host identity and client key are pinned. Heimberry executes one forced command, handles exactly one request, writes exactly one response, and exits.

G6.3 deliberately stopped at authenticated coordinator transport. G6.4 later wired the fence into `grabowski_effect_interceptor` in observation-only shadow mode and proved that the observer had zero Heimberry effect. G6.5 keeps that shadow evidence but adds a separate opt-in enforcement config for mutating effects. It still does not automate failover or failback and grants no root, secret, generic shell or destructive authority.

## Authority boundary

A production fence MUST NOT run as the ordinary Heimberry `alex` account. Grabowski already has normal fleet access to that account; if `alex` owned the fence database, the primary operator could modify the purported third-party authority through an unrelated SSH path.

The production deployment therefore uses a dedicated OS identity, named here `operator-fence`, with these properties:

- no sudo/admin membership;
- a locked password and no interactive password login;
- no ordinary shell-authorized SSH key;
- only the two dedicated forced-command public keys;
- a root-owned, non-writable login home and SSH authorization policy;
- a separate private state directory owned by `operator-fence` and not writable by `alex` without root escalation;
- an immutable/versioned reviewed runtime path that `operator-fence` can execute but cannot rewrite.

The login home and mutable fence state MUST be different directories. A suitable layout is:

```text
/var/lib/operator-fence-home/           root:operator-fence 0750
/var/lib/operator-fence-home/.ssh/      root:operator-fence 0750
/var/lib/operator-fence-home/.ssh/authorized_keys  root:operator-fence 0640
/var/lib/operator-fence/                operator-fence:operator-fence 0700
```

This prevents the forced-command account from replacing its own `authorized_keys` policy while still allowing `sshd` to read the root-owned authorization file under `StrictModes`; the `operator-fence` group has read/traverse access but no write bit. The account needs an executable shell such as `/bin/sh` because `sshd` uses the login shell to start the forced command; the locked password and root-owned authorization home, not a `nologin` shell, enforce the non-interactive boundary.

Root remains capable of repairing the host and is outside the normal online writer model. Such repair is recovery/break-glass, not ordinary failover authority. G6.4 must ensure that operator-originated mutating fleet/root paths cannot be used to bypass the fence.

A temporary `alex`-owned deployment may be used only as a clearly separate G6.3 canary to prove wire behavior. Its generation/state must never be promoted as production authority.

## Peer identity

The SSH key selected by Heimberry determines the peer identity. Request bodies cannot supply `owner_id` or `reconciler_id`.

A forced-command entry for the primary invokes the server with:

```text
--peer-id grabowski
```

A separate forced-command entry for the secondary invokes it with:

```text
--peer-id der-kleine-maulwurf
```

The server injects that peer identity into `acquire`, `renew`, `begin`, `settle`, `reconcile` and `release` calls. This prevents a client from presenting itself as the other operator at the RPC layer.

## Heimberry production state

Recommended production state path:

```text
/var/lib/operator-fence/fence.sqlite3
```

The directory and all durable state are owned by `operator-fence`. The ordinary `alex` account must have no write permission there without explicit root escalation.

`OperatorFenceStore` owns the SQLite database and its private durable sidecars. Generation/anchor reconciliation, in-flight state, settlements and replay protection remain properties of the G6.2 core; the RPC layer does not create a second truth.

A canary path, if needed before the service account can be provisioned, must be visibly distinct, for example:

```text
/home/alex/.local/state/grabowski/operator-fence-g6.3-canary/fence.sqlite3
```

Canary epochs establish no production high-water value.

## Server installation

Install the exact reviewed files from one commit-bound Grabowski source under a versioned path not writable by the `operator-fence` account, for example:

```text
/opt/grabowski-operator-fence/<commit>/src/grabowski_operator_fence.py
/opt/grabowski-operator-fence/<commit>/src/grabowski_operator_fence_rpc.py
/opt/grabowski-operator-fence/<commit>/tools/grabowski_operator_fence_rpc.py
```

The wrapper adds its sibling release `src/` to `sys.path`. Do not run production authority from a mutable checkout. The repository wrapper is intentionally not required to be executable; the forced command invokes the fixed system interpreter `/usr/bin/python3 -I` explicitly. Isolated mode ignores Python environment variables and the user site before the wrapper pins the reviewed release `src/` path.

No service needs to listen. `sshd` starts the forced command on demand.

## Dedicated SSH keys

Use a different client key for each operator. Do not reuse either operator's normal administrative SSH identity.

Each client private key must be owned by its operator account and mode `0600`. The client helper uses `IdentitiesOnly=yes` and `IdentityAgent=none`, so an agent-loaded administrative key cannot silently replace the selected fence identity.

The public halves are the only SSH keys authorized for `operator-fence`, with separate forced commands. The authorization file is root-owned as described above. Schematic entries:

```text
restrict,command="/usr/bin/python3 -I /opt/grabowski-operator-fence/<commit>/tools/grabowski_operator_fence_rpc.py serve --state-path /var/lib/operator-fence/fence.sqlite3 --peer-id grabowski" ssh-ed25519 <PRIMARY-PUBLIC-KEY>
restrict,command="/usr/bin/python3 -I /opt/grabowski-operator-fence/<commit>/tools/grabowski_operator_fence_rpc.py serve --state-path /var/lib/operator-fence/fence.sqlite3 --peer-id der-kleine-maulwurf" ssh-ed25519 <SECONDARY-PUBLIC-KEY>
```

`restrict` denies forwarding, PTY and related SSH side channels. The RPC server additionally requires the client-supplied original command to be exactly:

```text
operator-fence-rpc-v1
```

Any other original command is rejected before the fence state is opened.

## Host identity pinning

Each operator uses a dedicated private `known_hosts` file containing the trusted Heimberry host key. The client requires:

- an absolute regular file;
- current-user ownership;
- one hard link;
- no group/world write permission.

`ssh` is invoked with `-F /dev/null`, `StrictHostKeyChecking=yes`, an explicit `UserKnownHostsFile`, `GlobalKnownHostsFile=/dev/null`, disabled proxy/jump/multiplexing/agent paths and an explicit `HostKeyAlias`. DNS/Tailscale name resolution therefore does not replace host-key verification.

## RPC contract

One request per SSH process. Maximum request size: 32 KiB. Maximum response size: 256 KiB.

Allowed operations:

- `status`
- `acquire`
- `renew`
- `begin`
- `settle`
- `reconcile`
- `release`

The request shape is exact:

```json
{
  "schema_version": 1,
  "kind": "grabowski.operator_fence_rpc_request",
  "request_id": "bounded-id",
  "operation": "status",
  "arguments": {}
}
```

The response is bound to both `request_id` and the expected authenticated `peer_id`. A mismatching peer or request is a transport-contract failure, not an application result.

Authentication establishes which operator made the request; it does not by itself prove an external effect. In particular, `reconcile` still consumes the G6.2 evidence digest contract. G6.4 must bind reconciliation to an actual target-state readback/typed proof before automatic failover may rely on it.

## G6.5 enforcement contract

Enforcement is enabled only by a safe `0600` client file at:

```text
~/.config/grabowski/operator-fence-enforcement.v1.json
```

Absence of that file preserves the G6.4 shadow-only behavior. Presence of an invalid enforcement file fails closed for mutating effects; it never silently falls back to shadow-only mutation.

The config binds exactly one peer, the pinned Heimberry SSH transport, the expected fence instance, a durable minimum generation and a bounded lease duration. The central MCP mutation boundary uses the existing effect-admission identity as the fence intent:

```text
transport admission
  -> deterministic effect admission
  -> fence acquire
  -> fence begin(admission_sha256)
  -> durable local phase = dispatching
  -> domain effect
  -> effect completion
  -> fence settle(completion_sha256)
  -> fence release
```

Read-only tool calls do not acquire the fence. Exact read-only transport exemptions and the transport handshake remain available. A mutating transport exemption that cannot produce the normal mutation identity is rejected while enforcement is active; it is never allowed to execute unfenced.

### Durable client recovery

Each enforcing peer keeps a private `0600` state file at:

```text
~/.local/state/grabowski/operator-fence-enforcement-state.v1.json
```

It records a monotone local generation high-water mark and at most one pending effect. The phases are `prepared`, `granted`, `begun`, `dispatching`, `completion_ready`, `outcome_unknown` and `settled`.

Recovery is deliberately conservative:

- `prepared` re-enters the same acquire idempotently;
- `granted` re-enters the same begin idempotently;
- `begun` proves the domain dispatch was never marked and settles `effect_not_applied`;
- `dispatching` without completion becomes `outcome_unknown`;
- `completion_ready` retries only the same fence settlement, never the domain effect;
- `outcome_unknown` blocks a new effect until authoritative reconciliation has resolved the Heimberry inflight record;
- `settled` retries release or proves through status that the old grant is no longer authoritative.

The Heimberry `inflight` record, not a client renewal loop, is the takeover barrier once `begin` succeeds. A writer lease may expire while a long effect is running; the unresolved inflight operation still blocks another peer.

### Minimal secondary profile

The G6.5 `failover-mutate` access profile is intentionally narrower than the normal `mutate` profile. It grants exactly:

```text
file_read
file_write
rollback_text
audit_verify
audit_read
bureau_mutation
git_cli
github_cli
resource_lease
artifact_transfer
process_inspect
port_inspect
```

Its write roots are limited to the repository tree and the Grabowski/Bureau local state roots. It does not grant `terminal_execute`, user-service control, browser/GUI workers, browser-profile access, secret capabilities, process signals, privileged/power execution or delete/destroy authority.

`bureau_mutation` is a separate capability for the typed candidate/proposal/review/publication/pickup surfaces. It does not authorize `grabowski_terminal_run` and does not create a second Bureau mutation path.

`durable_job` is deliberately absent from `failover-mutate` in G6.5. Its current start surface accepts general argv and would therefore reintroduce generic command/host-mutation authority through a different transport. A later slice may add a separately typed bounded durable-work capability; the broad existing capability remains available only to the normal higher-authority profiles.

## Failure semantics

If Heimberry or SSH is unavailable, the RPC client fails closed. G6.4 must interpret that as **no mutation authority**. It must not fall back to a local fence, stale cached lease or the other operator.

Read-only operator paths remain independent of the fence. Heimberry loss therefore means:

```text
READ  = allowed by the normal local read policy
WRITE = denied because no fresh global fence decision exists
```

A live writer lease denies the other peer. An unresolved in-flight effect continues to deny takeover after lease expiry. `outcome_unknown` must be reconciled through the same authoritative Heimberry store before a new writer can be acquired. Authentication alone is insufficient evidence to settle the effect; automatic reconciliation belongs to G6.4's typed readback integration.

## Recovery boundary

Heimberry is online coordination, not backup recovery. BACKUP remains the offline recovery authority. Rebuilding Heimberry must preserve the G6.2 high-water/generation contract and must never reset an old generation into validity.

The detailed coordinator-recovery procedure and cross-host highest-generation recovery proof belong to a later recovery/cutover slice; G6.3 only provides the authenticated single-state transport.

## G6.3 acceptance

G6.3 is complete only when all of these are evidenced:

1. the RPC and G6.2 core tests pass together;
2. production state is owned by the dedicated `operator-fence` identity, not `alex`;
3. the account cannot rewrite its own SSH authorization policy or reviewed runtime;
4. each peer identity is forced by a distinct SSH key;
5. Heimberry host identity is pinned by each client;
6. a real primary `status/acquire/release` round trip succeeds against Heimberry;
7. a second client cannot acquire while the first writer lease is live;
8. an unresolved in-flight operation prevents takeover after lease expiry;
9. the normal `alex` account cannot write the production fence state without root escalation;
10. no new public listener exists on Heimberry.

Secondary credential provisioning may be completed with G6.5 only if G6.3 remains explicitly non-production. Production authority is not declared until both peer identities and the dedicated service-account boundary have real host evidence.

## Next slices

- **G6.4:** terminally accepted: central read-only shadow observation, live zero-effect proof and failure/performance matrix.
- **G6.5:** this contract: opt-in central enforcement plus the minimal `failover-mutate` secondary profile, followed by exact primary/secondary deployment and a controlled manual writer handoff canary.
- **G6.6:** implement classified automatic failover/failback routing; policy, safety, CI, GitHub, Bureau and authority denials are never failover triggers.
- **G6.7:** adversarial race, partition, stale-generation, response-loss, in-flight-death and coordinator-death drills.
- **G6.8:** Stage-A production cutover, scheduler routing, observability and final recovery/failback evidence.

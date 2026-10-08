# Day-1 signed task-proof verifier v1 — read-only, not activated

Status: **draft protocol, verifier only, not a capture provider, not an admission grant.** Owning issue: [Grabowski #1387](https://github.com/heimgewebe/grabowski/issues/1387). Related blocked consumer: [heim-pc #197](https://github.com/heimgewebe/heim-pc/pull/197).

## Problem and scope

The present Grabowski ordinary task runs under the operator UID. Its `stdout.log`, canonical v2 receipt self-hash, SQLite ledger and mutable source path share a trust domain. Recomputing all hashes produces an internally consistent forgery. The actual protected task-capture parent, immutable executed source closure, trusted request nonce and crash-consistent protected publisher **do not currently exist**.

The separate [Draft PR #1388](https://github.com/heimgewebe/grabowski/pull/1388) explicitly reports `day1_admission_authorized=false` for all current backends. This module does **not** supersede or weaken that decision.

This verifier implements only a potential *future* detached SSH-signature and byte-binding reader. It is currently **not registered as an MCP tool, not wired into `grabowski_tasks`, not a rootbroker command and not deployed**. Its return value is always `day1_admission_authorized=false` even if the test signature and all proof fields verify.

## Proposed signed byte contract

The protected parent would produce a canonical UTF-8, sorted compact JSON payload with an ending newline. It declares exact fields: schema/kind/issuer/capture-boundary, host, task ID/attempt/unit, canonical argv SHA-256, executed source SHA-256, complete immutable execution closure digest, independently issued one-time nonce, actual stream byte counts/digests and complete/truncated flags for stdout and stderr, start and terminal times, and terminal state/exit code. The schema is exact: unknown, missing, legacy or noncanonical fields are rejected.

The detached signature is SSHSIG with fixed principal `grabowski-day1-capture@heimgewebe` and fixed namespace `grabowski-day1-task-proof-v1@heimgewebe`, using OpenSSH `ssh-keygen -Y verify`. A root-owned policy is read only from `/etc/grabowski/day1-capture-allowed-signers`; no caller-selected key or trust-file path exists in the public API. The trusted file and **all its directory ancestors** must be root-owned and not group/world writable. The regular policy file must have one link, no symlink, fixed bounds and stable descriptor identity.

The verifier snapshots proof, signature, stdout and stderr as bounded **bytes** before checking; it does not follow mutable output paths. The signature and allowed-signers policy are presented to `ssh-keygen` via Linux `memfd_create` FDs after applying `F_SEAL_WRITE`, `F_SEAL_GROW`, `F_SEAL_SHRINK`, `F_SEAL_SEAL`, not via replaceable temporary pathnames. Signature failure, no sealed FDs, missing protected trust policy, mismatched nonce/context, altered streams, missing completion, truncation, oversized output, stale/future observation and failed exit all fail closed.

## Explicit non-claims

**A valid signature authenticates a statement from the allowed signer, not the truth of that statement's capture/process claims.** This verifier **does not establish**:

- that a root/dedicated-UID parent actually observed the child pipes;
- that the exact claimed executed source and its transitive runtime imports were loaded from an immutable reviewed closure;
- that the protected signer key was ever generated, installed or kept away from the task UID;
- that the declared task/attempt/nonce was independently issued and bound by the trusted operator;
- that the captured bytes were atomically published or are unchanged at a current mutable filesystem path;
- the real renderer generation time or productive Day-1 readiness.

Only an **actual separate** protected provider with an immutable packaged executable closure, direct parent-owned pipe capture, one-time request identity, key custody, atomic protected commit and independent deployed readback can close [#1387](https://github.com/heimgewebe/grabowski/issues/1387). The eventual consumer/publisher contract in [heim-pc #199](https://github.com/heimgewebe/heim-pc/issues/199) and renderer-time contract in [#198](https://github.com/heimgewebe/heim-pc/issues/198) must also be proven.

## Tests and release/rollback boundary

Adversarial tests use disposable generated ED25519 keys and **synthetic** fixture receipts; they prove only rejection semantics and local signature verification, never positive real-host provenance. Include test cases for unchanged bytes, forged signer, altered signed bytes, wrong namespace/nonce/task/source, unkeyed legacy v2 self-hash, truncation, symlinks, missing root-owned trust store, timestamp bounds, and absent kernel sealing.

No private keys or production signed material are in this repository. No deploy is authorized by this module. Integration into an actual protected capture/signing service requires a separate narrowly scoped implementation, code/CI review, explicit authority contract and independent deployed host evidence; otherwise this code remains read-only and non-admitting. Rollback is simply withdrawing the unused draft source branch.

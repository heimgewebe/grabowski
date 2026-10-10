# Day-1 Task Output Attestation — trust-boundary contract v1

Status: **proposed, fail-closed, NOT IMPLEMENTED**. Source: [grabowski#1387](https://github.com/heimgewebe/grabowski/issues/1387); consumer: [heim-pc#197](https://github.com/heimgewebe/heim-pc/pull/197). This is a design and safety boundary, **not** a rootbroker deployment, an authenticated host inventory or a Day-1 admission grant.

## Current verified state (2026-10-08)

- Ordinary tasks run via `systemd-run --user`. `TASK_OUTPUT_CAPTURE_CODE` opens files under the task owner's `~/.local/state/grabowski/task-output` using `0700` directories and `0600` output files, drains stdout/stderr from pipes, and fsyncs the retained bytes. This protects against *other* UIDs, not a process with the **same** UID.
- The controller then records terminal state in a user-writable task SQLite ledger, emits a create-only user-owned `tasks.outcomes/<task-id>.json` lifecycle receipt and stores its **unkeyed** canonical `receipt_sha256` back in the same ledger. Recomputing all three is possible for that UID. Existing v2 lifecycle receipts contain no `captured_stdout_sha256` or `captured_stdout_bytes`.
- `TASK_OUTPUT_CLEANUP_CODE` can hash and count bytes when inspecting a stored output later. Its inventory is an **after-the-fact** snapshot of those user-owned paths, not a task-time, independently authenticated capture.
- The existing `systemd-root-broker` backend is selected for a narrow recovery command category and its catalog currently covers the approved handoff operations. It is not a generalized Day-1 inventory executor or attestation service. Broadening its executable prefixes does not establish that its child executed reviewed source.
- Collector or renderer paths in the user-writable worktree may be changed before Python opens them and restored before a *later* hash check. A signature over a subsequent result does not authenticate the code that was actually executed.
- This was demonstrated with the isolated heim-pc test fixture: edited inventory + stdout + receipt + ledger passed the Binder (`FORGED_BINDING_ACCEPTED`). No productive task state was changed.

## Required trust separation

The capture **authority** MUST not be the task UID or any process/data store that the task UID can rewrite, ptrace, signal or replace. It MUST own the capture boundary **before** executing the reviewed program, not merely sign its later output file. A possible provider is a narrowly catalogued root-owned service using a dedicated lower-privilege child UID and a root-owned capture/receipt store. It is a proposal, not an existing facility. Any implementation MUST prove:

1. A root-owned (or separately protected) launcher admits only an exact, reviewed, packaged **immutable program closure**, for example a Nix-store executable with a pinned derivation/closure identity and constrained imports/environment. A mutable path supplied in user-controlled argv is not sufficient. Python imports, entrypoint, libraries and child helpers must be included in the executed-code trust claim.
2. A protected parent obtains the child's stdout/stderr **directly from its pipe** or an equivalent protected FD. The child/task UID cannot change capture buffers, trusted output metadata, or the parent. If captured stdout is truncated, missing, incomplete or exceeds the policy bound, the result is **not Day-1 eligible**.
3. The protected authority binds canonical host identity, invocation and immutable program closure, `task_id`, `attempt`, `unit`, argv digest, execution context, source revision, nonce, capture start/stop evidence, terminal status, `captured_stdout_sha256`, `captured_stdout_bytes` and explicit truncation/completeness semantics in one immutable/protected attestation. Hashes in a user-owned SQLite row or self-hashed receipt do not count as protection.
4. A non-user-mutable authority is independently read back by the consumer: a root-owned, descriptor/no-follow verified store accessed via a strictly scoped read broker, **or** a detached signature verifiable under a separately pinned root-owned key/identity. No reusable signing oracle, arbitrary root command, shell, or caller-controlled path is admitted.
5. The publication order is crash-consistent: capture completion and flush first; protected attestation commit second; only then ordinary user-ledger projection. Missing attestation after crash/retry/recovery stays blocked. A retry uses a different attempt/nonce. No post hoc seal/backfill for legacy v1/v2 receipts.
6. Final consumers verify these independently protected exact bytes again and treat the observation as historical. They cannot infer that mutable canonical `runtime/...` filenames have remained unchanged. The atomic immutable Evidence/Consumer contract is separately tracked by [heim-pc#199](https://github.com/heimgewebe/heim-pc/issues/199); genuine in-process renderer time by [heim-pc#198](https://github.com/heimgewebe/heim-pc/issues/198).

## Admission state machine (planned, not implemented)

`unavailable` → `captured_protected` → `terminally_sealed` → `independently_verified`.

Only `independently_verified` MAY provide evidence to Day-1 binding. All other states, including current `systemd-user` and current `systemd-root-broker` tasks, **must** return `day1_admission_authorized=false`. Receipt presence, mode `0600`, a self-consistent SHA-256 chain, or a successful `systemd` exit may not advance this state.

A later protected attestation should use a separately versioned contract, not silently reinterpret or mutate existing v2 lifecycle receipts. During migration, ordinary task consumers retain their existing fields, while Day-1 consumers reject old/unknown/unanchored evidence.

## Negative and positive acceptance tests for the provider

- Exact finished task with empty and nonempty stdout; output bytecount/hash and code closure readback from a **real deployed protected authority**; two independent reads agree.
- Spoof user-owned stdout file, terminal receipt and SQLite together, including recomputed unkeyed hashes: **deny**.
- Swap reviewed script just before Python load and restore it after; alter imports or helper binaries: **deny** or run the proven immutable closure.
- Replace path via symlink, hardlink, ancestor rename or FD race; delete or truncate output; present `0`-length/oversize output: **deny** unless an authenticated truly empty stream is proven.
- Mark truncated output as complete, reorder/replay old attempts, change unit/host/task ID, backdate timestamp or exchange receipts: **deny**.
- Crash before/after protected commit, retry/recovery, archived logs, ambiguous systemd terminal readback: **deny** or deterministic revalidation from the protected original; no backfill.
- Prove attacker model: task UID cannot write/ptrace protected producer, source closure, stored proof, root key or reader results. Independent observer reads actual UID/mode/mount/key custody, not only mocked permission bits.
- Verify negative gate with existing v2 receipts **even if an attacker adds digest fields**. Production host inventory, classification, readiness, NixOS/EFI/storage activation and merge must remain blocked until all positive checks are actually complete.

## This branch's bounded behavior

An additive **read-only task evidence diagnostic** may expose that both ordinary and current rootbroker task receipts are **not independently attested**; it cannot transform the present data into an attestation and cannot authorize Day-1 use. No output capture, policy, rootbroker, privileged command catalog, production service or existing v2 receipt is changed here.

The full provider must be designed, implemented, independently reviewed and deployed under its own scoped source, operational blast-radius, recovery and Captain gates before this issue can be closed.

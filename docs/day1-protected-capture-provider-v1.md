# Day-1 protected capture provider — prototype v1

**Status: source-only, disabled, not deployed, not eligible for productive admission.** Owner: [Grabowski #1387](https://github.com/heimgewebe/grabowski/issues/1387). Consumers: [heim-pc #197](https://github.com/heimgewebe/heim-pc/pull/197) (blocked), [#199](https://github.com/heimgewebe/heim-pc/issues/199) (protected Evidence/Consumer), [#198](https://github.com/heimgewebe/heim-pc/issues/198) (render-time evidence). Companion [Grabowski #1389](https://github.com/heimgewebe/grabowski/pull/1389) is an offline signed-proof verifier; [#1388](https://github.com/heimgewebe/grabowski/pull/1388) explicitly refuses Day-1 admission.

## What has been implemented

`tools/day1_protected_capture_provider.py` implements a *separate*, root-only, one-shot **actual capture/signing parent**. It does not use Grabowski's generic `systemd-root-broker`, does not introduce a new MCP callable, and does not allow an arbitrary executable, argv, shell, user-defined signing namespace or destination. The matching systemd unit is an **uninstalled `.example` with no `[Install]`/timer and `RefuseManualStart=yes`**.

Its exact control surface, which must be installed only through a separately approved trusted deployment, is:

| Root-only source | Purpose |
|---|---|
| `/etc/grabowski/day1-capture-policy-v1.json` | Root-owned bounded canonical policy, not task UID writable |
| `/usr/local/libexec/grabowski/day1-collector-static` | Fixed root-owned **static ELF64 x86-64 ET_EXEC**; pinned exact SHA-256 in policy |
| `/etc/grabowski/day1-capture-signing-key` | Root-owned `0600` dedicated SSH Ed25519 key, **never stored in Git** |
| `/var/lib/grabowski/day1-capture` | Existing root-owned `0700` evidence root |
| `grabowski-day1-collector` | Dedicated non-login, non-root system account with no other untrusted workloads |

All source/config/key path ancestors must be root-owned and not group/world writable. Symlinked ancestors/leaves, ambiguous inodes, non-regular/multiply linked files, unsafe modes, changed identity during source read and missing/oversize source bytes are rejected. The root-only parent validates the policy host against `socket.gethostname()`. No user-specified path or command is accepted.

### Exact root-owned policy example (documentation only)

```json
{
  "collector_sha256": "<SHA256_OF_INDEPENDENTLY_REVIEWED_STATIC_BINARY>",
  "host": "heim-pc",
  "kind": "grabowski.day1_protected_capture_policy",
  "max_stderr_bytes": 1048576,
  "max_stdout_bytes": 1048576,
  "runtime_seconds": 30,
  "schema_version": 1,
  "source_revision": "<EXACT_40_HEX_REVIEWED_SOURCE_REVISION>"
}
```

**The real file must be canonical compact UTF-8 sorted-key JSON with a final LF**, not this indented documentation example. The placeholders above are deliberately not usable. All real bytes must come from the separately approved root-owned installation; no signing key, account, program or policy was created by this PR.

### Physical execution boundary

1. The root parent opens and SHA-256-verifies the **actual root-owned executable FD**, not merely a user repository path. It requires a fixed static ELF64 x86-64 ET_EXEC binary **with no PT_INTERP or PT_DYNAMIC** (so no runtime dynamic library/loader or Python imports). It is never a shell/script. The reviewed build must establish and retain the exact binary/source binding. This is usable on the existing Pop!_OS host; there is no false dependency on having NixOS installed first.
2. The separately named dedicated collector process starts through `execve("/proc/self/fd/<opened-collector-fd>")`. That inherited descriptor names exactly the inode the root parent previously read and hashed. The parent drops the child to the dedicated UID/GID with no supplementary groups, and the child inherits **only** the opened executable FD, a sanitized environment, and stdin `/dev/null`. Neither the operator UID nor the dedicated collector UID can rewrite the root-owned code or root parent's buffers.
3. The root parent reads **both child pipes directly** via bounded nonblocking descriptors. Output overflow, nonzero exit, missing EOF, unexpected child/pipe failure or timeout **prevents signing and authoritative publication**. It terminates the process group on failures; systemd `KillMode=control-group`, memory/runtime/Task limits provide an additional external stop. There is no truncated stream promoted as complete.
4. Only after successful terminalization is one proof built, containing exact host/task/attempt/nonce/logical-unit/argv/source-binary/closure digests, observed byte hashes/lengths, actual start/end seconds and exit=0. A root-only signer verifies ownership/protection of the private key and signs the **canonical exact receipt bytes** using SSHSIG and fixed namespace `grabowski-day1-task-proof-v1@heimgewebe`, compatible with the proposed #1389 reader.
5. Root-only staging holds `stdout.bin`, `stderr.bin`, `proof.json` and `proof.sshsig`. Each file is create-only `0600`, read back and `fsync`ed, then the containing `0700` directory is atomically renamed from `.incomplete-...` to `proof-<task>-<nonce>` under the root-owned parent directory and the parent directory is `fsync`ed. A crash before rename leaves **no authoritative proof name**; an incomplete bundle is ignored. There is no mutable `current` symlink and no retroactive v2 receipt signing.

## Residual security and integration gates (not claims)

The policy's `source_revision` must be independently checked against a reproducible, reviewed binary build; a root-owned binary SHA does **not** prove that it implements the same semantics as the Python software-inventory collector. The first disposable/static test collector emits only fixture bytes; it is **not** the final Day-1 host software/program inventory contract. A reviewed, static/fully immutable equivalent of the real host collector, with verified data-access scope and no unpinned subprocess helpers, is still required. **Rejecting PT_INTERP/PT_DYNAMIC is insufficient to exclude secondary `execve` calls, static libc runtime loading, or a different program replacing the collector process.** No kernel-enforced child-exec prohibition or proven transitive executable closure is implemented in this draft. A real admission must independently close that gap through source/build verification and, where required, execution confinement; the current proof is not an independently authenticated full code closure.

The `unit` recorded by this isolated provider is currently a **logical attempt identifier** `grabowski-task-<task_id>-a1.service`, not independently linked to a live Grabowski `systemd-user` task. The only systemd unit in this source is the parent template. **The task lifecycle/nonce issuance and canonical v2 outcome receipt binding demanded by #1387 are not yet integrated**, and must be independently audited before Day-1 proof use. There is no claim of completed real host inventory, trusted runtime activation, or approved `current_binding`.

The signing key is checked as root-only, but the provider does not install, rotate or publish its **root-owned allowed signers** policy, nor register/enable the #1389 reader. A protected consumer that verifies *the original root-owned four-file bundle* (not a user-modifiable copied file or past checked mutable pointer) remains for [heim-pc #199](https://github.com/heimgewebe/heim-pc/issues/199). A successful signature of real pipes would prove only that this **independent dedicated collector** ran its reviewed binary; it does not automatically authenticate legacy `stdout.log`, mutable SQLite, or other user-UID tasks.

## Acceptance before installing/activating

- Package/install all root-owned paths **from frozen reviewed source** with rollback evidence, isolated source/package and private key custody; confirm path ancestors/inode/UID/mode via independent Observer. No policy edit or deployment in this PR.
- Create the dedicated no-login system UID/GID through a separately reviewed host provisioning contract. Prove it is not shared with the Grabowski controller nor any attacker-controlled child; confirm effective/saved UID/GID/no supplementary groups **at actual execution**.
- Independently observe on physical `heim-pc`: exact opened collector binary hash/inode, direct pipe full bytes, child/parent UIDs, protected key, signature check using a distinct root-pinned verifier authority, terminal unit/task ID and crash/retry-proof protected readback.
- Negative attacks must swap same-UID `stdout.log`, SQLite, lifecycle self-hash, source file, policy path, and post-terminal output; inject symlinks/races, forged signing key, replay nonce, truncated/overlong output, failed child and crash during publication; each must be rejected or left explicitly ineligible.
- Bind actual protected task proof to Grabowski terminal receipts and to [heim-pc #197](https://github.com/heimgewebe/heim-pc/pull/197)'s admission predicate with **separate** review, exact-head tests and Captain gates; retain `current_binding=null` until host evidence is fully authenticated.

**Test-only simulation warning:** Unit tests below may replace the root-ownership checks with user-owned temporary directories and omit UID dropping **inside a disposable fixture**. Those tests validate algorithm/data-integrity paths but are **not** privileged execution evidence. Until a real root-owned deployment/observer readback exists, this code is not sufficient to close #1387 or merge #197.

## Operational status and rollback

No root-owned config, key, binary, system UID, systemd unit, timer, broker policy, actual current host state or NixOS storage/boot state has been modified. No `[Install]` section exists. Rollback of this source-only change is a regular code revert; the existing Grabowski task backend and v2 receipt schema are untouched. Any later operational pilot requires an explicitly approved root-managed install, exact unit/host preflight and reverse-operation plan.
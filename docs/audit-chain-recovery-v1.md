# Audit chain locking and recovery boundary v1

## Purpose

Grabowski's mutation audit is a hash-linked JSONL chain. Every new record binds
its sequence number, the previous record hash and its own record hash. A valid
chain is a precondition for mutating tools.

The chain must remain valid when several Grabowski processes run under the same
user at the same time. This document defines the process-wide locking contract,
partial-write rollback and the deliberately narrow recovery boundary.

## Process-wide locking invariant

Canonical mutation coordination uses a separate private advisory flock file.
The mutable active audit head is read under a shared coordination lock and
re-read under an exclusive coordination lock before append. The active audit
descriptor itself is also locked and remains descriptor/path-bound while it is
verified and written.

Immutable archived predecessors are deliberately different: their payloads,
hash chain and manifests are fully verified outside the coordination lock.
That off-lock verification produces a per-call snapshot binding each expected
segment and manifest to its verified filesystem identity. Under the exclusive
coordination lock, Grabowski revalidates those bound path identities without
re-reading historical payloads. A predecessor-binding change restarts the
append attempt.

The coordination and descriptor locks have bounded acquisition time and fail
closed. The in-process re-entrant lock remains, but is not treated as
sufficient. Together these rules prevent cooperative Grabowski processes from
reading the same mutable tail and publishing sibling records while avoiding
history-sized payload I/O in the exclusive coordination section.

Active files and immutable evidence are private regular single-link files.
Descriptor-bound verification uses O_NOFOLLOW, requires the effective user and
group with mode 0600, and checks that the opened descriptor matches the visible
path. Snapshot revalidation checks the already-verified path metadata (type,
owner, group, mode, link count, size and filesystem identity) without reopening
every immutable file.

## Append transaction

An append follows this order:

1. under a shared coordination lock, verify the mutable head and capture its
   predecessor binding;
2. outside the coordination lock, fully verify the bound immutable predecessor
   chain and build a per-call identity snapshot;
3. take the exclusive coordination lock, re-read the mutable head and restart
   if its predecessor binding changed;
4. revalidate the verified immutable snapshot through metadata only;
5. open and exclusively lock the active audit descriptor, verify it, derive the
   next sequence/hash and enforce the byte limit;
6. if needed, rotate the verified active bytes into create-only immutable
   evidence and bind the new archived predecessor before replacing the active
   head;
7. write the complete payload, fsync, verify descriptor/path binding and the
   exact expected size;
8. revalidate the predecessor snapshot again; if it drifted after the append,
   truncate the active descriptor back to its exact pre-append size and fsync
   the rollback.

If a write starts but does not complete, Grabowski truncates the same locked
descriptor back to its exact previous size, calls fsync and verifies the
restored size before returning the original error. If rollback itself cannot be
proved complete, Grabowski raises a separate rollback-failure error and remains
fail-closed.

A failed first append may leave a safe empty 0600 audit file. Grabowski does
not delete that path during error handling because a check-then-unlink sequence
would introduce another path-replacement race. An empty valid file represents
zero records and can be used by the next append.

## Read and verification behavior

Canonical status verification captures and verifies the mutable head under the
shared coordination lock, verifies immutable history after releasing that lock,
then re-reads the head. If only the head advanced while its predecessor binding
stayed equal, the already-verified immutable history is reused with the fresh
head instead of being scanned again. If the predecessor changed, verification
retries the history binding; repeated predecessor churn terminates with the
distinct audit-head-raced error.

Record-oriented readers that need complete payloads keep their own stronger
snapshot rules. A missing audit file is a valid empty chain and verification is
read-only; verification does not create the file.

Readers and writers therefore use only heads that were fully verified while
cooperative writers were excluded by the appropriate shared/exclusive
coordination state. Immutable history is accepted only when its binding matches
the verified head.

## Fail-closed boundary

The locking contract prevents the known cooperative multi-process sibling race.
It does not claim isolation from arbitrary code with the same Unix user that
ignores the lock and directly modifies audit evidence. In particular, the
metadata-only in-lock snapshot recheck is an identity/drift check, not a second
content-hash verification. Content hashes and manifests are verified off-lock
before that identity is captured. Same-UID hostile-code isolation would require
a separate operating-system security domain or a privileged broker-owned log.

Grabowski must continue to block mutations when it observes any of the
following:

- malformed JSON or schema fields;
- a sequence, previous-hash or record-hash mismatch;
- an unsafe owner, group, mode, link count or parent directory;
- a symlink, hardlink or descriptor/path identity change;
- lock timeout, byte-limit breach, incomplete rollback or uncertain postflight;
- corruption that is not exactly classified by an implemented recovery type.

## Recovery boundary

The normal runtime does not receive a generic command to rewrite or discard
Audit records. Such a command would turn the integrity gate into a bypass.

A break-glass recovery remains external to the blocked mutation surface. It
must stop or quiesce canonical writers, bind an exact preimage, create a durable
backup, perform one narrowly specified transformation, append a recovery
record, atomically publish the result, restart services and verify both the
chain and runtime state. A successful recovery proves only the transformation
and checks recorded in its receipt; it does not prove that the original writer
race has been removed.

A future typed self-recovery may support only the proven tail-sibling race:

- the valid prefix is unambiguous;
- exactly the final record is a sibling of the previous valid tail;
- both sibling records are internally hash-valid;
- they have the same sequence and previous-record hash;
- the current file bytes match a precondition digest;
- repair runs under the exclusive audit descriptor lock;
- the untouched preimage is durably backed up;
- the sibling is re-sequenced and re-hashed, followed by a dedicated recovery
  record and complete readback.

Any additional ambiguity, earlier-chain damage, missing preimage binding or
backup failure must remain blocked and require the external recovery path.

## Verification evidence

The regression suite covers:

- concurrent appends from multiple operating-system processes;
- bounded lock timeout;
- short writes and partial-write rollback;
- predecessor-change append retry and predecessor-drift fail-closed behavior;
- off-lock immutable-history verification and metadata-only in-lock rechecks;
- head-only status races without redundant immutable-history rescans;
- safe behavior after a failed first append;
- symlink, hardlink, broad-mode and unsafe-parent rejection;
- visible-path replacement during append;
- byte-limit enforcement;
- read-only verification of a missing audit file.

Passing tests establish the implemented contracts for the tested environment.
They do not establish protection against arbitrary same-UID code that bypasses
the Grabowski runtime and ignores the advisory lock.

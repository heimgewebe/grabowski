# Audit chain locking and recovery boundary v1

## Purpose

Grabowski's mutation audit is a hash-linked JSONL chain. Every new record binds
its sequence number, the previous record hash and its own record hash. A valid
chain is a precondition for mutating tools.

The chain must remain valid when several Grabowski processes run under the same
user at the same time. This document defines the process-wide locking contract,
partial-write rollback and the deliberately narrow recovery boundary.

## Process-wide locking invariant

Every read, verification and append of the canonical audit file uses an
advisory `flock` on the opened audit-file descriptor:

- readers take a shared lock;
- appenders take an exclusive lock;
- lock acquisition has a bounded timeout and fails closed;
- the in-process re-entrant lock remains, but is not treated as sufficient;
- verification and append occur while the same descriptor and exclusive lock
  remain held.

This prevents two cooperative Grabowski processes from reading the same tail
and independently publishing sibling records with the same sequence and
previous-record hash.

The lock is bound to the audit file itself rather than to a separate lock-file
path. Grabowski opens it with `O_NOFOLLOW`, requires a regular single-link file
owned by the effective user and group with mode `0600`, and checks that the
opened descriptor still matches the visible path. The parent directory must be
private, non-symlinked and owned by the same user and group.

## Append transaction

An append follows this order while holding the exclusive descriptor lock:

1. verify the complete existing chain from the locked descriptor;
2. derive the next sequence, previous hash and new record hash;
3. enforce the audit byte limit;
4. verify descriptor-to-path binding immediately before writing;
5. write the complete payload, including retrying short writes;
6. `fsync` the audit descriptor;
7. recheck descriptor-to-path binding and the exact expected file size.

If a write starts but does not complete, Grabowski truncates the same locked
descriptor back to its exact previous size, calls `fsync` and verifies the
restored size before returning the original error. If rollback itself cannot be
proved complete, Grabowski raises a separate rollback-failure error and remains
fail-closed.

A failed first append may leave a safe empty `0600` audit file. Grabowski does
not delete that path during error handling because a check-then-unlink sequence
would introduce another path-replacement race. An empty valid file represents
zero records and can be used by the next append.

## Read and verification behavior

Canonical verification and record reads use a shared lock and the opened file
descriptor. They enforce the same file contract and byte limit. A missing audit
file is a valid empty chain and verification is read-only; verification does
not create the file.

Readers and writers therefore observe either the state before a complete append
or the state after it. They do not treat a cooperative in-progress append as a
finished record.

## Fail-closed boundary

The locking contract prevents the known cooperative multi-process sibling race.
It does not claim isolation from arbitrary code with the same Unix user that
ignores the lock and directly modifies the audit file. Same-UID hostile-code
isolation would require a separate operating-system security domain or a
privileged broker-owned log.

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
- safe behavior after a failed first append;
- symlink, hardlink, broad-mode and unsafe-parent rejection;
- visible-path replacement during append;
- byte-limit enforcement;
- read-only verification of a missing audit file.

Passing tests establish the implemented contracts for the tested environment.
They do not establish protection against arbitrary same-UID code that bypasses
the Grabowski runtime and ignores the advisory lock.

# Operator blockade store v1 — transaction proof

This slice implements the filesystem transaction layer for the scoped blockade
model from issue #215. It is intentionally not registered as an MCP tool and
does not alter capability catalogs, generated context, runtime entrypoints or
the current mutation guard.

## Trusted inputs

Every public operation receives both an observed path and an independently
supplied expected runtime path. The operation fails before opening the target
when these differ. The same rule applies to the quarantine root.

The runtime adapter remains responsible for deriving these expected paths from
trusted deployment configuration. Caller-supplied evidence is never accepted
as the expected path.

## Directory and file binding

Directory paths are opened component by component from `/` using directory
file descriptors and `O_NOFOLLOW` where available. Operations continue through
those descriptors, not through a re-resolved string path. The final directory
must:

- still bind to the same inode as its visible path;
- be owned by the expected UID;
- have no group or other permissions.

A marker or receipt must be a regular `0600` single-link file owned by the
expected UID. Reads compare descriptor identity before and after the operation
and bind the final directory entry to the same inode.

## Engagement

`engage_blockade_marker` serializes a validated `BlockadeRecord` as exact
canonical JSON. Publication is create-only:

1. create a random `0600` temporary file in the already opened marker parent;
2. write and fsync the full payload;
3. hard-link it to the canonical target, which fails if any entry already
   exists;
4. unlink the temporary name;
5. fsync the parent directory;
6. re-open and validate record, file hash, record hash, mode, owner and link
   count.

Temporary publication and post-publication readback share the same verified
rollback rule as disarm and restore. An owned target or temporary inode is
removed exactly and absence is read back. If either cleanup cannot be proved,
`BlockadeRollbackError` exposes the partial engagement instead of returning an
ordinary readback or publication error.

No replacement path exists. If an existing file, symlink or other directory
entry occupies the canonical name, engagement fails without changing it.

## Disarm

`disarm_blockade_marker` first runs the pure evidence validator. It then binds
the live marker to the exact record and file identity before mutation.
Quarantine is same-filesystem and create-only:

1. create a private transaction directory under the trusted quarantine root;
2. hard-link the exact marker inode to a fixed preimage name;
3. verify both names refer to the same two-link inode;
4. unlink only the source entry with the expected inode;
5. fsync source and quarantine directories;
6. re-read the single-link preimage;
7. publish a canonical create-only disarm receipt;
8. verify both the complete receipt mapping and its SHA-256;
9. confirm the source remains absent and the preimage remains exact.

Any exception after source removal performs an inode-bound rollback. The source
is restored only when absent and only from the expected preimage inode. The
marker, preimage and receipt state are then read back against the original
snapshot. If cleanup or readback is incomplete, a dedicated
`BlockadeRollbackError` replaces the original error so rollback uncertainty can
never be mistaken for a harmless operation failure.

## Restore

`restore_disarmed_marker` requires:

- exact transaction ID;
- exact marker and quarantine roots;
- exact record SHA-256;
- exact marker-file SHA-256;
- exact full disarm-receipt SHA-256;
- source path still absent;
- canonical, private and single-link receipt and preimage files.

The complete receipt key set, security-relevant booleans, rollback contract and
embedded `BlockadeRecord` are validated. Restore links the exact preimage inode
back to the marker, removes the quarantine name, fsyncs both sides and performs
full readback. A canonical restore receipt is then published and verified. A
failure after the source link rolls back to the quarantined state, removes the
incomplete restore receipt and verifies the exact preimage state. An incomplete
or unverifiable rollback raises `BlockadeRollbackError` rather than hiding the
recovery failure behind the original exception.

## Fault and denial coverage

`tests/test_blockade_store.py` uses only the Python standard library and covers:

- create-only publication and winner preservation;
- post-publication engage rollback and explicit unverified-rollback failure;
- trusted-path mismatch;
- symlinked directory chains;
- non-private parent or quarantine directories;
- symlink, hardlink, wrong-mode, wrong-owner and noncanonical markers;
- duplicate JSON keys;
- evidence denial before mutation;
- record and inode drift;
- receipt-publication rollback;
- exact disarm receipt and receipt-SHA binding;
- successful disarm/restore round trip;
- wrong hash and occupied-source denial;
- restore-receipt failure rollback;
- explicit hard failure when either rollback cannot be verified;
- strict numeric and transaction identifiers;
- isolated temporary state with production-path before/after comparison.

## Explicit boundary

This module does not establish:

- runtime tool registration;
- audit-log append completion;
- authenticity of caller-supplied provenance;
- permission to clear an external environment stop;
- deployment or live activation;
- permission to edit currently leased MCP or generated surfaces.

Those concerns belong to the subsequent lease-bound integration phase. The
storage layer merely makes that phase smaller and less error-prone.

# Root-owned operator blockade authority v2

Status: implementation contract for `GRABOWSKI-KILL-SWITCH-RECOVERY-V1-T002`.

## Purpose

The canonical operator blockade must remain observable by the unprivileged
Grabowski runtime while no ordinary process running as the operator user can
create, replace, rename, hard-link or remove it. The authority boundary therefore
moves both the marker and its parent directory outside the operator-owned state
root.

## Filesystem authority

The production paths are fixed by the root-owned broker configuration:

- authority directory: `/var/lib/grabowski/operator-blockade`, root-owned, mode
  `0711`;
- canonical marker: `operator-kill-switch`, root-owned, mode `0644`, regular and
  single-link;
- quarantine directory: `quarantine`, root-owned, mode `0700`;
- legacy marker: the previous operator-owned marker below
  `~/.local/state/grabowski`.

Mode `0711` permits the unprivileged runtime to traverse to the known marker
name without listing the authority directory. The marker is readable but its
parent is not writable by the operator user. Ownership of the marker alone
would not be sufficient because rename and unlink authority belongs to the
parent directory.

Every create-only publication starts as a private `0600` temporary file. The
broker writes and fsyncs complete bytes, changes to the final mode, fsyncs
again, publishes create-only, fsyncs the parent and performs descriptor/path,
owner, mode, link-count, size and hash readback.

## Broker lifecycle

The root broker exposes no caller-selected path or command for this domain.
The root-owned catalog fixes every path, UID, recovery gate and allowed peer.
The request contains only one typed operation, exact identities, hashes and a
transaction ID.

Supported operations are:

- `engage`: create one canonical record;
- `disarm`: quarantine one exact canonical record after recovery validation;
- `migrate`: create the canonical marker from one exact typed legacy record
  while deliberately preserving the operator-owned legacy preimage; the
  unprivileged runtime removes that preimage only after exact canonical
  readback;
- `rollback-engage`: remove only the exact marker created by a failed engage
  transaction and only with the same fresh root recovery gate required for a
  disarm;
- `restore-disarm`: restore only the exact quarantined preimage after a failed
  user-audit append;
- `observe`: classify an exact transaction as engaged, disarmed or
  absent-without-proof without mutation.

The broker claims each request ID before entering the lifecycle. Repeating a
request is rejected. Repeating an operation with a new request ID remains
fail-closed through create-only publication, marker absence/presence checks,
transaction-specific quarantine paths and exact hashes.

## Peer boundary

Lifecycle requests are accepted only from the long-lived main process of the
configured operator service. The typed blockade adapter sends its immutable
privileged reference directly over the Unix socket; it deliberately does not
spawn the generic privileged-request client, because that would replace the
operator's `SO_PEERCRED` with a child-process identity.

The socket-activated root process reads kernel `SO_PEERCRED`, requires the exact
operator UID, and independently queries the owning user systemd manager for the
configured unit's active `MainPID` and `ControlGroup`. The user-manager bus is
resolved only from the configured UID: `/run/user/<uid>` must be UID/GID-owned
mode `0700`, its `bus` endpoint must be an owned Unix socket, and caller-supplied
`XDG_RUNTIME_DIR` / `DBUS_SESSION_BUS_ADDRESS` values are ignored. The socket
peer PID must be that exact `MainPID`, its observed cgroup must equal the systemd
`ControlGroup`, and `/proc/<pid>/cmdline` must equal Grabowski's fixed operator
entrypoint argv. This means writable user-cgroup membership alone grants no
authority.

The broker additionally binds the decision to cgroup-v2 `cgroup.procs` plus
`/proc/<pid>/stat`: the peer must be the unique oldest process in that exact
service cgroup, its parent must be outside that cgroup, and the membership set
must remain unchanged across validation. Thus a same-UID terminal/request-client
child is rejected even though it inherited the exact operator-service cgroup; a
process manually moved into that writable user cgroup still fails the systemd
`MainPID` boundary; tmux, login-session, durable-job, persistent-task and
other-service peers fail earlier.

Failure to read peer credentials, systemd unit identity, command identity, cgroup
membership, process start identity or parent identity; malformed/unbounded
process sets; a UID/unit/MainPID/ControlGroup mismatch; a non-main peer; or
membership drift all block before the single-use claim and before any filesystem
effect.

This peer check does not claim protection against a compromised kernel, root,
or arbitrary code injected into the long-lived operator main process itself.

## Audit and unknown outcomes

The root broker durably appends an `intent` record after peer validation and
single-use claiming but before any lifecycle mutation. The intent binds the
request, operation, target hash, recovery-gate hashes and peer boundary. A
successful mutation is followed by a `complete` record bound to the intent and
the lifecycle-result hash. A rejected or failed mutation is followed by a
`failure` record bound to the same intent and bounded error metadata. If the
intent cannot be fsynced, no lifecycle mutation starts. If completion cannot be
published after a mutation, the client outcome remains unknown and exact
readback decides the visible state. The unprivileged runtime writes its normal
hash-chain audit record as a separate contract.

A client timeout, nonzero exit or malformed response never proves that no root
mutation happened. The client reports `unknown` and never retries
automatically. The runtime resolves the state by exact broker-side readback:

- engage succeeds only when the exact marker exists;
- disarm succeeds only when the marker is absent and the exact root-owned
  transaction receipt exists;
- absence without a matching receipt remains unproven;
- audit failure after engage invokes the recovery-gated exact rollback;
- audit failure after disarm invokes the exact restore and verifies the marker.

If rollback or restore cannot be proven, the system remains fail-closed.

## Legacy migration

Canonical and legacy markers are observed independently. Either marker, an
unsafe marker or an uncertain observation blocks matching mutation. A generic
file, terminal, power or indirect command may mutate neither path.

Migration is intentionally separate from installation:

1. install and verify broker modules, catalog and service sandbox;
2. observe the exact typed legacy marker;
3. append a migration-intent audit record;
4. ask the root broker to create the canonical marker create-only;
5. verify the root-owned canonical marker by exact record and file hashes;
6. locally re-read the operator-owned legacy marker and remove only that exact
   preimage through the narrow store primitive;
7. verify canonical presence and legacy absence;
8. append a migration-complete audit record.

The root broker never needs write authority over the operator-owned parent
directory. If local legacy removal fails, the canonical marker is deliberately
not rolled back: both markers remain visible and block mutation. This is safer
than reopening the system during an incomplete migration. Legacy free-text
markers are never reinterpreted as typed records.

## Service sandbox and deployment binding

The broker service receives read-only access to the recovery source and the
single legacy marker path. It receives no writable bind for the operator home,
legacy marker or state tree. The canonical authority lives outside
`ProtectHome`; exact legacy removal remains in the operator-owned local store
after root publication has been verified.

The cutover installs commit-bound copies of the blockade model, store,
authority and broker modules plus the service unit and root-owned catalog. The
runtime deployment manifest includes the authority module as a supporting
source, and the tool contract includes the explicit legacy migration tool.

## Does not establish

This contract does not establish:

- protection against root, kernel or filesystem compromise;
- safety of arbitrary code injected into the long-lived operator main process itself;
- correctness of recovery evidence outside its separately validated contract;
- automatic migration, disarm, merge or deployment;
- permission to set the production marker during tests;
- exactly-once delivery of broker responses.

Tests use temporary directories and test UIDs. Production verification must
prove the installed ownership and modes, rejection from both non-operator and
same-cgroup child processes, exact main-operator-process acceptance, legacy
migration behavior and that the production marker was never created merely for
a denial proof.

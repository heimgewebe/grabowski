# RepoBrief RAB root-systemd sandbox: no-provider qualification

Status: **experimental root-systemd plan and no-provider kernel probe only**.
Neither the probe nor a printed live plan authorizes Codex, a one-shot
benchmark, a PR merge or deployment.

## Kernel evidence on the target host (2026-10-15, systemd 249)

PrivateTmp=yes by itself creates two writable ext4 bind mounts on the
same protected root filesystem. Those cannot be treated as independent
temporary filesystems. Binding the host's shared /dev/shm onto /tmp
or /var/tmp is also unsafe: it reuses the host-visible filesystem.

The positive isolation test instead uses two separately created
DynamicUser-owned RuntimeDirectory trees under /run (mode 0700),
bind-mounted onto /tmp and /var/tmp. The original paths under /run
are explicitly read-only. Thus /tmp and /var/tmp are writable
tmpfs, without exposing other writable aliases for either scratch root.

The fixed service prefix grabowski-rab- is 14 ASCII characters.
On the actual systemd 249 host, a 17-character run ID (31-character
DynamicUser name) started successfully, whereas an 18-character ID
(32-character user name) failed with a systemd resources error.
The planner therefore denies run IDs longer than 17 characters.

The first live StateDirectory probe (with the repos path available)
**failed the full writable-mount check**: besides the four intentional
RW output leaves, systemd exposed five additional RW aliases at
/var/lib/private/<unit>/epoch/{state,transcripts,evidence,reports}
and /var/lib/private/<unit>/repos. Treating the public mounts as the
only RW paths would have been unsafe. An attempted ReadOnlyPaths on the
physical parent failed at systemd namespace setup (226/NAMESPACE).

The actual host-proven correction is
InaccessiblePaths=/var/lib/private. With this mask, the direct
physical aliases are inaccessible, HOME/repos is read-only, and
the four public output mounts remain writable. The corrected
no-provider root-systemd micro-unit returned PASS and observed
**exactly nine** RW mounts: four outputs, /tmp, /var/tmp, /dev/pts,
/dev/mqueue and /dev/shm. This proves the bounded host geometry,
**not** that frozen source checkouts and the production runner are
already staged or approved.

The root manager configures:
- DynamicUser, matching per-run User and Group, PrivateTmp,
  PrivateDevices, PrivateIPC, NoNewPrivileges, empty capabilities,
  DevicePolicy=closed, Delegate=no and system.slice placement.
- ProtectSystem=strict, four ProtectKernel controls, and explicit
  read-only /run, /proc, /sys and HOME parents.
- InaccessiblePaths for host session sockets at /run/user, Docker
  socket/namespace roots under /run/docker, the host backup automount,
  and hugepages under /dev/hugepages. The initial attempt **without**
  these masks exposed 32 RW mountpoints; the intermediate /run-RO
  profile exposed 17. The final no-provider root unit exposed exactly
  **nine** RW mounts: four intended output leaves, /tmp, /var/tmp,
  /dev/pts, /dev/mqueue and /dev/shm.
- An independent private /dev/shm tmpfs, rather than a host bind.

In the no-provider probe HOME also lives under /run. Its repos
subdirectory is separately read-only; the probe contains no real
frozen inputs or provider credentials. This profile is intentionally
**not** suitable for a benchmark dispatch, because HOME and temporary
directories can share the same underlying /run tmpfs.

The no-provider probe remains limited to 30 seconds. **Standalone live
requests are disabled.** The earlier 7,200-second single-request profile
was only a planning estimate and is retained as historical evidence, not an
executable systemd command. Calling --live-plan, live_runner_plan(),
or unit_argv() for a live single condition now fails closed. In particular,
neither a prior 3,600-second provider wall clock, twenty bounded Git phases,
nested sandbox checks nor postflight allowances make standalone dispatch safe
or supported.

Only the **same-unit baseline/treatment pair** has a qualified *plan format*:
--live-pair-plan emits RuntimeMaxSec=21600 (six hours). The configured
envelope allocates up to two former 7,200-second condition allowances and
3,600 seconds for pair-preflight, independent external validators, ledger,
terminalization and shutdown; the remaining 3,600 seconds are conservative
scheduling slack. This is not an observed production worst-case duration.
The per-condition wall_seconds budget measures only the bounded provider
execution, not subsequent Git readback, evidence cleanup or terminalization.
The latter still count toward the independent systemd service maximum.

The old --max-cost-usd field remains an explicitly **non-authorizing legacy
compatibility field** for Codex ChatGPT-subscription pairs. The preflight now
validates an independent, request-hash/model/order-bound *non-monetary* envelope:
exactly two bounded Codex exec processes (one per condition), up to 300
provider wall-clock seconds, 64,000 input and 6,000 output tokens, 80 tool
calls, 1 MiB tool input and 8 MiB tool output per condition. The bound source
is the 24-request frozen variants plan (SHA-256
\`2795584ac0c100cdceb6ed2c7eb42b883de2099b2a3d33ac51dbe9987655f10c\`).
Token/tool limits are checked against provider receipts after execution, not
reserved beforehand. The external Root-Systemd service has its separate
six-hour absolute lifetime limit. Neither those bounds nor a user-supplied
dollar flag is a hard USD spending ceiling; individual subscription USD
expenses remain unknown and must not be reported as 0 USD.

**This envelope is not an independent one-shot authorization.** Both the
paired preflight and direct Codex runner still deny real provider starts until
an independently issued, precisely bound and consumed one-time provider grant
is implemented and verified. No internal ledger, CLI flag, credential or
Root-Systemd admission alone supplies that grant. The live plan remains
non-authorizing; root-owned frozen code and MCP sources, complete mounts and
the real production validator are also required before any model process.

For a future live plan, the launcher instead uses StateDirectory
on persistent host storage, with four mode-0700 dynamic UID leaves.
A physical /var/lib/private/<unit> bind overlays the public
/var/lib/<unit> HOME so Path.resolve ancestry stays inside HOME.
Only the four output leaves are RW. Both temporary directories
remain on /run tmpfs, independent of that HOME backing.

A live-profile micro-unit initially failed with systemd 249 status
226/NAMESPACE because ReadOnlyPaths targeted HOME/repos before that
path existed. The corrected StateDirectory additionally creates the
per-run repos directory; ReadOnlyPaths then remounts its physical ext4
backing read-only, as verified by an actual DynamicUser micro-unit. This
persistent repos path is **not** a trusted staged source checkout yet;
freezing and binding qualified files remains a separate release gate. A no-provider
root-systemd micro-unit verified this topology; the empty StateDirectory
created for the experiment was removed after readback.

## Operational interface

Generate a bounded, no-provider command plan as a regular user:

    python3 tools/repobrief_agent_benchmark_systemd_launcher.py \
      --run-id auditexample --probe-plan

The module **only prints a plan**. It exposes no executable
--execute-probe mode, even to root. A kernel probe may run only through
the audited root-owned Grabowski broker consuming an independently
inspected, exact systemd-run argv. Never execute a mutable developer
checkout's Python code as root.
The transient root unit runs its child as DynamicUser, contains no
provider invocation, and removes its runtime directories on exit.

The obsolete --live-plan option now **rejects before emitting a broker
plan**; it is not a supported single-request entrypoint. Only
--live-pair-plan can print a proposed paired service. Even
--allow-live-provider is merely a plan opt-in, **never** a one-shot
authorization or actual cost reservation.

The host kernel confirmed the genuine system-bus listener as root
PID 1 in /init.scope, and a nonprivileged root-systemd DynamicUser
unit successfully read back its own systemctl properties. This is a
channel geometry witness, not the complete runner's SO_PEERPIDFD and
source-bound admission.

Systemd --collect removed the transient service and output leaves,
but an empty /run/<unit>-home/epoch parent can remain from nested
RuntimeDirectory entries. After exact ownership/content readback and
unit inactivity, remove only those two empty directories using rmdir;
never recursively delete runtime roots or evidence.

## Release and cleanup gates still open

1. Stage the frozen runner and complete import/tool tree as trusted,
   root-owned, readable, hash-bound files. Developer checkout sources
   currently have owner-only permissions and are not a live runtime.
2. Bind real source, Git metadata, request, manifest and repo map as
   read-only inputs. Establish the expected HOME/repos directory.
3. Prove the complete production kernel mount validator passes under
   the real unit. The current microprobe attests its own nine expected
   writable mounts but **does not run the production validator** with
   actual frozen source, Git metadata, binary, request and manifest.
   Verify system-bus authenticity and the runner's exact PID1/procfs
   checks still work with the additional read-only kernel mounts.
4. Verify no extra writable aliases, privileged sockets, hard links
   or writable source mounts; repeat admission before provider intent
   and after provider completion.
5. Stage the complete MCP executable/script/manifest/source closure through
   the trusted parent before provider intent, outside writable CODEX_HOME.
   Kernel-bind it read-only inside the actual provider PID/mount namespace,
   including all alternative writable aliases. Verify real provider-free
   tools/list, malicious same-UID mutation attempts and immutable cleanup.
   A final SHA-256 comparison does not detect an intermediate swap-and-restore.
6. Run fresh tests, Python CI, exact-diff independent High-Critical
   review and settlement of every material review thread.
7. Merge only through Captain, then verify deployed and serving state.
   Obtain separate explicit one-shot approval *after* all safety gates
   before any provider run or six-case benchmark.

Live StateDirectory content persists after a transient systemd unit.
Never remove it without verifying the exact service is inactive,
all artifacts are finalized, retention policies are satisfied, and
no foreign writer or owner is active.

**A successful mount microprobe is not a finished production
sandbox, an approved PR, or completed benchmark evidence.**

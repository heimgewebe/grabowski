#!/usr/bin/env python3
"""Construct a bounded RAB root-systemd sandbox argv without executing it.

The live plan is data, not dispatch authority. The caller must independently
authorize the one-shot, stage immutable readable runner inputs, verify mounts,
and invoke the privileged broker. No live provider is started by this module.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Sequence

_UNIT_ID = re.compile(r"\A[a-z][a-z0-9-]{0,16}\Z")
_OUTPUTS = ("state", "transcripts", "evidence", "reports")
_TMPFS_SHM = "/dev/shm:rw,nosuid,nodev,noexec,mode=1777"


class LauncherError(ValueError):
    """Deny an unsafe or incomplete root-systemd launch plan."""


def service_name(run_id: str) -> str:
    if not isinstance(run_id, str) or not _UNIT_ID.fullmatch(run_id):
        raise LauncherError(
            "run id must be 1-17 lowercase ASCII letters/digits/hyphens"
        )
    return "grabowski-rab-" + run_id


def unit_argv(
    run_id: str,
    program: Sequence[str],
    *,
    probe: bool,
) -> list[str]:
    """Return argv, never a shell string; root-owned PID 1 owns the unit."""
    name = service_name(run_id)
    if not program or any(not isinstance(x, str) or not x for x in program):
        raise LauncherError("empty program or argument")
    if not Path(program[0]).is_absolute():
        raise LauncherError("program must be an absolute executable path")

    tmp, var = name + "-tmp", name + "-var"
    home = f"/run/{name}-home" if probe else f"/var/lib/{name}"
    outputs = tuple(f"{home}/epoch/{x}" for x in _OUTPUTS)
    runtime = [tmp, var]
    binds = [f"/run/{tmp}:/tmp", f"/run/{var}:/var/tmp"]
    if probe:
        runtime.extend(f"{name}-home/epoch/{x}" for x in _OUTPUTS)
        runtime.append(f"{name}-home/repos")
    else:
        # DynamicUser creates StateDirectory leaves behind public symlinks.
        # Bind the root-owned physical parent over the public directory so that
        # Python's Path.resolve() sees all four real leaves below HOME.
        binds.append(f"/var/lib/private/{name}:{home}")

    properties = [
        "Type=exec",
        "DynamicUser=yes",
        f"User={name}",
        f"Group={name}",
        "PrivateTmp=yes",
        "PrivateIPC=yes",
        "PrivateDevices=yes",
        "DevicePolicy=closed",
        "Delegate=no",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "UMask=0077",
        f"Environment=HOME={home}",
        f"RuntimeDirectory={' '.join(runtime)}",
        "RuntimeDirectoryMode=0700",
        f"BindPaths={' '.join(binds)}",
        f"ReadOnlyPaths=/run /run/{tmp} /run/{var} {home} {home}/repos /proc /sys",
        "InaccessiblePaths=/run/user /run/docker /mnt/backup /dev/hugepages /var/lib/private",
        f"ReadWritePaths={' '.join(outputs)}",
        f"TemporaryFileSystem={_TMPFS_SHM}",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectKernelLogs=yes",
        "ProtectControlGroups=yes",
        "MemoryMax=512M",
        "TasksMax=128",
        f"RuntimeMaxSec={30 if probe else 900}",
    ]
    if not probe:
        properties.extend(
            [
                f"StateDirectory={' '.join([f'{name}/epoch/{x}' for x in _OUTPUTS] + [f'{name}/repos'])}",
                "StateDirectoryMode=0700",
            ]
        )

    return [
        "/usr/bin/systemd-run",
        "--system",
        "--wait",
        "--pipe",
        *(["--collect"] if probe else []),
        f"--unit={name}",
        *(f"--property={p}" for p in properties),
        "--",
        *program,
    ]


# This process has no access to benchmark requests, provider credentials or
# frozen runner code. It only reads the live kernel state from its own service.
_PROBE_PROGRAM = r"""
import json, os, pathlib, stat, sys

name = sys.argv[1]
home = pathlib.Path.home().resolve(strict=True)
unit = name + ".service"
def deny(message):
    raise RuntimeError(message)
if os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
    deny("not an unprivileged dynamic identity")
if not str(home).startswith("/run/" + name + "-home"):
    deny("unrecognized probe HOME")
cgroup = pathlib.Path("/proc/self/cgroup").read_text(encoding="ascii")
if cgroup.strip() != "0::/system.slice/" + unit:
    deny("not running in the exact root systemd cgroup")
status = pathlib.Path("/proc/self/status").read_text(encoding="ascii")
fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
if fields.get("NoNewPrivs", "").strip() != "1":
    deny("new privileges are possible")
for key in ("CapEff", "CapPrm", "CapAmb"):
    if int(fields.get(key, "-1").strip(), 16) != 0:
        deny("nonzero kernel capabilities")
if not (os.statvfs("/").f_flag & os.ST_RDONLY):
    deny("filesystem root is writable")
records = {}
for line in pathlib.Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines():
    row = line.split()
    if "-" not in row:
        deny("malformed mountinfo")
    records[row[4]] = (row[2], row[3], row[5].split(","), row[row.index("-")+1])
def mount(path, *, writable, fstype=None):
    row = records.get(str(path))
    if row is None or (("rw" in row[2]) != writable):
        deny("incorrect mount mode: " + str(path))
    if fstype is not None and row[3] != fstype:
        deny("incorrect filesystem: " + str(path))
    return row
mount("/", writable=False)
if os.access(home, os.W_OK):
    deny("HOME root unexpectedly writable")
out = [home / "epoch" / part for part in ("state", "transcripts", "evidence", "reports")]
for path in out:
    mount(path, writable=True, fstype="tmpfs")
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        deny("private output ownership invalid")
for path, suffix in (("/tmp", "-tmp"), ("/var/tmp", "-var")):
    live = mount(path, writable=True, fstype="tmpfs")
    source = "/run/" + name + suffix
    private = mount(source, writable=False, fstype="tmpfs")
    if live[:2] != private[:2]:
        deny("writable temp mount backing is not the private read-only source")
    info = os.stat(path)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        deny("temporary output owner or mode invalid")
allowed_rw = {str(path) for path in out}
allowed_rw.update(("/tmp", "/var/tmp", "/dev/pts", "/dev/mqueue", "/dev/shm"))
actual_rw = {path for path, row in records.items() if "rw" in row[2]}
if actual_rw != allowed_rw:
    deny("unexpected writable mount(s): " + repr(sorted(actual_rw ^ allowed_rw)))
print(json.dumps({"result": "PASS", "unit": unit, "cgroup": cgroup.strip(),
                  "private_outputs": len(out), "separate_private_tmpfs": True,
                  "only_expected_rw_mounts": len(actual_rw)},
                 sort_keys=True))
"""


def probe_argv(run_id: str) -> list[str]:
    name = service_name(run_id)
    return unit_argv(
        run_id, ["/usr/bin/python3", "-c", _PROBE_PROGRAM, name], probe=True
    )


def live_runner_plan(
    run_id: str,
    runner: Path,
    request_root: Path,
    repository_map: Path,
    codex: Path,
    codex_sha256: str,
    *,
    allow_live_provider: bool = False,
) -> list[str]:
    """Plan a fail-closed actual runner entrypoint; never execute it here."""
    name = service_name(run_id)
    for label, path in (
        ("runner", runner),
        ("request root", request_root),
        ("repository map", repository_map),
        ("codex", codex),
    ):
        if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
            raise LauncherError(f"{label} must be a canonical absolute path")
    if not re.fullmatch(r"[0-9a-f]{64}", codex_sha256):
        raise LauncherError("codex executable sha256 is required")
    if not runner.name == "repobrief_agent_benchmark_codex_runner.py":
        raise LauncherError("not the qualified benchmark runner")
    home = Path("/var/lib") / name
    runner_args = [
        "/usr/bin/python3",
        str(runner),
        "--request-root",
        str(request_root),
        "--repository-map",
        str(repository_map),
        "--state-root",
        str(home / "epoch" / "state"),
        "--transcript-root",
        str(home / "epoch" / "transcripts"),
        "--provider-evidence-root",
        str(home / "epoch" / "evidence"),
        "--codex-command",
        str(codex),
        "--codex-command-sha256",
        codex_sha256,
    ]
    if allow_live_provider:
        runner_args.append("--allow-live-provider")
    return unit_argv(run_id, runner_args, probe=False)


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--run-id", required=True)
    mode = cli.add_mutually_exclusive_group(required=True)
    mode.add_argument("--probe-plan", action="store_true")
    mode.add_argument("--live-plan", action="store_true")
    cli.add_argument("--runner", type=Path)
    cli.add_argument("--request-root", type=Path)
    cli.add_argument("--repository-map", type=Path)
    cli.add_argument("--codex", type=Path)
    cli.add_argument("--codex-sha256")
    cli.add_argument("--allow-live-provider", action="store_true")
    args = cli.parse_args(argv)
    try:
        if args.live_plan:
            if None in (
                args.runner,
                args.request_root,
                args.repository_map,
                args.codex,
                args.codex_sha256,
            ):
                raise LauncherError(
                    "live plan requires frozen runner, request, map and codex identities"
                )
            command = live_runner_plan(
                args.run_id,
                args.runner,
                args.request_root,
                args.repository_map,
                args.codex,
                args.codex_sha256,
                allow_live_provider=args.allow_live_provider,
            )
        else:
            if args.allow_live_provider:
                raise LauncherError("provider flag is forbidden for sandbox probes")
            command = probe_argv(args.run_id)
        print(
            json.dumps(
                {
                    "mode": "probe" if not args.live_plan else "live-plan-only",
                    "argv": command,
                },
                sort_keys=True,
            )
        )
        return 0
    except (LauncherError, OSError) as exc:
        print(f"root-systemd sandbox denied: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

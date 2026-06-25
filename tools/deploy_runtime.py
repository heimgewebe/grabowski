#!/usr/bin/env python3

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
from pathlib import Path
import platform
import select
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterator, NoReturn


SERVICE = "tunnel-client-grabowski.service"
PROFILE_NAME = "grabowski"
HEALTH_URL = "http://127.0.0.1:18080/healthz"
READY_URL = "http://127.0.0.1:18080/readyz"
HOME = Path.home().resolve()
DEFAULT_PROFILE_PATH = HOME / ".config/tunnel-client/grabowski.yaml"
DEFAULT_LOCK_FILE = HOME / ".local/state/grabowski/deploy.lock"
RUNTIME_LOCK_RELATIVE = Path("requirements/runtime.lock.txt")
EXPECTED_TOOLS = {
    "grabowski_status",
    "grabowski_list_directory",
    "grabowski_stat",
    "grabowski_read_text",
    "grabowski_create_text",
    "grabowski_replace_text",
    "latest_complete_bundles",
}
PROTOCOL_VERSIONS = (
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)


class DeployError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise DeployError(message)


def run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        check=check,
        text=True,
        capture_output=capture,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_file(path: Path, label: str) -> None:
    if not path.is_file():
        fail(f"{label} fehlt: {path}")


def git_head(repo: Path) -> str:
    result = run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        capture=True,
    )
    return result.stdout.strip()


def repo_dirty(repo: Path) -> bool:
    result = run(
        ["git", "status", "--porcelain"],
        cwd=repo,
        capture=True,
    )
    return bool(result.stdout.strip())


def require_clean_repo(repo: Path) -> str:
    if repo_dirty(repo):
        fail("Repository enthält uncommittete Änderungen.")
    return git_head(repo)


@contextmanager
def deployment_lock(lock_path: Path) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock_path.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            fail(f"Ein anderes Deployment hält bereits den Lock: {lock_path}")
            raise AssertionError from exc

        handle.seek(0)
        handle.truncate()
        handle.write(
            json.dumps(
                {
                    "pid": str(Path("/proc/self").resolve().name),
                    "acquired_at_unix": int(time.time()),
                },
                sort_keys=True,
            )
            + "\n"
        )
        handle.flush()
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def service_active() -> bool:
    result = run(
        ["systemctl", "--user", "is-active", "--quiet", SERVICE],
        check=False,
    )
    return result.returncode == 0


def http_text(url: str) -> str | None:
    result = run(
        ["curl", "-fsS", "--max-time", "2", url],
        check=False,
        capture=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def wait_until_ready(timeout_seconds: int) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if (
            service_active()
            and http_text(HEALTH_URL) == "live"
            and http_text(READY_URL) == "ready"
        ):
            return True
        time.sleep(1)
    return False


def send_json(proc: subprocess.Popen[bytes], payload: dict[str, Any]) -> None:
    if proc.stdin is None:
        fail("MCP-Probe besitzt kein stdin.")
    raw = (
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    proc.stdin.write(raw)
    proc.stdin.flush()


def wait_for_id(
    proc: subprocess.Popen[bytes],
    wanted_id: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    if proc.stdout is None:
        fail("MCP-Probe besitzt kein stdout.")

    deadline = time.monotonic() + timeout_seconds
    seen: list[str] = []

    while time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        ready, _, _ = select.select([proc.stdout], [], [], remaining)
        if not ready:
            break

        line = proc.stdout.readline()
        if not line:
            break

        decoded = line.decode("utf-8", errors="replace").rstrip("\n")
        seen.append(decoded)

        try:
            message = json.loads(decoded)
        except json.JSONDecodeError as exc:
            fail(f"MCP-Server schrieb Nicht-JSON auf stdout: {decoded!r}")
            raise AssertionError from exc

        if message.get("id") == wanted_id:
            return message

    fail(
        f"Keine MCP-Antwort auf JSON-RPC-ID {wanted_id}; "
        f"empfangen: {seen!r}"
    )


def stop_process(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def probe_mcp(python_exe: Path, server_script: Path) -> str:
    last_error: Exception | None = None

    for version in PROTOCOL_VERSIONS:
        with tempfile.TemporaryFile() as stderr_file:
            proc = subprocess.Popen(
                [str(python_exe), str(server_script)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr_file,
                bufsize=0,
            )

            try:
                send_json(
                    proc,
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": version,
                            "capabilities": {},
                            "clientInfo": {
                                "name": "grabowski-deploy-probe",
                                "version": "1.0",
                            },
                        },
                    },
                )
                initialized = wait_for_id(proc, 1, 15)
                if "error" in initialized:
                    raise DeployError(
                        f"initialize({version}) meldete "
                        f"{initialized['error']}"
                    )

                negotiated = initialized.get("result", {}).get(
                    "protocolVersion"
                )
                if not isinstance(negotiated, str):
                    raise DeployError(
                        f"Ungültige initialize-Antwort: {initialized!r}"
                    )

                send_json(
                    proc,
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized",
                        "params": {},
                    },
                )
                send_json(
                    proc,
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/list",
                        "params": {},
                    },
                )
                listed = wait_for_id(proc, 2, 15)
                if "error" in listed:
                    raise DeployError(
                        f"tools/list meldete {listed['error']}"
                    )

                tools = listed.get("result", {}).get("tools")
                if not isinstance(tools, list):
                    raise DeployError(
                        f"tools/list enthält keine Liste: {listed!r}"
                    )

                names = {
                    item.get("name")
                    for item in tools
                    if isinstance(item, dict)
                }
                missing = sorted(EXPECTED_TOOLS - names)
                if missing:
                    raise DeployError(
                        "MCP-Probe vermisst Werkzeuge: "
                        + ", ".join(missing)
                    )

                stop_process(proc)
                return negotiated

            except Exception as exc:
                last_error = exc
                stop_process(proc)
                stderr_file.seek(0)
                stderr_tail = stderr_file.read().decode(
                    "utf-8",
                    errors="replace",
                )[-4000:]
                if stderr_tail:
                    print(
                        f"MCP-Probe stderr ({version}):\n{stderr_tail}",
                        file=sys.stderr,
                    )

    fail(f"MCP-Probe fehlgeschlagen: {last_error}")


def python_provenance(python_exe: Path) -> dict[str, str]:
    result = run(
        [
            str(python_exe),
            "-c",
            (
                "import json,platform,sys; "
                "print(json.dumps({"
                "'python_version': platform.python_version(),"
                "'python_implementation': platform.python_implementation(),"
                "'platform': platform.platform(),"
                "'executable': sys.executable"
                "}, sort_keys=True))"
            ),
        ],
        capture=True,
    )
    data = json.loads(result.stdout)
    pip = run(
        [str(python_exe), "-m", "pip", "--version"],
        capture=True,
    ).stdout.strip()
    data["pip_version"] = pip
    return data


def create_stage(
    repo: Path,
    runtime: Path,
) -> tuple[Path, str, dict[str, str]]:
    runtime_parent = runtime.parent
    runtime_parent.mkdir(parents=True, exist_ok=True)

    stage = Path(
        tempfile.mkdtemp(
            prefix=".grabowski-mcp.stage.",
            dir=runtime_parent,
        )
    )

    try:
        source = repo / "src" / "grabowski_mcp.py"
        lockfile = repo / RUNTIME_LOCK_RELATIVE
        require_file(source, "MCP-Server")
        require_file(lockfile, "Runtime-Lockfile")

        venv = stage / ".venv"
        run([sys.executable, "-m", "venv", str(venv)])
        venv_python = venv / "bin" / "python"
        run(
            [
                str(venv_python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                "--require-hashes",
                "--no-deps",
                "-r",
                str(lockfile),
            ]
        )
        run([str(venv_python), "-m", "pip", "check"])

        shutil.copy2(source, stage / "grabowski_mcp.py")
        run(
            [
                str(venv_python),
                "-m",
                "py_compile",
                str(stage / "grabowski_mcp.py"),
            ]
        )
        negotiated = probe_mcp(
            venv_python,
            stage / "grabowski_mcp.py",
        )
        return stage, negotiated, python_provenance(venv_python)

    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def write_manifest(
    stage: Path,
    *,
    repo_head: str,
    source_hash: str,
    lockfile_hash: str,
    protocol_version: str,
    provenance: dict[str, str],
) -> None:
    manifest: dict[str, Any] = {
        "schema_version": 2,
        "repo_head": repo_head,
        "source_sha256": source_hash,
        "runtime_lock_path": str(RUNTIME_LOCK_RELATIVE),
        "runtime_lock_sha256": lockfile_hash,
        "mcp_protocol_version": protocol_version,
        "created_at_unix": int(time.time()),
        **provenance,
    }
    path = stage / "deployment-manifest.json"
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def read_manifest(runtime: Path) -> dict[str, Any]:
    path = runtime / "deployment-manifest.json"
    require_file(path, "Deployment-Manifest")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"Deployment-Manifest ist ungültig: {exc}")
    if not isinstance(data, dict):
        fail("Deployment-Manifest ist kein Objekt.")
    return data


def verify_manifest(
    runtime: Path,
    *,
    repo_head: str,
    source_hash: str,
    lockfile_hash: str,
) -> dict[str, Any]:
    manifest = read_manifest(runtime)
    expected = {
        "schema_version": 2,
        "repo_head": repo_head,
        "source_sha256": source_hash,
        "runtime_lock_sha256": lockfile_hash,
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            fail(
                f"Manifest-Feld {key} weicht ab: "
                f"{manifest.get(key)!r} != {value!r}"
            )
    return manifest


def verify_profile_command(profile_path: Path, runtime: Path) -> None:
    require_file(profile_path, "Tunnelprofil")
    text = profile_path.read_text(encoding="utf-8")
    expected_python = str(runtime / ".venv/bin/python")
    expected_server = str(runtime / "grabowski_mcp.py")
    command_lines = [line for line in text.splitlines() if "command:" in line]
    if not any(
        expected_python in line and expected_server in line
        for line in command_lines
    ):
        fail(
            "Tunnelprofil zeigt nicht auf die deployte Runtime: "
            f"{profile_path}"
        )


def verify_service_execstart() -> None:
    result = run(
        [
            "systemctl",
            "--user",
            "show",
            SERVICE,
            "-p",
            "ExecStart",
            "--value",
        ],
        capture=True,
    )
    value = result.stdout.strip()
    if "tunnel-client" not in value or PROFILE_NAME not in value:
        fail(f"Unerwartetes systemd ExecStart: {value}")


def service_main_pid() -> int:
    result = run(
        [
            "systemctl",
            "--user",
            "show",
            SERVICE,
            "-p",
            "MainPID",
            "--value",
        ],
        capture=True,
    )
    try:
        pid = int(result.stdout.strip())
    except ValueError as exc:
        fail(f"Ungültige MainPID: {result.stdout!r}")
        raise AssertionError from exc
    if pid <= 0:
        fail(f"{SERVICE} besitzt keine aktive MainPID.")
    return pid


def child_pids(pid: int, proc_root: Path = Path("/proc")) -> list[int]:
    path = proc_root / str(pid) / "task" / str(pid) / "children"
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return []
    return [int(value) for value in text.split()] if text else []


def descendant_pids(
    root_pid: int,
    proc_root: Path = Path("/proc"),
) -> list[int]:
    result: list[int] = []
    pending = [root_pid]
    seen = {root_pid}
    while pending:
        current = pending.pop()
        for child in child_pids(current, proc_root):
            if child in seen:
                continue
            seen.add(child)
            result.append(child)
            pending.append(child)
    return result


def process_argv(pid: int, proc_root: Path = Path("/proc")) -> list[str]:
    path = proc_root / str(pid) / "cmdline"
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return []
    return [
        item.decode("utf-8", errors="replace")
        for item in raw.split(b"\0")
        if item
    ]


def verify_running_runtime(
    runtime: Path,
    *,
    main_pid: int | None = None,
    proc_root: Path = Path("/proc"),
) -> dict[str, Any]:
    root_pid = service_main_pid() if main_pid is None else main_pid
    expected_python = str(runtime / ".venv/bin/python")
    expected_server = str(runtime / "grabowski_mcp.py")

    for pid in [root_pid, *descendant_pids(root_pid, proc_root)]:
        argv = process_argv(pid, proc_root)
        if expected_python in argv and expected_server in argv:
            return {"pid": pid, "argv": argv}

    fail(
        "Kein laufender MCP-Prozess verwendet die erwartete Runtime: "
        f"{runtime}"
    )


def verify_runtime_identity(
    runtime: Path,
    profile_path: Path,
    *,
    repo_head: str,
    source_hash: str,
    lockfile_hash: str,
) -> dict[str, Any]:
    verify_profile_command(profile_path, runtime)
    verify_service_execstart()
    process = verify_running_runtime(runtime)
    manifest = verify_manifest(
        runtime,
        repo_head=repo_head,
        source_hash=source_hash,
        lockfile_hash=lockfile_hash,
    )
    return {"process": process, "manifest": manifest}


def install_stage(
    runtime: Path,
    stage: Path,
    *,
    stamp: str,
) -> Path | None:
    backup: Path | None = None

    if runtime.exists():
        backup = runtime.with_name(
            f"{runtime.name}.rollback.{stamp}"
        )
        if backup.exists():
            fail(f"Rollback-Pfad existiert bereits: {backup}")
        runtime.rename(backup)

    try:
        stage.rename(runtime)
    except Exception:
        if backup is not None and backup.exists() and not runtime.exists():
            backup.rename(runtime)
        raise

    return backup


def restore_previous_runtime(
    runtime: Path,
    backup: Path | None,
    *,
    stamp: str,
) -> Path | None:
    failed_runtime: Path | None = None

    if runtime.exists():
        failed_runtime = runtime.with_name(
            f"{runtime.name}.failed.{stamp}"
        )
        if failed_runtime.exists():
            fail(f"Failed-Runtime-Pfad existiert bereits: {failed_runtime}")
        runtime.rename(failed_runtime)

    if backup is not None and backup.exists():
        backup.rename(runtime)

    return failed_runtime


def deploy(
    repo: Path,
    runtime: Path,
    profile_path: Path,
    *,
    timeout_seconds: int,
) -> None:
    repo_head = require_clean_repo(repo)
    if not service_active():
        fail(f"{SERVICE} ist vor dem Deployment nicht aktiv.")

    source = repo / "src" / "grabowski_mcp.py"
    lockfile = repo / RUNTIME_LOCK_RELATIVE
    require_file(source, "MCP-Server")
    require_file(lockfile, "Runtime-Lockfile")
    source_hash = sha256(source)
    lockfile_hash = sha256(lockfile)
    stage, protocol_version, provenance = create_stage(repo, runtime)
    write_manifest(
        stage,
        repo_head=repo_head,
        source_hash=source_hash,
        lockfile_hash=lockfile_hash,
        protocol_version=protocol_version,
        provenance=provenance,
    )

    backup: Path | None = None
    swapped = False
    stamp = time.strftime("%Y%m%d-%H%M%S")

    try:
        run(["systemctl", "--user", "stop", SERVICE])
        backup = install_stage(runtime, stage, stamp=stamp)
        swapped = True

        run(["systemctl", "--user", "start", SERVICE])
        if not wait_until_ready(timeout_seconds):
            fail("Neue Runtime wurde nicht rechtzeitig live und ready.")

        deployed_source = runtime / "grabowski_mcp.py"
        if sha256(deployed_source) != source_hash:
            fail("Deployter Source-Hash weicht vom Repo ab.")

        identity = verify_runtime_identity(
            runtime,
            profile_path,
            repo_head=repo_head,
            source_hash=source_hash,
            lockfile_hash=lockfile_hash,
        )

        print("PASS: Deployment erfolgreich")
        print(f"Repo-HEAD:       {repo_head}")
        print(f"Source-SHA256:   {source_hash}")
        print(f"Lock-SHA256:     {lockfile_hash}")
        print(f"MCP-Protokoll:   {protocol_version}")
        print(f"Runtime-PID:     {identity['process']['pid']}")
        print(f"Runtime:         {runtime}")
        print(f"Rollback:        {backup}")

    except Exception as original:
        if swapped:
            run(
                ["systemctl", "--user", "stop", SERVICE],
            )
            try:
                restore_previous_runtime(
                    runtime,
                    backup,
                    stamp=stamp,
                )
            except Exception as rollback_exc:
                raise DeployError(
                    f"Deployment fehlgeschlagen ({original}); "
                    f"Rollback konnte nicht installiert werden: {rollback_exc}"
                ) from rollback_exc

            run(
                ["systemctl", "--user", "start", SERVICE],
            )
            if backup is not None and not wait_until_ready(timeout_seconds):
                raise DeployError(
                    f"Deployment fehlgeschlagen ({original}); "
                    "wiederhergestellte Runtime wurde nicht ready."
                ) from original
        else:
            if not runtime.exists() and backup is not None and backup.exists():
                backup.rename(runtime)
            if not service_active():
                run(
                    ["systemctl", "--user", "start", SERVICE],
                )
        raise

    finally:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)


def check(repo: Path, runtime: Path) -> None:
    repo_head = git_head(repo)
    dirty = repo_dirty(repo)
    source = repo / "src" / "grabowski_mcp.py"
    lockfile = repo / RUNTIME_LOCK_RELATIVE
    require_file(source, "MCP-Server")
    require_file(lockfile, "Runtime-Lockfile")

    stage, protocol_version, provenance = create_stage(repo, runtime)
    try:
        source_hash = sha256(source)
        lockfile_hash = sha256(lockfile)
        write_manifest(
            stage,
            repo_head=repo_head,
            source_hash=source_hash,
            lockfile_hash=lockfile_hash,
            protocol_version=protocol_version,
            provenance=provenance,
        )
        verify_manifest(
            stage,
            repo_head=repo_head,
            source_hash=source_hash,
            lockfile_hash=lockfile_hash,
        )
        print("PASS: Deployment-Staging ist dependency-locked")
        print(f"Repo-HEAD:       {repo_head}")
        print(f"Arbeitsbaum:     {'dirty' if dirty else 'clean'}")
        print(f"Source-SHA256:   {source_hash}")
        print(f"Lock-SHA256:     {lockfile_hash}")
        print(f"Python:          {provenance['python_version']}")
        print(f"MCP-Protokoll:   {protocol_version}")
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deploy Grabowski atomically from its repository."
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument(
        "--runtime",
        type=Path,
        default=HOME / ".local/share/grabowski-mcp",
    )
    parser.add_argument(
        "--profile-path",
        type=Path,
        default=DEFAULT_PROFILE_PATH,
    )
    parser.add_argument(
        "--lock-file",
        type=Path,
        default=DEFAULT_LOCK_FILE,
    )
    parser.add_argument("--timeout", type=int, default=40)

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = args.repo.resolve()
    runtime = args.runtime.expanduser().resolve()
    profile_path = args.profile_path.expanduser().resolve()
    lock_file = args.lock_file.expanduser().resolve()

    try:
        if args.check:
            check(repo, runtime)
        else:
            with deployment_lock(lock_file):
                deploy(
                    repo,
                    runtime,
                    profile_path,
                    timeout_seconds=args.timeout,
                )
    except DeployError as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print(
            f"STOP: Befehl fehlgeschlagen: {exc.cmd}",
            file=sys.stderr,
        )
        return exc.returncode or 1
    except Exception as exc:
        print(f"STOP: Unerwarteter Fehler: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

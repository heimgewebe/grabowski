#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile
import time
from typing import NoReturn


SERVICE = "tunnel-client-grabowski.service"
HEALTH_URL = "http://127.0.0.1:18080/healthz"
READY_URL = "http://127.0.0.1:18080/readyz"
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


def send_json(proc: subprocess.Popen[bytes], payload: dict) -> None:
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
) -> dict:
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


def create_stage(repo: Path, runtime: Path) -> tuple[Path, str]:
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
        pyproject = repo / "pyproject.toml"

        require_file(source, "MCP-Server")
        require_file(pyproject, "pyproject.toml")

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
                str(repo),
            ]
        )

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
        return stage, negotiated

    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def write_manifest(
    stage: Path,
    *,
    repo_head: str,
    source_hash: str,
    protocol_version: str,
) -> None:
    manifest = {
        "schema_version": 1,
        "repo_head": repo_head,
        "source_sha256": source_hash,
        "mcp_protocol_version": protocol_version,
        "created_at_unix": int(time.time()),
    }
    path = stage / "deployment-manifest.json"
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


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
    *,
    timeout_seconds: int,
) -> None:
    repo_head = require_clean_repo(repo)
    if not service_active():
        fail(f"{SERVICE} ist vor dem Deployment nicht aktiv.")

    source = repo / "src" / "grabowski_mcp.py"
    source_hash = sha256(source)
    stage, protocol_version = create_stage(repo, runtime)
    write_manifest(
        stage,
        repo_head=repo_head,
        source_hash=source_hash,
        protocol_version=protocol_version,
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

        print("PASS: Deployment erfolgreich")
        print(f"Repo-HEAD:       {repo_head}")
        print(f"Source-SHA256:   {source_hash}")
        print(f"MCP-Protokoll:   {protocol_version}")
        print(f"Runtime:         {runtime}")
        print(f"Rollback:        {backup}")

    except Exception:
        if swapped:
            run(
                ["systemctl", "--user", "stop", SERVICE],
                check=False,
            )
            restore_previous_runtime(
                runtime,
                backup,
                stamp=stamp,
            )
            run(
                ["systemctl", "--user", "start", SERVICE],
                check=False,
            )
            if backup is not None and not wait_until_ready(timeout_seconds):
                print(
                    "WARN: Wiederhergestellte Runtime wurde nicht ready.",
                    file=sys.stderr,
                )
        else:
            if not runtime.exists() and backup is not None and backup.exists():
                backup.rename(runtime)
            if not service_active():
                run(
                    ["systemctl", "--user", "start", SERVICE],
                    check=False,
                )
        raise

    finally:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)


def check(repo: Path, runtime: Path) -> None:
    repo_head = git_head(repo)
    dirty = repo_dirty(repo)
    source = repo / "src" / "grabowski_mcp.py"
    require_file(source, "MCP-Server")

    stage, protocol_version = create_stage(repo, runtime)
    try:
        print("PASS: Deployment-Staging ist reproduzierbar")
        print(f"Repo-HEAD:       {repo_head}")
        print(f"Arbeitsbaum:     {'dirty' if dirty else 'clean'}")
        print(f"Source-SHA256:   {sha256(source)}")
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
        default=Path.home() / ".local/share/grabowski-mcp",
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

    try:
        if args.check:
            check(repo, runtime)
        else:
            deploy(
                repo,
                runtime,
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

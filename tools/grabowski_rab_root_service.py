"""Inert root-only socket seam for RepoBrief subscription one-shot grants.

This source is NOT deployed, not a grant issuer, not a policy installer and not
a Codex launcher. A trusted root-installed bootstrap must verify its exact
code/import closure before invoking it. The socket must be established by a
root-owned systemd .socket with SO_PASSCRED enabled *before* listening: setting
it after an untrusted client queued data loses kernel sender provenance.

Only root may run this service. A separately reviewed issuer must create and
verify the first provider outcome before releasing the second position.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket
import stat
from typing import Any


_LISTENER_PATH = Path("/run/grabowski/rab-provider-one-shot.sock")
_POLICY_ROOT = Path("/etc/grabowski/rab-provider-one-shot")
_STATE_ROOT = Path("/var/lib/grabowski/rab-provider-one-shot")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_MAX_ATTEMPTS = 2


class RootOneShotServiceDenied(RuntimeError):
    """No model process or authorization is started."""


def _checked_listener(listener: socket.socket) -> None:
    if os.geteuid() != 0:
        raise RootOneShotServiceDenied("root-owned socket service only")
    if not isinstance(listener, socket.socket):
        raise RootOneShotServiceDenied("unrecognized socket descriptor")
    if (
        listener.family != socket.AF_UNIX
        or listener.type != socket.SOCK_SEQPACKET
        or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
        or listener.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1
    ):
        raise RootOneShotServiceDenied("SOCK_SEQPACKET listener lacks early PASSCRED")
    if listener.getsockname() != str(_LISTENER_PATH):
        raise RootOneShotServiceDenied("root listener has incorrect kernel pathname")
    parent = _LISTENER_PATH.parent
    try:
        info = parent.lstat()
        socket_info = _LISTENER_PATH.lstat()
    except OSError as exc:
        raise RootOneShotServiceDenied(
            "root listener filesystem identity unavailable"
        ) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
        or not stat.S_ISSOCK(socket_info.st_mode)
        or socket_info.st_uid != 0
        or socket_info.st_gid == 0
        or socket_info.st_mode & 0o007
        or socket_info.st_nlink != 1
    ):
        raise RootOneShotServiceDenied("root listener filesystem is untrusted")


def _checked_activated_listener() -> socket.socket:
    """Consume exactly one named root-systemd socket-activation FD 3."""
    if os.geteuid() != 0:
        raise RootOneShotServiceDenied("root-owned socket service only")
    if (
        os.environ.get("LISTEN_PID") != str(os.getpid())
        or os.environ.get("LISTEN_FDS") != "1"
        or os.environ.get("LISTEN_FDNAMES") != "rab-provider-once"
    ):
        raise RootOneShotServiceDenied("trusted root systemd socket activation missing")
    try:
        listener = socket.socket(fileno=3)
    except OSError as exc:
        raise RootOneShotServiceDenied("root socket activation FD unavailable") from exc
    try:
        _checked_listener(listener)
        return listener
    except BaseException:
        listener.close()
        raise


def _serve_two(
    listener: socket.socket,
    *,
    policy_path: Path,
    state_dir: Path,
    grant_core: Any,
) -> dict[str, Any]:
    """Consume at most two service connections; never retry uncertain intents.

    No CLI response is authorization: the caller must also independently
    authenticate the root server and the exact grant receipt. Malformed peers
    count against the two-attempt cap, preventing unbounded rootbroker work.
    """
    _checked_listener(listener)
    if (
        not isinstance(policy_path, Path)
        or not isinstance(state_dir, Path)
        or policy_path.parent != _POLICY_ROOT
        or not re.fullmatch(r"epoch-[0-9a-f]{64}\.json", policy_path.name)
        or state_dir != _STATE_ROOT
    ):
        raise RootOneShotServiceDenied("root policy or state path not fixed")
    results: list[str] = []
    listener.settimeout(15)
    for _ in range(_MAX_ATTEMPTS):
        try:
            connected, _addr = listener.accept()
        except (OSError, TimeoutError) as exc:
            raise RootOneShotServiceDenied(
                "bounded root accept window expired"
            ) from exc
        with connected:
            try:
                if (
                    connected.family != socket.AF_UNIX
                    or connected.type != socket.SOCK_SEQPACKET
                    or connected.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1
                ):
                    raise RootOneShotServiceDenied(
                        "accepted sender credentials unavailable"
                    )
                result = grant_core.authorize_once(
                    connected,
                    policy_path=policy_path,
                    state_dir=state_dir,
                )
                if (
                    not isinstance(result, dict)
                    or result.get("status") != "consumed"
                    or not isinstance(result.get("token_sha256"), str)
                    or _SHA.fullmatch(result["token_sha256"]) is None
                    or result.get("arm") not in {"baseline", "treatment"}
                ):
                    raise RootOneShotServiceDenied("root grant result failed admission")
                response = json.dumps(
                    {
                        "status": "consumed",
                        "token_sha256": result["token_sha256"],
                        "arm": result["arm"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                results.append(result["arm"])
            except Exception:
                # Deliberately generic output: do not leak policy or broker internals.
                response = b'{"status":"denied"}'
                results.append("denied")
            try:
                connected.sendall(response)
            except OSError:
                # A successful CAS stays consumed even if the response is lost.
                pass
    return {
        "attempts": _MAX_ATTEMPTS,
        "consumed": sum(r in {"baseline", "treatment"} for r in results),
    }


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--epoch-sha256", required=True)
    args = cli.parse_args(argv)
    if not isinstance(args.epoch_sha256, str) or not _SHA.fullmatch(args.epoch_sha256):
        raise RootOneShotServiceDenied("exact root epoch digest required")
    listener = _checked_activated_listener()
    try:
        # Root installation must first prove this Python module and its entire
        # import closure immutable. Importing from the writable Git checkout is
        # never a valid runtime option; this inert module does not implement an
        # installer or root publishing authority.
        raise RootOneShotServiceDenied(
            "root-installed verified grant-core import closure is unavailable"
        )
    finally:
        listener.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RootOneShotServiceDenied:
        raise SystemExit(2)

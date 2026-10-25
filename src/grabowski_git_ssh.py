"""Fail-closed, non-configurable OpenSSH transport for Grabowski GitHub writes.

Only root-managed system SSH binaries and the owner-private, explicitly named
Heimgewebe GitHub writer key are accepted. No PATH, HOME, SSH config or Git
transport override is consulted. No key material is read or logged here.
"""
from __future__ import annotations

import os
from pathlib import Path
import pwd
import shlex
import stat


SSH_CANDIDATES = (Path("/usr/bin/ssh"), Path("/run/current-system/sw/bin/ssh"))
_NIX_SSH = SSH_CANDIDATES[1]
_NIX_STORE = Path("/nix/store")
_WRITER_KEY_NAME = "heimgewebe-github-ed25519"


def _root_managed_chain(path: Path) -> None:
    # Check both the visible path and the resolved target. In particular,
    # /run/current-system and its NixOS system-path symlinks are root-owned.
    for node in (path, *path.parents):
        info = node.lstat()
        if info.st_uid != 0:
            raise PermissionError(f"SSH executable path is not root-owned: {node}")
        if stat.S_ISLNK(info.st_mode):
            continue  # The root-owned parent controls replacement of this link.
        if info.st_mode & 0o022:
            # The Nix store is group-writable to nixbld on this host; sticky
            # semantics prevent those builders replacing root-owned entries.
            if not (node == _NIX_STORE and (info.st_mode & stat.S_ISVTX)):
                raise PermissionError(f"SSH executable path is writable: {node}")
        if node != path and not stat.S_ISDIR(info.st_mode):
            raise PermissionError(f"SSH executable parent is not a directory: {node}")


def _trusted_executable(path: Path) -> Path:
    if path not in SSH_CANDIDATES:
        raise PermissionError("SSH executable outside the supported system paths")
    real = path.resolve(strict=True)
    if path == _NIX_SSH and not real.is_relative_to(_NIX_STORE):
        raise PermissionError("NixOS OpenSSH does not resolve into the Nix store")
    _root_managed_chain(path)
    _root_managed_chain(real)
    info = real.stat()
    if not stat.S_ISREG(info.st_mode) or not (info.st_mode & 0o111):
        raise PermissionError("SSH executable is not a regular executable")
    if not os.access(real, os.X_OK):
        raise PermissionError("SSH executable cannot be executed by this operator")
    return real


def _selected_ssh_executable() -> Path:
    for path in SSH_CANDIDATES:
        if os.path.lexists(path):
            # If a preferred path exists but is untrusted, never silently fall
            # through to a second implementation.
            _trusted_executable(path)
            return path
    raise FileNotFoundError("No trusted system OpenSSH executable is installed")


def trusted_git_cli_path() -> str:
    """Return one root-managed Git executable, never resolved via PATH."""
    candidates = (Path("/usr/bin/git"), Path("/run/current-system/sw/bin/git"))
    for path in candidates:
        if not os.path.lexists(path):
            continue
        original = path.lstat()
        # Preserve the classic Linux contract: /usr/bin/git must be a regular
        # root-owned binary, never a user-rewritable or redirected symlink.
        if path == candidates[0] and not stat.S_ISREG(original.st_mode):
            if not stat.S_ISLNK(original.st_mode):
                raise PermissionError("trusted classic Git CLI must be a regular file")
            # Accept only a root-managed alias to exactly the NixOS system Git.
            nix_git = candidates[1]
            if not os.path.lexists(nix_git):
                raise PermissionError("legacy Git symlink lacks trusted NixOS Git")
            try:
                legacy_target = path.resolve(strict=True)
                nix_target = nix_git.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise PermissionError("legacy Git symlink lacks trusted NixOS Git") from exc
            if legacy_target != nix_target or not nix_target.is_relative_to(_NIX_STORE):
                raise PermissionError("legacy Git symlink does not match NixOS system Git")
            _root_managed_chain(path)
            continue  # The canonical NixOS path is checked by this same loop.
        actual = path.resolve(strict=True)
        if path == candidates[1] and not actual.is_relative_to(_NIX_STORE):
            raise PermissionError("NixOS Git must resolve into the Nix store")
        _root_managed_chain(path)
        _root_managed_chain(actual)
        info = actual.stat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or not info.st_mode & stat.S_IXUSR
            or not os.access(actual, os.X_OK)
        ):
            raise PermissionError("Git CLI is not a trusted system executable")
        return str(path)
    raise FileNotFoundError("No root-managed Git CLI is installed")


def _trusted_identity() -> Path:
    # passwd is the account authority; HOME or caller-provided paths are not.
    home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    if not home.is_absolute():
        raise PermissionError("GitHub writer home directory must be absolute")
    ssh_dir = home / ".ssh"
    key = ssh_dir / _WRITER_KEY_NAME
    uid = os.geteuid()
    for directory in (home, ssh_dir):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
            raise PermissionError("GitHub writer identity directory is not private")
    info = key.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077 or info.st_size == 0:
        raise PermissionError("GitHub writer identity is not a private regular file")
    return key


def hardened_git_ssh_command() -> str:
    executable = _selected_ssh_executable()
    key = _trusted_identity()
    return (
        f"{shlex.quote(str(executable))} -F /dev/null "
        "-oBatchMode=yes -oProxyCommand=none -oPermitLocalCommand=no "
        "-oClearAllForwardings=yes -oIdentitiesOnly=yes "
        "-oIdentityAgent=none -oStrictHostKeyChecking=yes "
        f"-i {shlex.quote(str(key))}"
    )
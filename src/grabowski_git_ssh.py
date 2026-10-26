"""Fail-closed, non-configurable OpenSSH transport for Grabowski GitHub writes.

Only root-managed system SSH binaries and the owner-private, explicitly named
Heimgewebe GitHub writer key are accepted. No PATH, HOME, SSH config or Git
transport override is consulted. No key material is read or logged here.
"""
from __future__ import annotations

import os
from collections import deque
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



def _root_managed_resolution(path: Path) -> Path:
    """Audit every symlink hop and pin the validated final executable.

    Checking only the spelling of an alias and its final realpath misses
    intermediate symlink targets in attacker-controlled directories.
    """
    if not path.is_absolute():
        raise PermissionError("System executable must use an absolute path")
    remaining = deque(path.parts[1:])
    current = Path("/")
    link_count = 0
    while remaining:
        component = remaining.popleft()
        if component in ("", "."):
            continue
        if component == "..":
            current = current.parent
            continue
        step = current / component
        _root_managed_chain(step)
        info = step.lstat()
        if stat.S_ISLNK(info.st_mode):
            link_count += 1
            if link_count > 40:
                raise PermissionError("Too many executable symlink hops")
            target = Path(os.readlink(step))
            if target.is_absolute():
                current = Path("/")
            remaining.extendleft(reversed(target.parts[1:] if target.is_absolute() else target.parts))
            continue
        if remaining and not stat.S_ISDIR(info.st_mode):
            raise PermissionError("Executable symlink traverses a non-directory")
        current = step
    # A concurrent retarget is harmless only when we never execute the
    # original alias again. Reconciliation additionally rejects path drift.
    final = path.resolve(strict=True)
    if final != current:
        raise PermissionError("System executable resolution changed during validation")
    _root_managed_chain(final)
    return final


def _trusted_executable(path: Path) -> Path:
    if path not in SSH_CANDIDATES:
        raise PermissionError("SSH executable outside the supported system paths")
    real = _root_managed_resolution(path)
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
            return _trusted_executable(path)
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
                legacy_target = _root_managed_resolution(path)
                nix_target = _root_managed_resolution(nix_git)
            except (OSError, RuntimeError) as exc:
                raise PermissionError("legacy Git symlink lacks trusted NixOS Git") from exc
            if legacy_target != nix_target or not nix_target.is_relative_to(_NIX_STORE):
                raise PermissionError("legacy Git symlink does not match NixOS system Git")
            _root_managed_chain(path)
            continue  # The canonical NixOS path is checked by this same loop.
        actual = _root_managed_resolution(path)
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
        return str(actual)
    raise FileNotFoundError("No root-managed Git CLI is installed")


def trusted_github_cli_path() -> str:
    """Return a root-owned, audited gh realpath without consulting PATH."""
    classic = Path("/usr/bin/gh")
    nixos = Path("/run/current-system/sw/bin/gh")
    for path in (classic, nixos):
        if not os.path.lexists(path):
            continue
        if path == classic:
            original = path.lstat()
            if stat.S_ISLNK(original.st_mode):
                if not os.path.lexists(nixos):
                    raise PermissionError("legacy gh alias lacks canonical NixOS gh")
                legacy_real = _root_managed_resolution(classic)
                nix_real = _root_managed_resolution(nixos)
                if legacy_real != nix_real or not nix_real.is_relative_to(_NIX_STORE):
                    raise PermissionError("legacy gh alias does not match NixOS system gh")
                _root_managed_chain(classic)
                continue
            if not stat.S_ISREG(original.st_mode):
                raise PermissionError("classic GitHub CLI must be a regular executable")
        real = _root_managed_resolution(path)
        if path == nixos and not real.is_relative_to(_NIX_STORE):
            raise PermissionError("NixOS GitHub CLI must resolve into the Nix store")
        _root_managed_chain(path)
        _root_managed_chain(real)
        info = real.stat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or not info.st_mode & stat.S_IXUSR
            or not os.access(real, os.X_OK)
        ):
            raise PermissionError("GitHub CLI is not a trusted system executable")
        return str(real)
    raise FileNotFoundError("No root-managed GitHub CLI is installed")


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
        if directory == ssh_dir and info.st_mode & 0o077:
            raise PermissionError("GitHub writer SSH directory is not owner-private")
    info = key.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077 or info.st_size == 0 or info.st_nlink != 1:
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
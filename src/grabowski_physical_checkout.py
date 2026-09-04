from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any


SCHEMA_VERSION = 1
KIND = "grabowski.physical_checkout_identity"
MAX_POINTER_BYTES = 64 * 1024


class PhysicalCheckoutIdentityError(RuntimeError):
    """The checkout's filesystem identity could not be observed safely."""


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _absolute_lexical(path: str | os.PathLike[str]) -> Path:
    value = os.fspath(path)
    if "\x00" in value:
        raise PhysicalCheckoutIdentityError("checkout path contains a NUL byte")
    return Path(os.path.abspath(value))


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _file_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _same_node(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
    )


def _same_file_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _identity(path: Path, metadata: os.stat_result) -> dict[str, Any]:
    return {
        "path": str(path),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }


def _identity_material(
    *,
    root: dict[str, Any],
    git_dir: dict[str, Any],
    common_dir: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "root": root,
        "git_dir": git_dir,
        "common_dir": common_dir,
    }


def _identity_sha256(material: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json_bytes(material)).hexdigest()


def _validated_identity_node(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"path", "device", "inode"}:
        raise PhysicalCheckoutIdentityError(
            f"expected physical identity {label} has an invalid shape"
        )
    path = value.get("path")
    if (
        not isinstance(path, str)
        or not path
        or "\x00" in path
        or not Path(path).is_absolute()
    ):
        raise PhysicalCheckoutIdentityError(
            f"expected physical identity {label} path is invalid"
        )
    for field in ("device", "inode"):
        number = value.get(field)
        if type(number) is not int or number < 0:
            raise PhysicalCheckoutIdentityError(
                f"expected physical identity {label} {field} is invalid"
            )
    return {"path": path, "device": value["device"], "inode": value["inode"]}


def _validate_component(component: str, *, label: str) -> None:
    if component in {"", ".", ".."} or "/" in component or "\x00" in component:
        raise PhysicalCheckoutIdentityError(f"{label} contains an unsafe path component")


def _open_absolute_directory(path: Path, *, label: str) -> tuple[int, os.stat_result]:
    """Open an absolute directory by walking every component with O_NOFOLLOW."""
    path = _absolute_lexical(path)
    if not path.is_absolute():
        raise PhysicalCheckoutIdentityError(f"{label} must be absolute")

    flags = _directory_flags()
    try:
        descriptor = os.open(path.anchor, flags)
    except OSError as exc:
        raise PhysicalCheckoutIdentityError(f"{label} root could not be opened safely") from exc

    try:
        anchor_opened = os.fstat(descriptor)
        anchor_linked = os.stat(path.anchor, follow_symlinks=False)
        if not stat.S_ISDIR(anchor_opened.st_mode) or not _same_node(
            anchor_opened, anchor_linked
        ):
            raise PhysicalCheckoutIdentityError(f"{label} root identity is unsafe")

        for component in path.parts[1:]:
            _validate_component(component, label=label)
            try:
                linked = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            except OSError as exc:
                raise PhysicalCheckoutIdentityError(
                    f"{label} component could not be inspected safely"
                ) from exc
            if not stat.S_ISDIR(linked.st_mode) or stat.S_ISLNK(linked.st_mode):
                raise PhysicalCheckoutIdentityError(
                    f"{label} may not traverse a symlink or non-directory component"
                )
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise PhysicalCheckoutIdentityError(
                    f"{label} component could not be opened safely"
                ) from exc
            try:
                opened = os.fstat(child)
                if not stat.S_ISDIR(opened.st_mode) or not _same_node(opened, linked):
                    raise PhysicalCheckoutIdentityError(
                        f"{label} changed while its path was being opened"
                    )
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child

        opened = os.fstat(descriptor)
        try:
            linked = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise PhysicalCheckoutIdentityError(
                f"{label} path disappeared during descriptor binding"
            ) from exc
        if not stat.S_ISDIR(opened.st_mode) or not _same_node(opened, linked):
            raise PhysicalCheckoutIdentityError(f"{label} path identity is unsafe")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _open_relative_directory(
    parent_descriptor: int,
    name: str,
    *,
    label: str,
) -> tuple[int, os.stat_result]:
    _validate_component(name, label=label)
    try:
        linked = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise PhysicalCheckoutIdentityError(f"{label} could not be inspected safely") from exc
    if not stat.S_ISDIR(linked.st_mode) or stat.S_ISLNK(linked.st_mode):
        raise PhysicalCheckoutIdentityError(f"{label} must be a non-symlink directory")
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
    except OSError as exc:
        raise PhysicalCheckoutIdentityError(f"{label} could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode) or not _same_node(opened, linked):
            raise PhysicalCheckoutIdentityError(
                f"{label} changed during descriptor binding"
            )
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _read_relative_regular(
    parent_descriptor: int,
    name: str,
    *,
    label: str,
) -> tuple[bytes, os.stat_result]:
    _validate_component(name, label=label)
    try:
        linked_before = os.stat(
            name, dir_fd=parent_descriptor, follow_symlinks=False
        )
    except OSError as exc:
        raise PhysicalCheckoutIdentityError(f"{label} could not be inspected safely") from exc
    if not stat.S_ISREG(linked_before.st_mode) or stat.S_ISLNK(linked_before.st_mode):
        raise PhysicalCheckoutIdentityError(f"{label} must be a non-symlink regular file")
    if linked_before.st_size < 1 or linked_before.st_size > MAX_POINTER_BYTES:
        raise PhysicalCheckoutIdentityError(f"{label} has an invalid size")

    try:
        descriptor = os.open(name, _file_flags(), dir_fd=parent_descriptor)
    except OSError as exc:
        raise PhysicalCheckoutIdentityError(f"{label} could not be opened safely") from exc
    try:
        opened_before = os.fstat(descriptor)
        if not _same_file_snapshot(opened_before, linked_before):
            raise PhysicalCheckoutIdentityError(
                f"{label} changed during descriptor binding"
            )
        payload = bytearray()
        while len(payload) <= MAX_POINTER_BYTES:
            chunk = os.read(
                descriptor,
                min(4096, MAX_POINTER_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MAX_POINTER_BYTES:
            raise PhysicalCheckoutIdentityError(f"{label} exceeded its byte limit")
        opened_after = os.fstat(descriptor)
        if not _same_file_snapshot(opened_before, opened_after):
            raise PhysicalCheckoutIdentityError(f"{label} changed while being read")
    finally:
        os.close(descriptor)

    try:
        linked_after = os.stat(
            name, dir_fd=parent_descriptor, follow_symlinks=False
        )
    except OSError as exc:
        raise PhysicalCheckoutIdentityError(
            f"{label} disappeared after being read"
        ) from exc
    if not _same_file_snapshot(opened_before, linked_after):
        raise PhysicalCheckoutIdentityError(f"{label} path identity changed after read")
    return bytes(payload), opened_before


def _assert_relative_file_snapshot(
    parent_descriptor: int,
    name: str,
    expected: os.stat_result,
    *,
    label: str,
) -> None:
    try:
        observed = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise PhysicalCheckoutIdentityError(f"{label} disappeared during capture") from exc
    if not _same_file_snapshot(expected, observed):
        raise PhysicalCheckoutIdentityError(f"{label} changed during capture")


def _assert_relative_directory_node(
    parent_descriptor: int,
    name: str,
    expected: os.stat_result,
    *,
    label: str,
) -> None:
    try:
        observed = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise PhysicalCheckoutIdentityError(f"{label} disappeared during capture") from exc
    if not stat.S_ISDIR(observed.st_mode) or not _same_node(expected, observed):
        raise PhysicalCheckoutIdentityError(f"{label} changed during capture")


def _single_line_pointer(payload: bytes, *, prefix: str, label: str) -> str:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PhysicalCheckoutIdentityError(f"{label} is not valid UTF-8") from exc
    if "\x00" in text:
        raise PhysicalCheckoutIdentityError(f"{label} contains a NUL byte")
    if text.endswith("\r\n"):
        line = text[:-2]
    elif text.endswith("\n"):
        line = text[:-1]
    else:
        line = text
    if "\n" in line or "\r" in line or not line.startswith(prefix):
        raise PhysicalCheckoutIdentityError(f"{label} has an unsupported format")
    target = line[len(prefix) :]
    if not target:
        raise PhysicalCheckoutIdentityError(f"{label} has an empty target")
    return target


def _pointer_target(base: Path, value: str, *, label: str) -> Path:
    candidate = Path(value)
    target = candidate if candidate.is_absolute() else base / candidate
    target = _absolute_lexical(target)
    if not target.is_absolute():
        raise PhysicalCheckoutIdentityError(f"{label} target must resolve lexically absolute")
    return target


def _assert_absolute_directory_node(
    path: Path,
    expected: os.stat_result,
    *,
    label: str,
) -> None:
    descriptor, observed = _open_absolute_directory(path, label=label)
    try:
        if not _same_node(expected, observed):
            raise PhysicalCheckoutIdentityError(f"{label} changed during capture")
    finally:
        os.close(descriptor)


def capture_physical_checkout_identity(
    worktree_root: str | os.PathLike[str],
) -> dict[str, Any]:
    """Capture only physical checkout identity: paths plus device/inode triples.

    The observation rejects symlink traversal in every lexical path component and
    revalidates every bound path after capture. It intentionally excludes branch, HEAD, remote, purpose, role, task and
    lease semantics.
    """
    root_path = _absolute_lexical(worktree_root)
    root_descriptor, root_metadata = _open_absolute_directory(
        root_path, label="checkout root"
    )
    git_descriptor: int | None = None
    common_descriptor: int | None = None
    try:
        try:
            git_entry = os.stat(
                ".git", dir_fd=root_descriptor, follow_symlinks=False
            )
        except OSError as exc:
            raise PhysicalCheckoutIdentityError(
                "checkout root has no safely observable .git entry"
            ) from exc

        git_pointer_snapshot: os.stat_result | None = None
        if stat.S_ISDIR(git_entry.st_mode) and not stat.S_ISLNK(git_entry.st_mode):
            git_path = root_path / ".git"
            git_descriptor, git_metadata = _open_relative_directory(
                root_descriptor, ".git", label="git directory"
            )
            git_entry_kind = "directory"
        elif stat.S_ISREG(git_entry.st_mode) and not stat.S_ISLNK(git_entry.st_mode):
            payload, git_pointer_snapshot = _read_relative_regular(
                root_descriptor, ".git", label="gitdir pointer"
            )
            target = _single_line_pointer(
                payload, prefix="gitdir: ", label="gitdir pointer"
            )
            git_path = _pointer_target(root_path, target, label="gitdir pointer")
            git_descriptor, git_metadata = _open_absolute_directory(
                git_path, label="git directory"
            )
            git_entry_kind = "pointer"
        else:
            raise PhysicalCheckoutIdentityError(
                ".git must be a non-symlink directory or regular gitdir pointer"
            )

        commondir_pointer_snapshot: os.stat_result | None = None
        commondir_absent = False
        try:
            commondir_entry = os.stat(
                "commondir", dir_fd=git_descriptor, follow_symlinks=False
            )
        except FileNotFoundError:
            commondir_absent = True
            common_path = git_path
            common_descriptor = os.dup(git_descriptor)
            common_metadata = os.fstat(common_descriptor)
        except OSError as exc:
            raise PhysicalCheckoutIdentityError(
                "commondir entry could not be inspected safely"
            ) from exc
        else:
            if not stat.S_ISREG(commondir_entry.st_mode) or stat.S_ISLNK(
                commondir_entry.st_mode
            ):
                raise PhysicalCheckoutIdentityError(
                    "commondir must be a non-symlink regular file"
                )
            payload, commondir_pointer_snapshot = _read_relative_regular(
                git_descriptor, "commondir", label="commondir pointer"
            )
            target = _single_line_pointer(
                payload, prefix="", label="commondir pointer"
            )
            common_path = _pointer_target(
                git_path, target, label="commondir pointer"
            )
            common_descriptor, common_metadata = _open_absolute_directory(
                common_path, label="git common directory"
            )

        material = _identity_material(
            root=_identity(root_path, root_metadata),
            git_dir=_identity(git_path, git_metadata),
            common_dir=_identity(common_path, common_metadata),
        )

        _assert_absolute_directory_node(
            root_path, root_metadata, label="checkout root"
        )
        _assert_absolute_directory_node(
            git_path, git_metadata, label="git directory"
        )
        if common_path != git_path:
            _assert_absolute_directory_node(
                common_path, common_metadata, label="git common directory"
            )
        if git_entry_kind == "directory":
            _assert_relative_directory_node(
                root_descriptor,
                ".git",
                git_metadata,
                label="git directory",
            )
        else:
            assert git_pointer_snapshot is not None
            _assert_relative_file_snapshot(
                root_descriptor,
                ".git",
                git_pointer_snapshot,
                label="gitdir pointer",
            )

        if commondir_absent:
            try:
                os.stat("commondir", dir_fd=git_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise PhysicalCheckoutIdentityError(
                    "commondir absence could not be revalidated"
                ) from exc
            else:
                raise PhysicalCheckoutIdentityError(
                    "commondir appeared during physical identity capture"
                )
        else:
            assert commondir_pointer_snapshot is not None
            _assert_relative_file_snapshot(
                git_descriptor,
                "commondir",
                commondir_pointer_snapshot,
                label="commondir pointer",
            )

        return {
            **material,
            "physical_identity_sha256": _identity_sha256(material),
        }
    finally:
        if common_descriptor is not None:
            os.close(common_descriptor)
        if git_descriptor is not None:
            os.close(git_descriptor)
        os.close(root_descriptor)


def verify_physical_checkout_identity(expected: dict[str, Any]) -> dict[str, Any]:
    required_fields = {
        "schema_version",
        "kind",
        "root",
        "git_dir",
        "common_dir",
        "physical_identity_sha256",
    }
    if (
        not isinstance(expected, dict)
        or set(expected) != required_fields
        or expected.get("schema_version") != SCHEMA_VERSION
        or expected.get("kind") != KIND
    ):
        raise PhysicalCheckoutIdentityError("expected physical identity is invalid")

    root = _validated_identity_node(expected.get("root"), label="root")
    git_dir = _validated_identity_node(expected.get("git_dir"), label="git_dir")
    common_dir = _validated_identity_node(expected.get("common_dir"), label="common_dir")
    material = _identity_material(root=root, git_dir=git_dir, common_dir=common_dir)
    expected_digest = expected.get("physical_identity_sha256")
    if not isinstance(expected_digest, str) or expected_digest != _identity_sha256(material):
        raise PhysicalCheckoutIdentityError(
            "expected physical identity digest is internally inconsistent"
        )

    observed = capture_physical_checkout_identity(root["path"])
    if expected_digest != observed["physical_identity_sha256"]:
        raise PhysicalCheckoutIdentityError(
            "physical checkout identity changed since the expected observation"
        )
    return observed

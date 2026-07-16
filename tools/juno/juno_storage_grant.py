#!/usr/bin/env python3
"""Locally consent one iPadOS folder for bounded Grabowski/Juno access.

Run this script interactively in Juno. It presents the system document picker for
one folder, creates a security-scoped bookmark, verifies it immediately, and
stores the bookmark as a private create-only grant record inside the persistent
Grabowski Juno agent state.

The script does not bypass iPadOS sandboxing and does not enumerate or read the
selected folder's contents.
"""

from __future__ import annotations

import base64
import builtins
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid
from typing import Any

from juno import dialogs
from juno.objc import (
    ObjCClass,
    ObjCInstance,
    ObjCProtocol,
    create_objc_class,
    ns,
    nsdata_to_bytes,
    on_main_thread,
    py_from_ns,
)


SCHEMA_VERSION = 1
BOOKMARK_CREATION_WITH_SECURITY_SCOPE = 1 << 11
BOOKMARK_RESOLUTION_WITH_SECURITY_SCOPE = 1 << 10
PICKER_MODE_OPEN = 1
MAX_GRANT_RECORD_BYTES = 128 * 1024
GRANT_CLASS_PREFIX = "GrabowskiJunoFolderGrantDelegateV1"
_RUNTIME_KEY = "_grabowski_juno_storage_grant_runtime_v1"

_runtime = getattr(builtins, _RUNTIME_KEY, None)
if not isinstance(_runtime, dict):
    _runtime = {"retained": {}}
    setattr(builtins, _RUNTIME_KEY, _runtime)
_RETAINED: dict[str, Any] = _runtime["retained"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _zero_arg(value: Any) -> Any:
    return value() if callable(value) else value


def _python_home() -> Path:
    return Path.home().resolve(strict=False)


def _state_root() -> Path:
    return (
        _python_home()
        / "Library"
        / "Application Support"
        / "GrabowskiJunoAgent"
    )


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise RuntimeError(f"unsafe private grant directory: {path}")


def _atomic_create(path: Path, payload: bytes) -> None:
    if len(payload) > MAX_GRANT_RECORD_BYTES:
        raise RuntimeError("grant record exceeds the bounded size")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or mode != 0o600
        ):
            raise RuntimeError(
                "grant record descriptor identity mismatch: "
                f"owner={metadata.st_uid}, mode={oct(mode)}, links={metadata.st_nlink}"
            )
        path_metadata = path.lstat()
        if (
            not stat.S_ISREG(path_metadata.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or path_metadata.st_dev != metadata.st_dev
            or path_metadata.st_ino != metadata.st_ino
            or path_metadata.st_nlink != 1
        ):
            raise RuntimeError("grant record path identity changed after creation")
    finally:
        os.close(descriptor)
    directory_descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _provider_hint(path: Path) -> str:
    text = str(path)
    if "/Library/Mobile Documents/" in text:
        return "apple_mobile_documents_or_file_provider"
    if "/Containers/Shared/AppGroup/" in text:
        return "ios_file_provider_or_shared_app_group"
    if "/Containers/Data/Application/" in text:
        return "application_container"
    if text.startswith("/private/var/mobile/Media/"):
        return "ios_media_area"
    return "document_provider_unknown"


def _first_url(urls: ObjCInstance) -> ObjCInstance:
    try:
        converted = py_from_ns(urls)
        if isinstance(converted, list) and converted:
            return converted[0]
    except Exception:
        pass
    count = int(_zero_arg(urls.count))
    if count != 1:
        raise RuntimeError(f"expected exactly one selected folder, got {count}")
    return urls.objectAtIndex_(0)


def _url_path(url: ObjCInstance) -> Path:
    raw = _zero_arg(url.path)
    converted = py_from_ns(raw)
    if not isinstance(converted, str) or not converted:
        converted = str(raw)
    path = Path(converted).resolve(strict=False)
    if not path.is_absolute():
        raise RuntimeError("selected URL did not resolve to an absolute path")
    return path


def _persist_grant(url: ObjCInstance) -> dict[str, Any]:
    scoped = bool(url.startAccessingSecurityScopedResource())
    if not scoped:
        raise RuntimeError("iPadOS did not open the selected security scope")
    try:
        selected_path = _url_path(url)
        bookmark_data = (
            url.bookmarkDataWithOptions_includingResourceValuesForKeys_relativeToURL_error_(
                BOOKMARK_CREATION_WITH_SECURITY_SCOPE,
                None,
                None,
                None,
            )
        )
        if bookmark_data is None:
            raise RuntimeError("iPadOS did not create a security-scoped bookmark")
        bookmark_bytes = nsdata_to_bytes(bookmark_data)
        if not bookmark_bytes:
            raise RuntimeError("security-scoped bookmark is empty")

        NSURL = ObjCClass("NSURL")
        resolved = (
            NSURL.URLByResolvingBookmarkData_options_relativeToURL_bookmarkDataIsStale_error_(
                bookmark_data,
                BOOKMARK_RESOLUTION_WITH_SECURITY_SCOPE,
                None,
                None,
                None,
            )
        )
        if resolved is None:
            raise RuntimeError("the new bookmark could not be resolved immediately")
        verification_scope = bool(resolved.startAccessingSecurityScopedResource())
        if not verification_scope:
            raise RuntimeError("the new bookmark did not reopen its security scope")
        try:
            resolved_path = _url_path(resolved)
            if resolved_path != selected_path:
                raise RuntimeError("bookmark readback resolved to a different path")
            exists = resolved_path.exists()
            readable = bool(exists and os.access(resolved_path, os.R_OK))
            writable = bool(exists and os.access(resolved_path, os.W_OK))
        finally:
            resolved.stopAccessingSecurityScopedResource()

        created_at = _utc_now()
        grant_id = f"grant-{uuid.uuid4().hex}"
        bookmark_sha256 = _sha256_bytes(bookmark_bytes)
        evidence_material = {
            "schema_version": SCHEMA_VERSION,
            "grant_id": grant_id,
            "selected_path": str(selected_path),
            "selected_name": selected_path.name or str(selected_path),
            "provider_hint": _provider_hint(selected_path),
            "bookmark_sha256": bookmark_sha256,
            "bookmark_creation_options": BOOKMARK_CREATION_WITH_SECURITY_SCOPE,
            "bookmark_resolution_options": BOOKMARK_RESOLUTION_WITH_SECURITY_SCOPE,
            "created_at": created_at,
            "exists": exists,
            "readable": readable,
            "writable": writable,
            "externally_granted": True,
        }
        record = {
            **evidence_material,
            "kind": "grabowski_juno_storage_grant",
            "bookmark_b64": base64.b64encode(bookmark_bytes).decode("ascii"),
            "evidence_hash": _sha256_bytes(_canonical_json_bytes(evidence_material)),
            "limitations": [
                "access is limited to the user-selected folder and its lawful descendants",
                "the grant does not expose private app containers or iPadOS system areas",
                "provider identity is a path-based hint until separately verified",
                "restart persistence requires a later agent and device readback",
            ],
        }
        grants_root = _state_root() / "storage-grants"
        _ensure_private_directory(grants_root)
        target = grants_root / f"{grant_id}.json"
        _atomic_create(target, _canonical_json_bytes(record) + b"\n")
        return {
            "status": "granted",
            "grant_id": grant_id,
            "selected_path": str(selected_path),
            "selected_name": evidence_material["selected_name"],
            "provider_hint": evidence_material["provider_hint"],
            "exists": exists,
            "readable": readable,
            "writable": writable,
            "bookmark_sha256": bookmark_sha256,
            "evidence_hash": record["evidence_hash"],
            "record_path": str(target),
        }
    finally:
        url.stopAccessingSecurityScopedResource()


def _release_picker(picker: ObjCInstance) -> None:
    for token, retained in list(_RETAINED.items()):
        try:
            if retained.get("picker") == picker:
                _RETAINED.pop(token, None)
                return
        except Exception:
            continue
    if len(_RETAINED) > 16:
        _RETAINED.pop(next(iter(_RETAINED)), None)


def _local_alert(title: str, message: str) -> None:
    try:
        dialogs.alert(title, message, ["OK"])
    except Exception:
        pass


def documentPicker_didPickDocumentsAtURLs_(
    self: ObjCInstance,
    picker: ObjCInstance,
    urls: ObjCInstance,
) -> None:
    try:
        result = _persist_grant(_first_url(urls))
        print(
            "Freigabe gespeichert: "
            f"{result['selected_name']} ({result['grant_id']}); "
            f"lesbar={result['readable']}, schreibbar={result['writable']}"
        )
        _local_alert(
            "Ordner aufgenommen",
            f"{result['selected_name']}\nFreigabe: {result['grant_id']}",
        )
    except Exception as exc:
        error = f"{type(exc).__name__}: {str(exc)[:500]}"
        print(f"Freigabe fehlgeschlagen: {error}")
        _local_alert("Freigabe fehlgeschlagen", error)
    finally:
        _release_picker(picker)


def documentPickerWasCancelled_(
    self: ObjCInstance,
    picker: ObjCInstance,
) -> None:
    print("Ordnerauswahl abgebrochen; es wurde keine Freigabe gespeichert.")
    _release_picker(picker)


def _top_presenter() -> ObjCInstance:
    UIApplication = ObjCClass("UIApplication")
    app = _zero_arg(UIApplication.sharedApplication)
    connected = _zero_arg(app.connectedScenes)
    scenes = py_from_ns(_zero_arg(connected.allObjects))
    windows: list[ObjCInstance] = []
    for scene in scenes:
        if int(_zero_arg(scene.activationState)) not in {0, 1}:
            continue
        scene_windows = py_from_ns(_zero_arg(scene.windows))
        windows.extend(scene_windows)
    if not windows:
        raise RuntimeError("Juno has no active iPadOS window for the folder picker")
    visible = [
        window
        for window in windows
        if not bool(_zero_arg(window.isHidden)) and float(_zero_arg(window.alpha)) > 0
    ]
    key_windows = [window for window in visible if bool(_zero_arg(window.isKeyWindow))]
    chosen = key_windows[0] if key_windows else (visible[0] if visible else windows[0])
    controller = _zero_arg(chosen.rootViewController)
    if controller is None:
        raise RuntimeError("Juno's active window has no root view controller")
    depth = 0
    while depth < 20:
        presented = _zero_arg(controller.presentedViewController)
        if presented is None:
            return controller
        controller = presented
        depth += 1
    raise RuntimeError("Juno's presentation stack exceeds the safety bound")


@on_main_thread
def _dismiss_retained_pickers() -> None:
    for retained in list(_RETAINED.values()):
        picker = retained.get("picker")
        if picker is None:
            continue
        try:
            picker.dismissViewControllerAnimated_completion_(False, None)
        except Exception:
            pass
    _RETAINED.clear()


@on_main_thread
def _present_picker() -> str:
    delegate_class_name = f"{GRANT_CLASS_PREFIX}_{uuid.uuid4().hex}"
    Delegate = create_objc_class(
        delegate_class_name,
        superclass=ObjCClass("NSObject"),
        methods=[
            documentPicker_didPickDocumentsAtURLs_,
            documentPickerWasCancelled_,
        ],
        protocols=[ObjCProtocol("UIDocumentPickerDelegate")],
    )
    delegate = Delegate.alloc().init()
    Picker = ObjCClass("UIDocumentPickerViewController")
    picker = Picker.alloc().initWithDocumentTypes_inMode_(
        ns(["public.folder"]),
        PICKER_MODE_OPEN,
    )
    if picker is None:
        raise RuntimeError("Juno could not create the iPadOS folder picker")
    picker.setDelegate_(delegate)
    picker.setAllowsMultipleSelection_(False)
    token = uuid.uuid4().hex
    _RETAINED[token] = {
        "delegate": delegate,
        "picker": picker,
        "created_at": _utc_now(),
    }
    presenter = _top_presenter()
    presenter.presentViewController_animated_completion_(picker, True, None)
    return token


def main() -> int:
    if _RETAINED:
        _dismiss_retained_pickers()
    print("Grabowski/Juno: Bitte genau einen Ordner auswählen.")
    print(
        "Es werden zunächst nur Zugriffsmetadaten und eine "
        "iPadOS-Freigabereferenz gespeichert."
    )
    try:
        token = _present_picker()
    except Exception as exc:
        print(f"Ordnerauswahl konnte nicht geöffnet werden: {type(exc).__name__}: {exc}")
        return 1
    print(
        "Der iPadOS-Dialog ist geöffnet. Dieses Skript blockiert Junos "
        f"Hauptthread nicht (Vorgang {token[:12]})."
    )
    print("Nach Auswahl oder Abbruch erscheint eine lokale Bestätigung.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

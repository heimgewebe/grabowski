from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Literal


MANAGED_LAUNCHER_MARKER = b"# managed-by: heimgewebe-bureau-runtime-v1\n"
MANIFEST_PAYLOAD_DIGEST_FIELD = "manifest_payload_sha256"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

ManifestBindingKind = Literal[
    "manifest-sha256-v1",
    "manifest-payload-sha256-v2",
]


@dataclass(frozen=True)
class ManagedLauncherBinding:
    manifest_path: Path
    manifest_binding_kind: ManifestBindingKind
    manifest_binding_value: str


class ManagedLauncherContractError(ValueError):
    def __init__(
        self,
        reason: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(f"managed Bureau launcher contract invalid: {reason}")
        self.reason = reason
        self.details = details or {}


def _launcher_assignment_values(tree: ast.Module, name: str) -> list[ast.expr]:
    matches: list[ast.expr] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == name:
            matches.append(node.value)
    return matches


def _literal_launcher_assignment(tree: ast.Module, name: str) -> ast.expr:
    matches = _launcher_assignment_values(tree, name)
    if len(matches) != 1:
        raise ManagedLauncherContractError(
            "assignment-count-invalid",
            details={"assignment": name, "count": len(matches)},
        )
    return matches[0]


def parse_managed_launcher_binding(
    launcher_raw: bytes,
    launcher_path: Path,
    *,
    expected_manifest_path: Path,
) -> ManagedLauncherBinding:
    if MANAGED_LAUNCHER_MARKER not in launcher_raw[:512]:
        raise ManagedLauncherContractError("marker-missing")
    try:
        launcher_text = launcher_raw.decode("utf-8")
        tree = ast.parse(launcher_text, filename=str(launcher_path), mode="exec")
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise ManagedLauncherContractError(
            "syntax-invalid",
            details={"error_type": type(exc).__name__},
        ) from None
    manifest_expr = _literal_launcher_assignment(tree, "manifest_path")
    if not (
        isinstance(manifest_expr, ast.Call)
        and isinstance(manifest_expr.func, ast.Name)
        and manifest_expr.func.id == "Path"
        and len(manifest_expr.args) == 1
        and not manifest_expr.keywords
        and isinstance(manifest_expr.args[0], ast.Constant)
        and isinstance(manifest_expr.args[0].value, str)
    ):
        raise ManagedLauncherContractError("manifest-path-expression-invalid")
    manifest_path = Path(manifest_expr.args[0].value)
    legacy = _launcher_assignment_values(tree, "expected_manifest_sha256")
    payload = _launcher_assignment_values(tree, "manifest_digest_field")
    if bool(legacy) == bool(payload):
        raise ManagedLauncherContractError(
            "manifest-digest-binding-ambiguous",
            details={
                "legacy_count": len(legacy),
                "payload_count": len(payload),
            },
        )
    if legacy:
        if len(legacy) != 1:
            raise ManagedLauncherContractError(
                "assignment-count-invalid",
                details={
                    "assignment": "expected_manifest_sha256",
                    "count": len(legacy),
                },
            )
        digest_expr = legacy[0]
        if not (
            isinstance(digest_expr, ast.Constant)
            and isinstance(digest_expr.value, str)
            and _SHA256_RE.fullmatch(digest_expr.value)
        ):
            raise ManagedLauncherContractError("manifest-digest-expression-invalid")
        binding = ManagedLauncherBinding(
            manifest_path=manifest_path,
            manifest_binding_kind="manifest-sha256-v1",
            manifest_binding_value=digest_expr.value,
        )
    else:
        if len(payload) != 1:
            raise ManagedLauncherContractError(
                "assignment-count-invalid",
                details={
                    "assignment": "manifest_digest_field",
                    "count": len(payload),
                },
            )
        field_expr = payload[0]
        if not (
            isinstance(field_expr, ast.Constant)
            and field_expr.value == MANIFEST_PAYLOAD_DIGEST_FIELD
        ):
            raise ManagedLauncherContractError("manifest-payload-digest-field-invalid")
        binding = ManagedLauncherBinding(
            manifest_path=manifest_path,
            manifest_binding_kind="manifest-payload-sha256-v2",
            manifest_binding_value=field_expr.value,
        )
    if binding.manifest_path != expected_manifest_path:
        raise ManagedLauncherContractError("manifest-path-mismatch")
    return binding


def verify_managed_launcher_manifest(
    binding: ManagedLauncherBinding,
    manifest_raw: bytes,
    manifest: dict[str, Any],
) -> None:
    if binding.manifest_binding_kind == "manifest-sha256-v1":
        if hashlib.sha256(manifest_raw).hexdigest() != binding.manifest_binding_value:
            raise ManagedLauncherContractError("manifest-binding-mismatch")
        return
    if binding.manifest_binding_kind != "manifest-payload-sha256-v2":
        raise ManagedLauncherContractError("manifest-binding-kind-unsupported")

    try:
        canonical = (
            json.dumps(
                manifest,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ManagedLauncherContractError(
            "manifest-payload-canonicalization-failed",
            details={"error_type": type(exc).__name__},
        ) from None
    if manifest_raw != canonical:
        raise ManagedLauncherContractError("manifest-payload-manifest-not-canonical")
    payload = dict(manifest)
    expected = payload.pop(binding.manifest_binding_value, None)
    if not isinstance(expected, str) or _SHA256_RE.fullmatch(expected) is None:
        raise ManagedLauncherContractError("manifest-payload-digest-invalid")
    rendered_payload = (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    if hashlib.sha256(rendered_payload).hexdigest() != expected:
        raise ManagedLauncherContractError("manifest-payload-digest-mismatch")

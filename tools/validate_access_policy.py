#!/usr/bin/env python3
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
POLICIES = (
    ROOT / "config" / "access.example.json",
    ROOT / "config" / "access.home-wide-operator.example.json",
    ROOT / "config" / "access.trusted-owner.example.json",
)
SCHEMAS = (
    ROOT / "contracts" / "access-policy.v1.schema.json",
    ROOT / "contracts" / "access-policy.v2.schema.json",
)
required = {
    "version": int,
    "mode": str,
    "read_roots": list,
    "write_roots": list,
    "write_excluded_roots": list,
    "secret_roots": list,
    "browser_profile_roots": list,
    "secret_export_roots": list,
    "max_read_bytes": int,
    "max_write_bytes": int,
    "max_list_entries": int,
    "max_secret_use_output_bytes": int,
    "max_secret_use_seconds": int,
    "forbid_symlinks": bool,
    "forbidden_components": list,
    "forbidden_file_patterns": list,
    "forbidden_capabilities": list,
}
known_capabilities = {
    "file_read",
    "file_write",
    "friction_record",
    "audit_verify",
    "rollback_text",
    "bundle_registry",
    "secret_inspect",
    "secret_reveal",
    "secret_use",
    "secret_export",
    "browser_profile_read",
    "terminal_execute",
    "durable_job",
    "git_cli",
    "github_cli",
    "user_service_control",
    "tmux_interaction",
    "process_inspect",
    "process_signal",
    "port_inspect",
    "privileged_reference",
    "resource_lease",
    "artifact_transfer",
    "browser_worker",
    "gui_worker",
    "file_delete",
    "file_destroy",
    "file_move",
    "chmod",
    "chown",
    "secret_read",
}
target_secret_roots = {
    "${HOME}/.ssh",
    "${HOME}/.gnupg",
    "${HOME}/.aws",
    "${HOME}/.kube",
    "${HOME}/.password-store",
    "${HOME}/.local/share/keyrings",
}
target_browser_roots = {
    "${HOME}/.mozilla/firefox",
    "${HOME}/.config/BraveSoftware/Brave-Browser",
    "${HOME}/.config/google-chrome",
    "${HOME}/.config/chromium",
}
target_sensitive_components = {
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".password-store",
    ".local/share/keyrings",
    ".mozilla/firefox",
    ".config/BraveSoftware/Brave-Browser",
    ".config/google-chrome",
    ".config/chromium",
}
secret_capabilities = {
    "secret_inspect",
    "secret_reveal",
    "secret_use",
    "secret_export",
}
forbidden_private_names = {
    "private_inspect",
    "private_content",
    "private_local_transfer",
    "private_safe_consumption",
}
staged_profile_names = {"observe", "maintain", "mutate", "break-glass"}
default_safe_profiles = {"observe", "maintain"}


def require_string_list(path: Path, data: dict, key: str) -> None:
    value = data.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SystemExit(f"{path}: {key} must be a string list.")
    if len(value) != len(set(value)):
        raise SystemExit(f"{path}: {key} must not contain duplicates.")
    for item in value:
        expanded = item.replace("${HOME}", "/home/example")
        if not Path(expanded).expanduser().is_absolute():
            raise SystemExit(
                f"{path}: {key} root must be absolute after expansion: {item}"
            )


def require_capabilities(path: Path, label: str, capabilities: list[str]) -> None:
    if len(capabilities) != len(set(capabilities)):
        raise SystemExit(f"{path}: {label} has duplicate capabilities.")
    unknown = sorted(set(capabilities) - known_capabilities)
    if unknown:
        raise SystemExit(f"{path}: {label} has unknown capabilities: {unknown}")
    private = sorted(set(capabilities) & forbidden_private_names)
    if private:
        raise SystemExit(f"{path}: {label} uses retired private capabilities: {private}")


def has_home_wide_root(data: dict) -> bool:
    return "${HOME}" in data["read_roots"] or "${HOME}" in data["write_roots"]


def require_home_wide_typed_roots(path: Path, label: str, data: dict) -> None:
    if not has_home_wide_root(data):
        return
    missing_secrets = sorted(target_secret_roots - set(data["secret_roots"]))
    if missing_secrets:
        raise SystemExit(
            f"{path}: {label} uses ${{HOME}} as a read/write root "
            f"without typed secret roots: {missing_secrets}"
        )
    missing_browser_roots = sorted(
        target_browser_roots - set(data["browser_profile_roots"])
    )
    if missing_browser_roots:
        raise SystemExit(
            f"{path}: {label} uses ${{HOME}} as a read/write root "
            f"without typed browser profile roots: {missing_browser_roots}"
        )


def validate_policy(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    for key, expected_type in required.items():
        if key not in data:
            raise SystemExit(f"{path}: missing policy field: {key}")
        if not isinstance(data[key], expected_type):
            raise SystemExit(
                f"{path}: invalid type for {key}: "
                f"{type(data[key]).__name__}, expected {expected_type.__name__}"
            )
    if data["version"] != 2:
        raise SystemExit(f"{path}: example policies must use policy version 2.")
    trusted_owner = bool(data.get("trusted_owner", False))
    if "trusted_owner" in data and not isinstance(data["trusted_owner"], bool):
        raise SystemExit(f"{path}: trusted_owner must be a boolean.")
    if not trusted_owner and "${HOME}/repos/merges" not in data["write_excluded_roots"]:
        raise SystemExit(
            f"{path}: ${{HOME}}/repos/merges must remain an explicit write exclusion."
        )
    for key in (
        "read_roots",
        "write_roots",
        "write_excluded_roots",
        "secret_roots",
        "browser_profile_roots",
        "secret_export_roots",
    ):
        require_string_list(path, data, key)
    if data["secret_roots"]:
        missing = sorted(target_secret_roots - set(data["secret_roots"]))
        if missing:
            raise SystemExit(f"{path}: missing top-level secret roots: {missing}")
    if data["browser_profile_roots"]:
        missing = sorted(target_browser_roots - set(data["browser_profile_roots"]))
        if missing:
            raise SystemExit(f"{path}: missing top-level browser roots: {missing}")
    require_home_wide_typed_roots(path, "policy", data)

    sensitive_denials = sorted(
        set(data["forbidden_components"]) & target_sensitive_components
    )
    if sensitive_denials:
        raise SystemExit(
            f"{path}: sensitive roots must be typed roots, not forbidden "
            f"components: {sensitive_denials}"
        )
    blocked_private_files = sorted(
        set(data["forbidden_file_patterns"]) & {"id_rsa", "id_ed25519"}
    )
    if blocked_private_files:
        raise SystemExit(
            f"{path}: private key names belong behind secret tools, not generic "
            f"forbidden_file_patterns: {blocked_private_files}"
        )
    if not any(root in data["read_roots"] for root in ("/", "${HOME}/repos", "${HOME}")):
        raise SystemExit(f"{path}: policy must keep a documented read root.")
    require_capabilities(path, "forbidden_capabilities", data["forbidden_capabilities"])

    definitions = data.get("capability_definitions", {})
    if not isinstance(definitions, dict):
        raise SystemExit(f"{path}: capability_definitions must be an object.")
    unknown_definitions = sorted(set(definitions) - known_capabilities)
    if unknown_definitions:
        raise SystemExit(
            f"{path}: unknown capability definitions: {unknown_definitions}"
        )
    private_definitions = sorted(set(definitions) & forbidden_private_names)
    if private_definitions:
        raise SystemExit(
            f"{path}: retired private capability definitions remain: "
            f"{private_definitions}"
        )

    profiles = data.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise SystemExit(f"{path}: profiles must be a non-empty object.")
    active = data.get("active_profile", data.get("mode"))
    if active not in profiles:
        raise SystemExit(f"{path}: active profile is not defined: {active!r}")
    if not trusted_owner and path.name != "access.trusted-owner.example.json":
        missing_staged = sorted(staged_profile_names - set(profiles))
        if missing_staged:
            raise SystemExit(f"{path}: missing staged profiles: {missing_staged}")
    if path.name == "access.example.json" and active not in default_safe_profiles:
        raise SystemExit(
            f"{path}: default example must activate observe or maintain, got {active!r}"
        )
    for name, profile in profiles.items():
        if not isinstance(profile, dict):
            raise SystemExit(f"{path}: profile {name} must be an object.")
        for key in (
            "read_roots",
            "write_roots",
            "write_excluded_roots",
            "secret_roots",
            "browser_profile_roots",
            "secret_export_roots",
            "capabilities",
        ):
            if not isinstance(profile.get(key), list):
                raise SystemExit(f"{path}: profile {name} missing list {key}.")
            if key != "capabilities":
                require_string_list(path, profile, key)
        profile_trusted_owner = bool(profile.get("trusted_owner", trusted_owner))
        if "trusted_owner" in profile and not isinstance(profile["trusted_owner"], bool):
            raise SystemExit(f"{path}: profile {name} trusted_owner must be boolean.")
        if not profile_trusted_owner and "${HOME}/repos/merges" not in profile["write_excluded_roots"]:
            raise SystemExit(
                f"{path}: profile {name} must exclude ${{HOME}}/repos/merges."
            )
        require_capabilities(path, f"profile {name}", profile["capabilities"])
        require_home_wide_typed_roots(path, f"profile {name}", profile)
        capabilities = set(profile["capabilities"])
        if secret_capabilities & capabilities:
            missing = sorted(target_secret_roots - set(profile["secret_roots"]))
            if missing:
                raise SystemExit(
                    f"{path}: profile {name} missing secret roots for secret "
                    f"capabilities: {missing}"
                )
        if "secret_export" in capabilities and not profile["secret_export_roots"]:
            raise SystemExit(
                f"{path}: profile {name} enables secret_export without "
                "secret_export_roots."
            )
        if "browser_profile_read" in capabilities:
            missing = sorted(target_browser_roots - set(profile["browser_profile_roots"]))
            if missing:
                raise SystemExit(
                    f"{path}: profile {name} missing browser profile roots: "
                    f"{missing}"
                )


def main() -> None:
    for schema in SCHEMAS:
        json.loads(schema.read_text(encoding="utf-8"))
    for policy in POLICIES:
        validate_policy(policy)
    print("PASS: access policy examples satisfy the repository contract")


if __name__ == "__main__":
    main()

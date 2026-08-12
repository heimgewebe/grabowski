#!/usr/bin/env python3
"""Validate Grabowski's revision-bound Chronik coding-memory runtime binding."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "contracts" / "chronik-coding-memory-runtime.v1.json"
BINDING_PATH = ROOT / "contracts" / "chronik-coding-memory-runtime.binding.v1.json"
RUNTIME_INPUT = ROOT / "requirements" / "runtime.in"
RUNTIME_LOCK = ROOT / "requirements" / "runtime.lock.txt"
PYPROJECT = ROOT / "pyproject.toml"

EXPECTED_CONTRACT_SCHEMA = "chronik-coding-memory-runtime.v1"
EXPECTED_BINDING_SCHEMA = "grabowski-chronik-coding-memory-runtime-binding.v1"
EXPECTED_PRODUCER_REPOSITORY = "heimgewebe/chronik"
EXPECTED_PRODUCER_PATH = "tools/coding_memory.runtime.v1.json"
EXPECTED_ENTRYPOINT = "tools/coding_memory.py"
EXPECTED_REQUIREMENTS_SOURCE = "requirements.txt"
REQUIRED_BOUNDARIES = {
    "dynamic_import_absence",
    "installed_distribution_versions",
    "consumer_environment_compatibility",
    "runtime_success_without_consumer_validation",
}
PIN_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9][A-Za-z0-9.+!-]*)$")
CLAUSE_RE = re.compile(r"^(==|>=|<=|>|<)(\d+(?:\.\d+)*)$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _version_tuple(value: str) -> tuple[int, ...]:
    if re.fullmatch(r"\d+(?:\.\d+)*", value) is None:
        raise ValueError(f"unsupported runtime version: {value!r}")
    return tuple(int(part) for part in value.split("."))


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    a = left + (0,) * (width - len(left))
    b = right + (0,) * (width - len(right))
    return (a > b) - (a < b)


def _satisfies(version: str, specifier: str) -> bool:
    current = _version_tuple(version)
    for raw_clause in specifier.split(","):
        clause = raw_clause.strip()
        match = CLAUSE_RE.fullmatch(clause)
        if match is None:
            raise ValueError(f"unsupported producer specifier clause: {clause!r}")
        op, expected_text = match.groups()
        relation = _compare(current, _version_tuple(expected_text))
        if op == "==" and relation != 0:
            return False
        if op == ">=" and relation < 0:
            return False
        if op == "<=" and relation > 0:
            return False
        if op == ">" and relation <= 0:
            return False
        if op == "<" and relation >= 0:
            return False
    return True


def _parse_direct_pins(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = PIN_RE.fullmatch(line)
        if match is None:
            raise ValueError(f"runtime input is not exactly pinned: {raw!r}")
        name, version = match.groups()
        normalized = _normalize(name)
        if normalized in pins:
            raise ValueError(f"duplicate direct runtime pin: {normalized}")
        pins[normalized] = version
    return pins


def _parse_lock_versions(path: Path) -> dict[str, str]:
    versions: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw or raw[:1].isspace() or raw.startswith("#"):
            continue
        head = raw[:-2] if raw.endswith(" \\") else raw
        match = PIN_RE.fullmatch(head)
        if match is None:
            continue
        name, version = match.groups()
        normalized = _normalize(name)
        if normalized in versions:
            raise ValueError(f"duplicate runtime lock package: {normalized}")
        versions[normalized] = version
    return versions


def _parse_pyproject_dependencies(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    match = re.search(r"(?ms)^dependencies\s*=\s*\[\s*(.*?)^\]", text)
    if match is None:
        raise ValueError("pyproject project dependencies block is missing")
    pins: dict[str, str] = {}
    for raw in match.group(1).splitlines():
        line = raw.strip().rstrip(",")
        if not line:
            continue
        if len(line) < 2 or line[0] != '"' or line[-1] != '"':
            raise ValueError(f"pyproject dependency is not a simple string: {raw!r}")
        requirement = line[1:-1]
        pin = PIN_RE.fullmatch(requirement)
        if pin is None:
            raise ValueError(f"pyproject dependency is not exactly pinned: {requirement!r}")
        name, version = pin.groups()
        normalized = _normalize(name)
        if normalized in pins:
            raise ValueError(f"duplicate pyproject runtime pin: {normalized}")
        pins[normalized] = version
    return pins


def _load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain an object")
    return value


def validate_root(root: Path = ROOT) -> dict[str, object]:
    contract_path = root / CONTRACT_PATH.relative_to(ROOT)
    binding_path = root / BINDING_PATH.relative_to(ROOT)
    runtime_input = root / RUNTIME_INPUT.relative_to(ROOT)
    runtime_lock = root / RUNTIME_LOCK.relative_to(ROOT)
    pyproject = root / PYPROJECT.relative_to(ROOT)

    contract_raw = contract_path.read_bytes()
    binding = _load_json(binding_path)
    expected_binding_keys = {
        "schema_version",
        "producer_repository",
        "producer_commit",
        "producer_path",
        "producer_git_blob_sha",
        "producer_sha256",
    }
    if set(binding) != expected_binding_keys:
        raise ValueError("Chronik runtime binding fields drifted")
    if binding.get("schema_version") != EXPECTED_BINDING_SCHEMA:
        raise ValueError("Chronik runtime binding schema_version mismatch")
    if binding.get("producer_repository") != EXPECTED_PRODUCER_REPOSITORY:
        raise ValueError("Chronik runtime producer repository mismatch")
    if binding.get("producer_path") != EXPECTED_PRODUCER_PATH:
        raise ValueError("Chronik runtime producer path mismatch")
    producer_commit = binding.get("producer_commit")
    producer_blob = binding.get("producer_git_blob_sha")
    producer_sha256 = binding.get("producer_sha256")
    if not isinstance(producer_commit, str) or HEX40_RE.fullmatch(producer_commit) is None:
        raise ValueError("Chronik runtime producer commit is invalid")
    if not isinstance(producer_blob, str) or HEX40_RE.fullmatch(producer_blob) is None:
        raise ValueError("Chronik runtime producer blob is invalid")
    if not isinstance(producer_sha256, str) or HEX64_RE.fullmatch(producer_sha256) is None:
        raise ValueError("Chronik runtime producer sha256 is invalid")
    observed_sha256 = hashlib.sha256(contract_raw).hexdigest()
    if observed_sha256 != producer_sha256:
        raise ValueError("vendored Chronik runtime contract sha256 mismatch")
    git_blob = hashlib.sha1(
        b"blob " + str(len(contract_raw)).encode("ascii") + b"\0" + contract_raw,
        usedforsecurity=False,
    ).hexdigest()
    if git_blob != producer_blob:
        raise ValueError("vendored Chronik runtime contract git blob mismatch")

    contract = json.loads(contract_raw)
    if not isinstance(contract, dict):
        raise ValueError("Chronik runtime contract must contain an object")
    expected_contract_keys = {
        "schema_version",
        "entrypoint",
        "requirements_source",
        "python",
        "required_distributions",
        "does_not_establish",
    }
    if set(contract) != expected_contract_keys:
        raise ValueError("Chronik runtime contract fields drifted")
    if contract.get("schema_version") != EXPECTED_CONTRACT_SCHEMA:
        raise ValueError("Chronik runtime contract schema_version mismatch")
    if contract.get("entrypoint") != EXPECTED_ENTRYPOINT:
        raise ValueError("Chronik runtime contract entrypoint mismatch")
    if contract.get("requirements_source") != EXPECTED_REQUIREMENTS_SOURCE:
        raise ValueError("Chronik runtime requirements_source mismatch")

    python_contract = contract.get("python")
    if not isinstance(python_contract, dict) or set(python_contract) != {"requires"}:
        raise ValueError("Chronik runtime Python contract is invalid")
    python_requires = python_contract.get("requires")
    if not isinstance(python_requires, str) or not python_requires:
        raise ValueError("Chronik runtime Python requirement is invalid")
    consumer_python = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if not _satisfies(consumer_python, python_requires):
        raise ValueError(
            "Grabowski validation Python violates Chronik contract: "
            f"python=={consumer_python} not in {python_requires}"
        )

    boundaries = contract.get("does_not_establish")
    if (
        not isinstance(boundaries, list)
        or not all(isinstance(item, str) and item for item in boundaries)
        or len(boundaries) != len(set(boundaries))
    ):
        raise ValueError("Chronik runtime does_not_establish is invalid")
    missing_boundaries = sorted(REQUIRED_BOUNDARIES - set(boundaries))
    if missing_boundaries:
        raise ValueError(
            "Chronik runtime semantic boundaries drifted: missing="
            + ",".join(missing_boundaries)
        )

    direct = _parse_direct_pins(runtime_input)
    locked = _parse_lock_versions(runtime_lock)
    packaged = _parse_pyproject_dependencies(pyproject)
    entries = contract.get("required_distributions")
    if not isinstance(entries, list) or not entries:
        raise ValueError("Chronik runtime required_distributions is empty")
    seen: set[str] = set()
    compatible: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"distribution", "specifier", "imports"}:
            raise ValueError("Chronik runtime distribution entry is invalid")
        distribution = entry.get("distribution")
        specifier = entry.get("specifier")
        imports = entry.get("imports")
        if not isinstance(distribution, str) or not isinstance(specifier, str):
            raise ValueError("Chronik runtime distribution/specifier is invalid")
        if not isinstance(imports, list) or not imports or not all(isinstance(item, str) and item for item in imports):
            raise ValueError(f"Chronik runtime imports are invalid for {distribution}")
        normalized = _normalize(distribution)
        if normalized in seen:
            raise ValueError(f"duplicate Chronik runtime distribution: {normalized}")
        seen.add(normalized)
        direct_version = direct.get(normalized)
        lock_version = locked.get(normalized)
        packaged_version = packaged.get(normalized)
        if direct_version is None:
            raise ValueError(f"Chronik runtime dependency is not a direct Grabowski pin: {normalized}")
        if lock_version != direct_version:
            raise ValueError(
                f"Chronik runtime dependency differs between input and lock: {normalized}"
            )
        if packaged_version != direct_version:
            raise ValueError(
                f"Chronik runtime dependency differs between input and pyproject: {normalized}"
            )
        if not _satisfies(direct_version, specifier):
            raise ValueError(
                "Grabowski runtime pin violates Chronik contract: "
                f"{normalized}=={direct_version} not in {specifier}"
            )
        compatible[normalized] = direct_version

    return {
        "schema_version": EXPECTED_BINDING_SCHEMA,
        "producer_commit": producer_commit,
        "producer_sha256": producer_sha256,
        "producer_python_requires": python_requires,
        "compatible_runtime_pins": dict(sorted(compatible.items())),
    }


def main() -> int:
    try:
        result = validate_root()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

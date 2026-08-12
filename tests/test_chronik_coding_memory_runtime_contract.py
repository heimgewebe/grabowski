import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "tools" / "validate_chronik_coding_memory_runtime.py"
SPEC = importlib.util.spec_from_file_location("chronik_runtime_binding", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class ChronikCodingMemoryRuntimeContractTests(unittest.TestCase):
    def test_current_binding_matches_producer_and_runtime_lock(self) -> None:
        result = validator.validate_root(ROOT)
        self.assertEqual(
            result["producer_commit"],
            "d8a097dd9356d840cc277d4a61a4749d9d48c9d1",
        )
        self.assertEqual(result["producer_python_requires"], ">=3.10")
        self.assertEqual(
            result["compatible_runtime_lock"],
            {
                "filelock": "3.32.2",
                "jsonschema": "4.26.0",
                "pydantic": "2.13.4",
                "pydantic-settings": "2.14.2",
                "pyyaml": "6.0.3",
            },
        )

    def test_specifier_comparison_is_bounded_and_fail_closed(self) -> None:
        self.assertTrue(validator._satisfies("2.14.2", ">=2.14,<3"))
        self.assertTrue(validator._satisfies("3.32.2", ">=3.13"))
        self.assertFalse(validator._satisfies("2.13.9", ">=2.14,<3"))
        self.assertFalse(validator._satisfies("3.0.0", ">=2.14,<3"))
        with self.assertRaisesRegex(ValueError, "unsupported producer specifier"):
            validator._satisfies("2.14.2", "~=2.14")

    def _fixture_root(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        (directory / "contracts").mkdir()
        (directory / "requirements").mkdir()
        shutil.copy2(
            ROOT / "contracts" / "chronik-coding-memory-runtime.v1.json",
            directory / "contracts" / "chronik-coding-memory-runtime.v1.json",
        )
        shutil.copy2(
            ROOT / "contracts" / "chronik-coding-memory-runtime.binding.v1.json",
            directory / "contracts" / "chronik-coding-memory-runtime.binding.v1.json",
        )
        pins = {
            "filelock": "3.32.2",
            "jsonschema": "4.26.0",
            "mcp": "1.27.2",
            "pydantic": "2.13.4",
            "pydantic-settings": "2.14.2",
            "pyyaml": "6.0.3",
        }
        (directory / "requirements" / "runtime.lock.txt").write_text(
            "\n".join(f"{name}=={version}" for name, version in pins.items()) + "\n",
            encoding="utf-8",
        )
        return directory

    def _rewrite_contract(self, root: Path, mutate) -> None:
        contract_path = root / "contracts" / "chronik-coding-memory-runtime.v1.json"
        binding_path = root / "contracts" / "chronik-coding-memory-runtime.binding.v1.json"
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        mutate(contract)
        contract_path.write_text(
            json.dumps(contract, indent=2) + "\n", encoding="utf-8"
        )
        raw = contract_path.read_bytes()
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        binding["producer_sha256"] = hashlib.sha256(raw).hexdigest()
        binding["producer_git_blob_sha"] = hashlib.sha1(
            b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw,
            usedforsecurity=False,
        ).hexdigest()
        binding_path.write_text(
            json.dumps(binding, indent=2) + "\n", encoding="utf-8"
        )

    def test_missing_locked_dependency_is_rejected(self) -> None:
        root = self._fixture_root()
        runtime_lock = root / "requirements" / "runtime.lock.txt"
        runtime_lock.write_text(
            runtime_lock.read_text(encoding="utf-8").replace(
                "pydantic-settings==2.14.2\n", ""
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "absent from Grabowski runtime lock"):
            validator.validate_root(root)

    def test_incompatible_locked_dependency_is_rejected(self) -> None:
        root = self._fixture_root()
        runtime_lock = root / "requirements" / "runtime.lock.txt"
        runtime_lock.write_text(
            runtime_lock.read_text(encoding="utf-8").replace(
                "pydantic-settings==2.14.2", "pydantic-settings==2.13.0"
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "runtime lock violates Chronik contract"):
            validator.validate_root(root)

    def test_vendored_contract_tampering_is_rejected_before_semantics(self) -> None:
        root = self._fixture_root()
        contract = root / "contracts" / "chronik-coding-memory-runtime.v1.json"
        contract.write_bytes(contract.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "sha256 mismatch"):
            validator.validate_root(root)

    def test_producer_python_floor_is_enforced_after_valid_rebinding(self) -> None:
        root = self._fixture_root()
        self._rewrite_contract(
            root,
            lambda contract: contract["python"].update({"requires": ">=99.0"}),
        )
        with self.assertRaisesRegex(ValueError, "validation Python violates"):
            validator.validate_root(root)

    def test_semantic_boundaries_cannot_be_silently_removed(self) -> None:
        root = self._fixture_root()

        def remove_boundary(contract):
            contract["does_not_establish"].remove("dynamic_import_absence")

        self._rewrite_contract(root, remove_boundary)
        with self.assertRaisesRegex(ValueError, "semantic boundaries drifted"):
            validator.validate_root(root)


if __name__ == "__main__":
    unittest.main()

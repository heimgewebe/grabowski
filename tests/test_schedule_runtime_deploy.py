from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "schedule_runtime_deploy_auto_source_test",
    ROOT / "tools" / "schedule_runtime_deploy.py",
)
assert SPEC is not None and SPEC.loader is not None
SCHEDULER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCHEDULER)


def _identity(material: dict[str, object]) -> dict[str, object]:
    digest = hashlib.sha256(
        json.dumps(
            material,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return {**material, "identity_sha256": digest}


def _canonical_receipt(head: str) -> dict[str, object]:
    repository = "/home/alex/repos/grabowski"
    identity = _identity(
        {
            "repository": repository,
            "canonical_repository": repository,
            "source_kind": "canonical-main",
            "head": head,
            "lease_evidence": {
                "resource_key": f"path:{repository}",
                "lease": None,
            },
        }
    )
    return {
        "scheduled": True,
        "expected_head": head,
        "source_identity": identity,
        "source_identity_sha256": identity["identity_sha256"],
        "automatic_source": None,
    }


def _automatic_receipt(head: str) -> dict[str, object]:
    repository = f"/home/alex/repos/.grabowski-deploy-worktrees/auto-current-main-{head[:12]}-abc123def456"
    canonical = "/home/alex/repos/grabowski"
    owner = f"runtime-deploy-source:{head[:12]}:abc123def456"
    resource_key = f"path:{repository}"
    lease = {
        "resource_key": resource_key,
        "owner_id": owner,
        "acquired_at_unix": 100,
        "updated_at_unix": 101,
        "expires_at_unix": 1000,
        "metadata_sha256": "c" * 64,
    }
    identity = _identity(
        {
            "repository": repository,
            "canonical_repository": canonical,
            "source_kind": "detached-worktree",
            "head": head,
            "lease_evidence": {
                "resource_key": resource_key,
                "lease": dict(lease),
            },
        }
    )
    return {
        "scheduled": True,
        "expected_head": head,
        "source_identity": identity,
        "source_identity_sha256": identity["identity_sha256"],
        "automatic_source": {
            "repository": repository,
            "owner_id": owner,
            "expected_head": head,
            "path_resource_key": resource_key,
            "path_lease": {**lease, "reclaimed_from_owner": None},
        },
    }


class RuntimeDeployAutomaticSourceReceiptTests(unittest.TestCase):
    def test_default_canonical_source_remains_accepted(self) -> None:
        head = "a" * 40
        receipt = _canonical_receipt(head)
        shared = Mock(return_value=receipt)
        with patch.object(SCHEDULER, "_load_runtime_scheduler", return_value=shared):
            observed = SCHEDULER.schedule(head, 8)
        self.assertEqual(observed, receipt)
        shared.assert_called_once_with(head, 8, None, None)

    def test_default_automatic_detached_source_is_receipt_bound(self) -> None:
        head = "b" * 40
        receipt = _automatic_receipt(head)
        shared = Mock(return_value=receipt)
        with patch.object(SCHEDULER, "_load_runtime_scheduler", return_value=shared):
            observed = SCHEDULER.schedule(head, 8)
        self.assertEqual(observed, receipt)
        shared.assert_called_once_with(head, 8, None, None)

    def test_default_detached_source_requires_automatic_source_binding(self) -> None:
        head = "c" * 40
        receipt = _automatic_receipt(head)
        receipt["automatic_source"] = None
        shared = Mock(return_value=receipt)
        with patch.object(SCHEDULER, "_load_runtime_scheduler", return_value=shared):
            with self.assertRaisesRegex(RuntimeError, "unbound automatic source"):
                SCHEDULER.schedule(head, 8)

    def test_default_detached_source_rejects_materialization_lease_drift(self) -> None:
        head = "d" * 40
        receipt = _automatic_receipt(head)
        automatic = receipt["automatic_source"]
        assert isinstance(automatic, dict)
        path_lease = automatic["path_lease"]
        assert isinstance(path_lease, dict)
        path_lease["metadata_sha256"] = "e" * 64
        shared = Mock(return_value=receipt)
        with patch.object(SCHEDULER, "_load_runtime_scheduler", return_value=shared):
            with self.assertRaisesRegex(
                RuntimeError, "different automatic source lease"
            ):
                SCHEDULER.schedule(head, 8)

    def test_default_detached_source_rejects_missing_lease_schema_field(self) -> None:
        head = "f" * 40
        receipt = _automatic_receipt(head)
        automatic = receipt["automatic_source"]
        identity = receipt["source_identity"]
        assert isinstance(automatic, dict)
        assert isinstance(identity, dict)
        path_lease = automatic["path_lease"]
        lease_evidence = identity["lease_evidence"]
        assert isinstance(path_lease, dict)
        assert isinstance(lease_evidence, dict)
        observed_lease = lease_evidence["lease"]
        assert isinstance(observed_lease, dict)
        del path_lease["metadata_sha256"]
        del observed_lease["metadata_sha256"]
        material = {key: value for key, value in identity.items() if key != "identity_sha256"}
        digest = hashlib.sha256(
            json.dumps(
                material,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        identity["identity_sha256"] = digest
        receipt["source_identity_sha256"] = digest
        shared = Mock(return_value=receipt)
        with patch.object(SCHEDULER, "_load_runtime_scheduler", return_value=shared):
            with self.assertRaises(KeyError):
                SCHEDULER.schedule(head, 8)

    def test_explicit_source_rejects_automatic_source_receipt(self) -> None:
        head = "e" * 40
        repository = "/home/alex/repos/grabowski"
        receipt = _canonical_receipt(head)
        receipt["automatic_source"] = {
            "repository": repository,
            "owner_id": "runtime-deploy-source:eeeeeeeeeeee:abc123def456",
        }
        shared = Mock(return_value=receipt)
        with patch.object(SCHEDULER, "_load_runtime_scheduler", return_value=shared):
            with self.assertRaisesRegex(RuntimeError, "unexpected automatic source"):
                SCHEDULER.schedule(head, 8, repository, None)


if __name__ == "__main__":
    unittest.main()

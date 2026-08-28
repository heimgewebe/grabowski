from __future__ import annotations

import unittest
from unittest import mock

import grabowski_attention_trace as attention


class AttentionTraceToolTests(unittest.TestCase):
    def test_build_attention_trace_reuses_observer_projection(self) -> None:
        workspace_id = "gaw-attention-tool-fixture"
        manifest = {"workspace_id": workspace_id, "scope": {"allowed_paths": ["src/x.py"]}}
        events = [{"sequence": 1, "event_type": "role_started", "role": "writer"}]
        event_log = {"present": True, "integrity_valid": True, "event_count": 1}
        expected = {"schema_version": 1, "kind": "attention_trace_v1", "trace_sha256": "a" * 64}
        with (
            mock.patch.object(attention.workspace, "_manifest", return_value=manifest),
            mock.patch.object(attention.observer, "_read_events", return_value=(events, event_log)),
            mock.patch.object(attention.observer, "_attention_trace", return_value=expected) as project,
        ):
            observed = attention.build_attention_trace(workspace_id)
        self.assertEqual(observed, expected)
        project.assert_called_once_with(workspace_id, manifest, events, event_log)

    def test_invalid_workspace_id_fails_before_state_read(self) -> None:
        with (
            mock.patch.object(attention.workspace, "_manifest") as manifest,
            self.assertRaises(ValueError),
        ):
            attention.build_attention_trace("../escape")
        manifest.assert_not_called()


if __name__ == "__main__":
    unittest.main()

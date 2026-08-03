from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest


class TransportSessionScopeRuntimeTests(unittest.TestCase):
    def test_unlabeled_sessions_receive_stable_disjoint_scopes(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        script = textwrap.dedent(
            """
            from pathlib import Path
            import tempfile
            import types

            import grabowski_runtime as runtime

            class Session:
                pass

            class Context:
                def __init__(self, session, client_id=None, *, stateless=False):
                    self.session = session
                    self.client_id = client_id
                    self.fastmcp = types.SimpleNamespace(
                        settings=types.SimpleNamespace(stateless_http=stateless)
                    )

            first_session = Session()
            second_session = Session()
            first = runtime._runtime_transport_client_scope(Context(first_session))
            replay = runtime._runtime_transport_client_scope(Context(first_session))
            second = runtime._runtime_transport_client_scope(Context(second_session))
            declared = runtime._runtime_transport_client_scope(
                Context(second_session, client_id="declared-connector")
            )
            stateless = runtime._runtime_transport_client_scope(
                Context(Session(), stateless=True)
            )
            missing = runtime._runtime_transport_client_scope(None)
            nonweak = runtime._runtime_transport_client_scope(Context(object()))

            assert first["kind"] == "server_session"
            assert first == replay
            assert first != second
            assert second["kind"] == "server_session"
            assert declared == {
                "kind": "client_declared_meta",
                "label": "declared-connector",
            }
            assert stateless["kind"] == "shared_unlabeled"
            assert missing["kind"] == "shared_unlabeled"
            assert nonweak["kind"] == "shared_unlabeled"

            transport = runtime._TRANSPORT_ROUNDTRIP
            binding = {
                "release_id": "release-1",
                "repo_head": "a" * 40,
                "registered_names_sha256": "b" * 64,
                "agent_instructions_sha256": "c" * 64,
            }
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "transport-state"
                transport.STATE_ROOT = root
                transport.LOCK_PATH = root / ".lock"

                begin = transport.begin(
                    client_scope=first,
                    runtime_binding=binding,
                    now_unix=100,
                )
                acknowledged = transport.acknowledge(
                    client_scope=first,
                    challenge_receipt_sha256=begin["challenge_receipt_sha256"],
                    runtime_binding=binding,
                    now_unix=101,
                )
                consumed = transport.consume_verified(
                    client_scope=first,
                    runtime_binding=binding,
                    tool_name="write",
                    arguments_sha256=transport.canonical_arguments_sha256(
                        {"path": "/tmp/example"}
                    ),
                    now_unix=102,
                )
                independent = transport.begin(
                    client_scope=second,
                    runtime_binding=binding,
                    now_unix=102,
                )

                assert begin["state"] == "challenge_pending"
                assert acknowledged["state"] == "verified"
                assert consumed["state"] == "consumed"
                assert independent["state"] == "challenge_pending"
                assert independent["client_scope_sha256"] != begin["client_scope_sha256"]
            """
        )
        environment = dict(os.environ)
        pythonpath = str(repository / "src")
        if environment.get("PYTHONPATH"):
            pythonpath += os.pathsep + environment["PYTHONPATH"]
        environment["PYTHONPATH"] = pythonpath
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=repository,
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )


if __name__ == "__main__":
    unittest.main()

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
            import grabowski_runtime as runtime

            class Session:
                pass

            class Context:
                def __init__(self, session, client_id=None):
                    self.session = session
                    self.client_id = client_id

            first_session = Session()
            second_session = Session()
            first = runtime._runtime_transport_client_scope(Context(first_session))
            replay = runtime._runtime_transport_client_scope(Context(first_session))
            second = runtime._runtime_transport_client_scope(Context(second_session))
            declared = runtime._runtime_transport_client_scope(
                Context(second_session, client_id="declared-connector")
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
            assert missing["kind"] == "shared_unlabeled"
            assert nonweak["kind"] == "shared_unlabeled"
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

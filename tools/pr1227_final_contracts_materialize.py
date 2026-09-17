from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement target, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


preflight = "tools/repobrief_agent_benchmark_preflight_core.py"
replace_once(
    preflight,
    "def _command_file_identities(command: Sequence[Any]) -> list[dict[str, Any]]:\n",
    "def _command_file_identities(\n    command: Sequence[Any], *, relative_to: Path | None = None\n) -> list[dict[str, Any]]:\n",
)
replace_once(
    preflight,
    "    identities: list[dict[str, Any]] = []\n    seen: set[str] = set()\n    for raw in command:\n",
    "    identities: list[dict[str, Any]] = []\n    seen: set[str] = set()\n    relative_root = None if relative_to is None else relative_to.expanduser().resolve()\n    for raw in command:\n",
)
replace_once(
    preflight,
    "        candidate = Path(raw).expanduser()\n        if not candidate.is_absolute() or not candidate.exists():\n            continue\n",
    "        candidate = Path(raw).expanduser()\n        if not candidate.is_absolute():\n            if relative_root is None:\n                continue\n            candidate = relative_root / candidate\n        if not candidate.exists():\n            continue\n",
)
replace_once(
    preflight,
    '        "mcp_command_files": _command_file_identities(mcp_command),\n',
    '        "mcp_command_files": _command_file_identities(\n            mcp_command, relative_to=Path.cwd()\n        ),\n',
)

runner = "tools/repobrief_agent_benchmark_codex_runner.py"
replace_once(
    runner,
    '    projection = _preflight_request_projection(request)\n    if (\n        not isinstance(treatment, dict)\n        or treatment.get("request_id") != request.get("request_id")\n        or treatment.get("sha256") != base._sha256_json(projection)\n    ):\n',
    '    if (\n        not isinstance(treatment, dict)\n        or treatment.get("request_id") != request.get("request_id")\n        or treatment.get("sha256") != base._sha256_json(request)\n    ):\n',
)
replace_once(
    runner,
    '    executable_binding = _bind_mcp_file(executable, label="MCP executable", executable=True)\n    argv = [str(executable), *upstream[1:]]\n    bindings = [executable_binding]\n    if len(argv) > 1 and Path(executable).name.startswith("python"):\n        script = Path(argv[1])\n        if not script.is_absolute():\n            script = Path.cwd() / script\n        try:\n            script = script.resolve(strict=True)\n        except OSError as exc:\n            raise RunnerError("MCP script is unavailable") from exc\n        script_binding = _bind_mcp_file(script, label="MCP script", executable=False)\n        argv[1] = str(script)\n        bindings.append(script_binding)\n    expected = _normalized_authorized_mcp_files(list(authorized_files))\n',
    '    executable_binding = _bind_mcp_file(executable, label="MCP executable", executable=True)\n    expected = _normalized_authorized_mcp_files(list(authorized_files))\n    argv = [str(executable), *upstream[1:]]\n    bindings = [executable_binding]\n    if len(argv) > 1 and Path(executable).name.startswith("python"):\n        script = Path(argv[1]).expanduser()\n        if not script.is_absolute():\n            if len(expected) < 2:\n                raise RunnerError("relative MCP script lacks a preflight-authorized file identity")\n            authorized_script = Path(expected[1]["path"])\n            relative_parts = script.parts\n            if (\n                not relative_parts\n                or ".." in relative_parts\n                or tuple(authorized_script.parts[-len(relative_parts):]) != relative_parts\n            ):\n                raise RunnerError("relative MCP script does not match preflight-authorized path")\n            script = authorized_script\n        try:\n            script = script.resolve(strict=True)\n        except OSError as exc:\n            raise RunnerError("MCP script is unavailable") from exc\n        script_binding = _bind_mcp_file(script, label="MCP script", executable=False)\n        argv[1] = str(script)\n        bindings.append(script_binding)\n',
)
replace_once(
    runner,
    '                if message.get("jsonrpc") != "2.0":\n                    raise RunnerError("MCP client JSON-RPC version is invalid")\n                method = message.get("method")\n',
    '                if message.get("jsonrpc") != "2.0":\n                    raise RunnerError("MCP client JSON-RPC version is invalid")\n                if "params" in message and not isinstance(message.get("params"), (dict, list)):\n                    raise RunnerError("MCP client JSON-RPC params are invalid")\n                method = message.get("method")\n',
)

codex_tests = "tests/test_repobrief_agent_benchmark_codex_runner.py"
replace_once(
    codex_tests,
    '                "sha256": runner.base._sha256_json(\n                    runner._preflight_request_projection(value)\n                ),\n',
    '                "sha256": runner.base._sha256_json(value),\n',
)
codex_extra = r'''
    def test_preflight_authorization_rejects_legacy_projected_request_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "server.py"
            script.write_text("pass\n", encoding="utf-8")
            manifest = root / "chosen.bundle.manifest.json"
            manifest.write_text("{}\n", encoding="utf-8")
            value = request(condition="treatment")
            value["repobrief"]["manifest"] = str(manifest)
            value["repobrief"]["manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
            value["repobrief"]["mcp_command"] = [str(Path(sys.executable).resolve()), str(script), "--bundle-root", str(root)]
            authorized = [file_identity(Path(sys.executable)), file_identity(script)]
            state_root = write_dispatch_authorization(root, value, authorized)
            authorization_path = next((state_root / "preflight-dispatch-ledger").glob("*/authorization.json"))
            authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
            authorization["binding"]["requests"]["treatment"]["sha256"] = runner.base._sha256_json(
                runner._preflight_request_projection(value)
            )
            authorization["contract_sha256"] = runner.base._sha256_json(authorization["binding"])
            authorization_path.write_text(json.dumps(authorization, sort_keys=True), encoding="utf-8")
            authorization_path.chmod(0o600)
            with self.assertRaisesRegex(runner.RunnerError, "treatment request"):
                runner._load_preflight_mcp_authorization(value, state_root)

    def test_relative_mcp_script_uses_preflight_authorized_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "python3"
            executable.write_bytes(Path(sys.executable).read_bytes())
            executable.chmod(0o755)
            script = root / "server.py"
            script.write_text("pass\n", encoding="utf-8")
            manifest = root / "chosen.bundle.manifest.json"
            manifest.write_text("{}\n", encoding="utf-8")
            authorized = [file_identity(executable), file_identity(script)]
            with patch.object(runner.Path, "cwd", side_effect=AssertionError("runtime cwd must not resolve an authorized relative script")):
                argv, bindings = runner._bind_mcp_upstream(
                    [str(executable), "server.py", "--bundle-root", str(root)],
                    manifest,
                    authorized,
                )
            self.assertEqual(argv[1], str(script.resolve()))
            self.assertEqual(bindings[1]["path"], script.resolve())

    def test_mcp_proxy_rejects_invalid_client_params_before_forwarding(self) -> None:
        for params in (None, 1, "invalid", True):
            with self.subTest(params=params), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                marker = root / "forwarded"
                upstream = root / "mcp.py"
                upstream.write_text(
                    "import pathlib, sys\n"
                    f"marker = pathlib.Path({str(marker)!r})\n"
                    "line = sys.stdin.readline()\n"
                    "if line:\n"
                    "    marker.write_text(line, encoding='utf-8')\n",
                    encoding="utf-8",
                )
                message = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": params}
                completed = subprocess.run(
                    proxy_command(upstream, root),
                    input=json.dumps(message).encode() + b"\n",
                    capture_output=True,
                    check=False,
                    timeout=5,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"benchmark MCP proxy stream failed", completed.stderr)
                self.assertFalse(marker.exists())

'''
replace_once(
    codex_tests,
    '\n\n\nif __name__ == "__main__":\n    unittest.main()\n',
    '\n' + codex_extra + '\nif __name__ == "__main__":\n    unittest.main()\n',
)

preflight_tests = "tests/test_repobrief_agent_benchmark_preflight.py"
preflight_extra = r'''

class McpCommandFileIdentityTests(unittest.TestCase):
    def test_mcp_relative_script_is_authorized_against_explicit_preflight_base(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "server.py"
            script.write_text("pass\n", encoding="utf-8")
            executable = Path(sys.executable).resolve()
            identities = support.preflight._core._command_file_identities(
                [str(executable), "server.py"], relative_to=root
            )
            self.assertEqual(
                [item["path"] for item in identities],
                [str(executable), str(script.resolve())],
            )
            legacy = support.preflight._core._command_file_identities(
                [str(executable), "server.py"]
            )
            self.assertEqual([item["path"] for item in legacy], [str(executable)])
'''
replace_once(
    preflight_tests,
    '\n\nif __name__ == "__main__":\n    unittest.main()\n',
    preflight_extra + '\n\nif __name__ == "__main__":\n    unittest.main()\n',
)

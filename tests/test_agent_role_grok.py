from __future__ import annotations

import errno
import hashlib
from concurrent.futures import ThreadPoolExecutor
import threading
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_agent_role as role
from grabowski_agent_sandbox import PreparedSandboxCommand


def stream_bytes(events: list[dict]) -> bytes:
    return ("\n".join(json.dumps(event, separators=(",", ":")) for event in events) + "\n").encode()


class GrokReviewRoleTests(unittest.TestCase):

    def test_create_only_receipt_is_private_and_cannot_be_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "receipts"
            parent.mkdir(mode=0o700)
            path = parent / "attempt.json"
            role.write_receipt(path, {"verdict": "PASS"}, create_only=True)
            original = path.read_bytes()
            self.assertEqual(json.loads(original), {"verdict": "PASS"})
            self.assertEqual(os.stat(path).st_nlink, 1)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(FileExistsError, "already exists"):
                role.write_receipt(path, {"verdict": "NEEDS_CHANGE"}, create_only=True)
            self.assertEqual(path.read_bytes(), original)
            os.chmod(parent, 0o750)
            with self.assertRaises(PermissionError):
                role.write_receipt(parent / "other.json", {}, create_only=True)

    def test_fdopen_failure_closes_raw_descriptor_and_removes_temp(self) -> None:
        # A failure to wrap an already opened fd must not exhaust a long-lived
        # reviewer/operator process. Both legacy replace and create-only paths
        # have the same pre-ownership constructor boundary.
        for create_only in (False, True):
            with self.subTest(create_only=create_only):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    target = root / "attempt.json"
                    real_open = os.open
                    opened_temporary: list[int] = []

                    def capture_open(name, flags, *args, **kwargs):
                        fd = real_open(name, flags, *args, **kwargs)
                        if (
                            isinstance(name, str)
                            and name.startswith(".attempt.json.")
                            and name.endswith(".tmp")
                        ):
                            opened_temporary.append(fd)
                        return fd

                    with (
                        mock.patch.object(role.os, "open", side_effect=capture_open),
                        mock.patch.object(
                            role.os, "fdopen",
                            side_effect=OSError(errno.EMFILE, "synthetic fdopen failure"),
                        ),
                        self.assertRaisesRegex(OSError, "synthetic fdopen failure"),
                    ):
                        role.write_receipt(
                            target, {"verdict": "PASS"}, create_only=create_only
                        )

                    self.assertEqual(len(opened_temporary), 1)
                    with self.assertRaises(OSError) as closed:
                        os.fstat(opened_temporary[0])
                    self.assertEqual(closed.exception.errno, errno.EBADF)
                    self.assertFalse(target.exists())
                    self.assertEqual(list(root.glob("*.tmp")), [])
                    self.assertFalse(
                        any(p.name.startswith(".attempt.json.") for p in root.iterdir())
                    )

    def test_create_only_receipt_rejects_link_attacks(self) -> None:
        for kind in ("symlink", "hardlink", "parent-symlink"):
            with self.subTest(kind=kind):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    parent = root / "receipts"
                    parent.mkdir(mode=0o700)
                    target = root / "real.json"
                    target.write_text('{"untouched": true}', encoding="utf-8")
                    os.chmod(target, 0o600)
                    path = parent / "attempt.json"
                    if kind == "parent-symlink":
                        alias = root / "link"
                        alias.symlink_to(parent, target_is_directory=True)
                        path = alias / "attempt.json"
                        with self.assertRaises(OSError):
                            role.write_receipt(path, {}, create_only=True)
                    else:
                        if kind == "symlink":
                            path.symlink_to(target)
                        else:
                            os.link(target, path)
                        with self.assertRaises(PermissionError):
                            role.write_receipt(path, {}, create_only=True)
                    self.assertEqual(json.loads(target.read_text()), {"untouched": True})

    def test_create_only_receipt_race_has_exactly_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "review.json"
            barrier = threading.Barrier(2)
            def write(value: int) -> str:
                barrier.wait()
                try:
                    role.write_receipt(path, {"attempt": value}, create_only=True)
                    return "created"
                except FileExistsError:
                    return "exists"
            with ThreadPoolExecutor(max_workers=2) as pool:
                a = pool.submit(write, 1)
                b = pool.submit(write, 2)
                self.assertEqual(sorted([a.result(), b.result()]), ["created", "exists"])
            self.assertIn(json.loads(path.read_text())["attempt"], (1, 2))
            self.assertFalse(any(p.name.endswith(".tmp") for p in path.parent.iterdir()))


    def test_role_main_binds_review_receipt_to_job_unit_and_origin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            unit = "grabowski-job-a11111111111"
            directory = Path(temporary) / unit
            directory.mkdir(mode=0o700)
            output = directory / role.REVIEW_ATTEMPT_RECEIPT_NAME
            head, base, diff = "a" * 40, "b" * 40, "c" * 64
            document = b'{"verdict":"PASS","findings":[]}'
            completed = SimpleNamespace(
                returncode=0, stdout_sha256=hashlib.sha256(document).hexdigest(),
                stderr_sha256="e" * 64, stdout_bytes=len(document), stderr_bytes=0,
                stdout_tail="", stderr_tail="", output_limit_exceeded=False,
                stdout_content_exceeded=False, stdout_content=document,
            )
            environment = {
                "GRABOWSKI_REVIEW_ATTEMPT_UNIT": unit,
                "GRABOWSKI_JOB_UNIT": unit,
                "GRABOWSKI_JOB_ID": "a11111111111",
                "GRABOWSKI_JOB_ORIGIN_SHA256": "d" * 64,
                "GRABOWSKI_JOB_DIRECTORY": str(directory),
            }
            with (
                mock.patch.dict(os.environ, environment),
                mock.patch.object(role, "current_binding", side_effect=[(head, diff, False)] * 2),
                mock.patch.object(role, "committed_diff", return_value=b"frozen diff"),
                mock.patch.object(role, "_review_sandbox_argv", return_value=(["sandbox"], None, None)),
                mock.patch.object(role, "runtime_sandbox_argv", return_value=["runtime"]),
                mock.patch.object(role, "run_bounded_capture", return_value=completed),
                mock.patch.object(role, "classify_result", return_value="passed"),
            ):
                self.assertEqual(role.main([
                    "--role", "review", "--repository", str(ROOT),
                    "--expected-head", head, "--expected-base-head", base,
                    "--expected-diff-sha256", diff, "--expected-dirty", "false",
                    "--output", str(output), "--", "grok", "--model", "grok-4.6",
                    "Review the frozen diff",
                ]), 0)
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(receipt["review_attempt_unit"], unit)
            self.assertEqual(receipt["review_attempt_origin_sha256"], "d" * 64)
            self.assertEqual(receipt["receipt_sha256"], role.digest({
                k: v for k, v in receipt.items() if k != "receipt_sha256"
            }))

    def test_role_main_rejects_cross_attempt_environment_before_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            unit = "grabowski-job-a11111111111"
            directory = Path(temporary) / unit
            directory.mkdir(mode=0o700)
            output = directory / role.REVIEW_ATTEMPT_RECEIPT_NAME
            head, base, diff = "a" * 40, "b" * 40, "c" * 64
            completed = SimpleNamespace(
                returncode=0, stdout_sha256="d" * 64, stderr_sha256="e" * 64,
                stdout_bytes=0, stderr_bytes=0, stdout_tail="", stderr_tail="",
                output_limit_exceeded=False, stdout_content_exceeded=False,
                stdout_content=b'{"verdict":"PASS","findings":[]}',
            )
            environment = {
                "GRABOWSKI_REVIEW_ATTEMPT_UNIT": unit,
                "GRABOWSKI_JOB_UNIT": "grabowski-job-b22222222222",
                "GRABOWSKI_JOB_ID": "a11111111111",
                "GRABOWSKI_JOB_ORIGIN_SHA256": "d" * 64,
                "GRABOWSKI_JOB_DIRECTORY": str(directory),
            }
            with (
                mock.patch.dict(os.environ, environment),
                mock.patch.object(role, "current_binding", side_effect=AssertionError("snapshot must not execute")) as current_binding,
                mock.patch.object(role, "committed_diff", return_value=b"frozen diff"),
                mock.patch.object(role, "_review_sandbox_argv", return_value=(["sandbox"], None, None)),
                mock.patch.object(role, "runtime_sandbox_argv", return_value=["runtime"]),
                mock.patch.object(role, "run_bounded_capture", side_effect=AssertionError("reviewer must not execute")) as execute,
                mock.patch.object(role, "classify_result", return_value="passed"),
                self.assertRaisesRegex(RuntimeError, "attempt binding is invalid"),
            ):
                role.main([
                    "--role", "review", "--repository", str(ROOT),
                    "--expected-head", head, "--expected-base-head", base,
                    "--expected-diff-sha256", diff, "--expected-dirty", "false",
                    "--output", str(output), "--", "grok", "--model", "grok-4.6",
                    "Review the frozen diff",
                ])
            current_binding.assert_not_called()
            execute.assert_not_called()
            self.assertFalse(output.exists())

    def test_streaming_review_command_embeds_bound_diff_without_repository_tools(self) -> None:
        prepared = ("/opt/grabowski-external/grok", "--model", "grok-4.6", "-p", "review this")
        head = "a" * 40
        base = "b" * 40
        review_diff = b"diff --git a/a.py b/a.py\n+safe = True\n"
        actual, prompt_bytes = role._grok_streaming_review_command(
            prepared, expected_head=head, expected_base_head=base, review_diff=review_diff
        )
        self.assertEqual(actual[actual.index("--tools") + 1], "todo_write")
        self.assertEqual(
            actual[actual.index("--disallowed-tools") + 1],
            "todo_write,search_tool,use_tool,run_terminal_cmd,run_terminal_command",
        )
        self.assertNotIn("--allow", actual)
        self.assertNotIn("--deny", actual)
        self.assertNotIn("-p", actual)
        self.assertIn("--verbatim", actual)
        self.assertEqual(actual[actual.index("--sandbox") + 1], "read-only")
        self.assertEqual(actual[actual.index("--prompt-file") + 1], "/dev/stdin")
        prompt = prompt_bytes.decode("utf-8")
        self.assertIn(base, prompt)
        self.assertIn(head, prompt)
        self.assertIn(hashlib.sha256(review_diff).hexdigest(), prompt)
        self.assertIn(review_diff.decode(), prompt)
        self.assertIn("Do not use any tool", prompt)


    def test_streaming_review_large_diff_stays_out_of_argv(self) -> None:
        prepared = ("/opt/grabowski-external/grok", "--model", "grok-4.6", "-p", "review this")
        review_diff = b"x" * 247_109
        actual, prompt_bytes = role._grok_streaming_review_command(
            prepared,
            expected_head="a" * 40,
            expected_base_head="b" * 40,
            review_diff=review_diff,
        )
        self.assertLess(max(len(item.encode("utf-8")) for item in actual), 4096)
        self.assertGreater(len(prompt_bytes), len(review_diff))
        self.assertIn("--verbatim", actual)
        self.assertEqual(actual[actual.index("--prompt-file") + 1], "/dev/stdin")

    def test_streaming_review_command_rejects_oversized_or_non_utf8_diff(self) -> None:
        prepared = ("/opt/grabowski-external/grok", "--model", "grok-4.6", "-p", "review this")
        kwargs = {"expected_head": "a" * 40, "expected_base_head": "b" * 40}
        with self.assertRaisesRegex(RuntimeError, "exceeds"):
            role._grok_streaming_review_command(
                prepared, review_diff=b"x" * (role.MAX_GROK_REVIEW_INPUT_BYTES + 1), **kwargs
            )
        with self.assertRaisesRegex(RuntimeError, "UTF-8"):
            role._grok_streaming_review_command(prepared, review_diff=b"\xff", **kwargs)

    def test_bound_review_input_artifact_is_private_hash_bound_and_size_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace_root = root / "gaw-a2345678"
            workspace_root.mkdir(mode=0o700)
            patch_path = workspace_root / "writer.patch"
            patch_bytes = b"diff --git a/src/app.py b/src/app.py\n+dirty = True\n"
            patch_path.write_bytes(patch_bytes)
            os.chmod(patch_path, 0o600)
            patch_sha256 = hashlib.sha256(patch_bytes).hexdigest()
            self.assertEqual(
                role.read_bound_review_input_artifact(
                    str(root), str(patch_path), patch_sha256
                ),
                patch_bytes,
            )
            with self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"):
                role.read_bound_review_input_artifact(
                    str(root), str(patch_path), "0" * 64
                )
            with self.assertRaisesRegex(RuntimeError, "outside the canonical workspace root"):
                role.read_bound_review_input_artifact(
                    str(root / "other-root"), str(patch_path), patch_sha256
                )
            patch_path.write_bytes(b"x" * (role.MAX_GROK_REVIEW_INPUT_BYTES + 1))
            os.chmod(patch_path, 0o600)
            with self.assertRaisesRegex(RuntimeError, "safety boundary"):
                role.read_bound_review_input_artifact(
                    str(root),
                    str(patch_path),
                    hashlib.sha256(patch_path.read_bytes()).hexdigest(),
                )

    def test_bound_review_input_artifact_requires_private_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace_root = root / "gaw-a2345678"
            workspace_root.mkdir(mode=0o700)
            patch_path = workspace_root / "writer.patch"
            patch_bytes = b"diff --git a/src/app.py b/src/app.py\n+dirty = True\n"
            patch_path.write_bytes(patch_bytes)
            os.chmod(patch_path, 0o600)
            os.chmod(root, 0o750)
            with self.assertRaisesRegex(RuntimeError, "workspace root"):
                role.read_bound_review_input_artifact(
                    str(root), str(patch_path), hashlib.sha256(patch_bytes).hexdigest()
                )

    def test_bound_review_input_artifact_rejects_wrong_owner_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace_root = root / "gaw-a2345678"
            workspace_root.mkdir(mode=0o700)
            patch_path = workspace_root / "writer.patch"
            patch_bytes = b"diff --git a/src/app.py b/src/app.py\n+dirty = True\n"
            patch_path.write_bytes(patch_bytes)
            os.chmod(patch_path, 0o600)
            expected_uid = os.getuid() + 1
            with mock.patch.object(role.os, "getuid", return_value=expected_uid):
                with self.assertRaisesRegex(RuntimeError, "workspace root"):
                    role.read_bound_review_input_artifact(
                        str(root), str(patch_path), hashlib.sha256(patch_bytes).hexdigest()
                    )

    def test_bound_review_input_artifact_requires_private_workspace_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace_root = root / "gaw-a2345678"
            workspace_root.mkdir(mode=0o700)
            patch_path = workspace_root / "writer.patch"
            patch_bytes = b"diff --git a/src/app.py b/src/app.py\n+dirty = True\n"
            patch_path.write_bytes(patch_bytes)
            os.chmod(patch_path, 0o600)
            os.chmod(workspace_root, 0o750)
            with self.assertRaisesRegex(RuntimeError, "canonical private workspace patch"):
                role.read_bound_review_input_artifact(
                    str(root), str(patch_path), hashlib.sha256(patch_bytes).hexdigest()
                )

    def test_bound_review_input_artifact_rejects_static_workspace_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real_workspace = root / "gaw-b2345678"
            real_workspace.mkdir(mode=0o700)
            real_patch = real_workspace / "writer.patch"
            patch_bytes = b"diff --git a/src/app.py b/src/app.py\n+dirty = True\n"
            real_patch.write_bytes(patch_bytes)
            os.chmod(real_patch, 0o600)
            linked_workspace = root / "gaw-a2345678"
            linked_workspace.symlink_to(real_workspace, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "could not be read safely"):
                role.read_bound_review_input_artifact(
                    str(root),
                    str(linked_workspace / "writer.patch"),
                    hashlib.sha256(patch_bytes).hexdigest(),
                )

    def test_bound_review_input_artifact_rejects_patch_symlink_and_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace_root = root / "gaw-a2345678"
            workspace_root.mkdir(mode=0o700)
            patch_bytes = b"diff --git a/src/app.py b/src/app.py\n+dirty = True\n"
            patch_sha256 = hashlib.sha256(patch_bytes).hexdigest()

            symlink_target = workspace_root / "writer-round-0002.patch"
            symlink_target.write_bytes(patch_bytes)
            os.chmod(symlink_target, 0o600)
            patch_path = workspace_root / "writer.patch"
            patch_path.symlink_to(symlink_target.name)
            with self.assertRaisesRegex(RuntimeError, "could not be read safely"):
                role.read_bound_review_input_artifact(
                    str(root), str(patch_path), patch_sha256
                )

            patch_path.unlink()
            hardlink_source = root / "hardlink-source.patch"
            hardlink_source.write_bytes(patch_bytes)
            os.chmod(hardlink_source, 0o600)
            os.link(hardlink_source, patch_path)
            with self.assertRaisesRegex(RuntimeError, "safety boundary"):
                role.read_bound_review_input_artifact(
                    str(root), str(patch_path), patch_sha256
                )

    def test_bound_review_input_artifact_rejects_exact_one_mib(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace_root = root / "gaw-a2345678"
            workspace_root.mkdir(mode=0o700)
            patch_path = workspace_root / "writer.patch"
            patch_bytes = b"x" * role.MAX_GROK_REVIEW_INPUT_BYTES
            patch_path.write_bytes(patch_bytes)
            os.chmod(patch_path, 0o600)
            with self.assertRaisesRegex(RuntimeError, "safety boundary"):
                role.read_bound_review_input_artifact(
                    str(root), str(patch_path), hashlib.sha256(patch_bytes).hexdigest()
                )

    def test_bound_review_input_artifact_rejects_patch_change_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace_root = root / "gaw-a2345678"
            workspace_root.mkdir(mode=0o700)
            patch_path = workspace_root / "writer.patch"
            patch_bytes = b"diff --git a/src/app.py b/src/app.py\n+dirty = True\n"
            patch_path.write_bytes(patch_bytes)
            os.chmod(patch_path, 0o600)
            patch_sha256 = hashlib.sha256(patch_bytes).hexdigest()
            real_read = os.read
            changed = False

            def racing_read(descriptor, count):
                nonlocal changed
                chunk = real_read(descriptor, count)
                if chunk and not changed:
                    patch_path.write_bytes(patch_bytes + b"# changed\n")
                    os.chmod(patch_path, 0o600)
                    changed = True
                return chunk

            with mock.patch.object(role.os, "read", side_effect=racing_read):
                with self.assertRaisesRegex(RuntimeError, "changed while being read"):
                    role.read_bound_review_input_artifact(
                        str(root), str(patch_path), patch_sha256
                    )
            self.assertTrue(changed)

    def test_bound_review_input_artifact_rejects_intermediate_symlink_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as outside_temporary:
            root = Path(temporary)
            workspace_root = root / "gaw-a2345678"
            workspace_root.mkdir(mode=0o700)
            patch_path = workspace_root / "writer.patch"
            patch_bytes = b"diff --git a/src/app.py b/src/app.py\n+dirty = True\n"
            patch_path.write_bytes(patch_bytes)
            os.chmod(patch_path, 0o600)
            outside = Path(outside_temporary)
            outside_patch = outside / "writer.patch"
            outside_patch.write_bytes(patch_bytes)
            os.chmod(outside_patch, 0o600)
            patch_sha256 = hashlib.sha256(patch_bytes).hexdigest()
            real_open = os.open
            swapped = False

            def racing_open(path_value, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                fd = real_open(path_value, flags, mode, dir_fd=dir_fd)
                if not swapped and dir_fd is None and Path(path_value) == root.resolve():
                    preserved = root / "preserved-workspace"
                    workspace_root.rename(preserved)
                    workspace_root.symlink_to(outside, target_is_directory=True)
                    swapped = True
                return fd

            with mock.patch.object(role.os, "open", side_effect=racing_open):
                with self.assertRaisesRegex(RuntimeError, "could not be read safely"):
                    role.read_bound_review_input_artifact(
                        str(root), str(patch_path), patch_sha256
                    )
            self.assertTrue(swapped)

    def test_dirty_grok_review_uses_frozen_patch_instead_of_committed_diff(self) -> None:
        head = "a" * 40
        base = "b" * 40
        diff = "c" * 64
        patch_bytes = b"diff --git a/src/app.py b/src/app.py\n+dirty = True\n"
        completed = SimpleNamespace(
            returncode=0,
            stdout_sha256=hashlib.sha256(b'{"verdict":"PASS","findings":[]}').hexdigest(),
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            stdout_bytes=len(b'{"verdict":"PASS","findings":[]}'),
            stderr_bytes=0,
            stdout_tail="",
            stderr_tail="",
            output_limit_exceeded=False,
            stdout_content_exceeded=False,
            stdout_content=b'{"verdict":"PASS","findings":[]}',
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace_root = root / "gaw-b2345678"
            workspace_root.mkdir(mode=0o700)
            patch_path = workspace_root / "writer.patch"
            patch_path.write_bytes(patch_bytes)
            os.chmod(patch_path, 0o600)
            patch_sha256 = hashlib.sha256(patch_bytes).hexdigest()
            with (
                mock.patch.object(
                    role, "current_binding",
                    side_effect=[(head, diff, True), (head, diff, True)],
                ),
                mock.patch.object(role, "committed_diff") as committed_diff,
                mock.patch.object(
                    role, "_review_sandbox_argv",
                    return_value=(["sandbox"], None, b"prompt"),
                ) as review_sandbox,
                mock.patch.object(role, "runtime_sandbox_argv", return_value=["runtime"]),
                mock.patch.object(role, "run_bounded_capture", return_value=completed),
                mock.patch.object(role, "write_receipt") as write_receipt,
            ):
                returncode = role.main(
                    [
                        "--role", "review",
                        "--repository", str(ROOT),
                        "--expected-head", head,
                        "--expected-base-head", base,
                        "--expected-diff-sha256", diff,
                        "--expected-dirty", "true",
                        "--review-input-root", str(root),
                        "--review-input-path", str(patch_path),
                        "--review-input-sha256", patch_sha256,
                        "--output", "/tmp/grok-dirty-review-receipt.json",
                        "--", "grok", "--model", "grok-4.6", "review this",
                    ]
                )

        self.assertEqual(returncode, 0)
        committed_diff.assert_not_called()
        self.assertEqual(review_sandbox.call_args.kwargs["review_diff"], patch_bytes)
        payload = write_receipt.call_args.args[1]
        self.assertEqual(payload["review_input_source"], "frozen_writer_patch")
        self.assertEqual(payload["review_input_sha256"], hashlib.sha256(patch_bytes).hexdigest())

    def test_dirty_grok_review_without_frozen_patch_fails_closed(self) -> None:
        head = "a" * 40
        base = "b" * 40
        diff = "c" * 64
        with (
            mock.patch.object(role, "current_binding", return_value=(head, diff, True)),
            mock.patch.object(role, "committed_diff") as committed_diff,
            self.assertRaisesRegex(RuntimeError, "requires the frozen writer patch"),
        ):
            role.main(
                [
                    "--role", "review",
                    "--repository", str(ROOT),
                    "--expected-head", head,
                    "--expected-base-head", base,
                    "--expected-diff-sha256", diff,
                    "--expected-dirty", "true",
                    "--output", "/tmp/grok-missing-dirty-review-receipt.json",
                    "--", "grok", "--model", "grok-4.6", "review this",
                ]
            )
        committed_diff.assert_not_called()

    def test_streaming_review_command_rejects_caller_owned_execution_framing(self) -> None:
        controlled = (
            "--always-approve", "--yolo", "--dangerously-skip-permissions",
            "--permission-mode", "--allow", "--deny", "--sandbox", "--tools",
            "--disallowed-tools", "--output-format", "--max-turns", "--json-schema",
            "--verbatim", "--prompt-file",
        )
        for option in controlled:
            for item in ((option, "value"), (f"{option}=value",)):
                with self.subTest(option=option, item=item):
                    prepared = ("/opt/grabowski-external/grok", *item, "-p", "review this")
                    with self.assertRaisesRegex(RuntimeError, "controlled by Grabowski"):
                        role._grok_streaming_review_command(
                            prepared, expected_head="a" * 40, expected_base_head="b" * 40, review_diff=b"diff"
                        )

    def test_claude_review_sandbox_binds_frozen_diff_stdin_headlessly(self) -> None:
        repo = Path("/tmp/claude-review-worktree")
        declared = [
            "claude", "--model", "claude-opus-5-5", "--effort", "high",
            "--permission-mode", "plan", "Review exact committed change",
        ]
        prepared = PreparedSandboxCommand(
            command=("/opt/grabowski-external/claude", *declared[1:]),
        )
        raw_diff = b"diff --git a/a.py b/a.py\n+interesting_but_untrusted\n"
        with (
            mock.patch.object(role, "prepare_external_agent_command",
                              return_value=prepared) as prepare,
            mock.patch.object(role, "sandbox_argv",
                              return_value=["read-only-sandbox"]) as sandbox,
        ):
            argv, contract, stdin = role._review_sandbox_argv(
                repo, declared, expected_head="a" * 40,
                expected_base_head="b" * 40, review_diff=raw_diff,
            )
        self.assertEqual(["read-only-sandbox"], argv)
        self.assertEqual(role.CLAUDE_REVIEW_JSON_CONTRACT, contract)
        self.assertIsInstance(stdin, bytes)
        self.assertIn(b"interesting_but_untrusted", stdin)
        self.assertIn(b"a" * 40, stdin)
        self.assertIn(b"b" * 40, stdin)
        self.assertIn(hashlib.sha256(raw_diff).hexdigest().encode(), stdin)
        self.assertIn(b"do not use any tool", stdin.lower())
        prepare.assert_called_once_with(declared)
        self.assertEqual(declared, sandbox.call_args.kwargs["declared_command"])
        actual = sandbox.call_args.args[1]
        self.assertEqual("/opt/grabowski-external/claude", actual[0])
        self.assertIn("-p", actual)
        self.assertEqual(1, actual.count("-p"))
        self.assertEqual("1", actual[actual.index("--max-turns") + 1])
        self.assertIn("exact", actual[-1].lower())
        self.assertIn("stdin", actual[-1].lower())
        self.assertNotEqual(declared[-1], actual[-1])
        self.assertEqual("json", actual[actual.index("--output-format") + 1])
        self.assertEqual("plan", actual[actual.index("--permission-mode") + 1])
        schema = json.loads(actual[actual.index("--json-schema") + 1])
        self.assertEqual(["PASS", "NEEDS_CHANGE", "BLOCK"],
                         schema["properties"]["verdict"]["enum"])
        self.assertEqual(["verdict", "findings"], schema["required"])
        for flag in ("--tools=", "--no-session-persistence", "--safe-mode"):
            self.assertIn(flag, actual)
        self.assertEqual("*", actual[actual.index("--disallowedTools") + 1])
        self.assertNotIn("Review exact committed change", actual)
        self.assertNotIn("interesting_but_untrusted", " ".join(actual))

    def test_claude_fable_review_route_accepts_registered_cli_shape(self) -> None:
        repo = Path("/tmp/claude-review-worktree")
        declared = [
            "claude", "-p", "--safe-mode", "--permission-mode", "plan",
            "--model", "claude-fable-5", "--effort", "high",
            "Review only the exact current revision",
        ]
        prepared = PreparedSandboxCommand(
            command=("/opt/grabowski-external/claude", *declared[1:]),
        )
        frozen = b"diff --git a/a.py b/a.py\n+safe only\n"
        with (
            mock.patch.object(role, "prepare_external_agent_command",
                              return_value=prepared) as prepare,
            mock.patch.object(role, "sandbox_argv",
                              return_value=["read-only-sandbox"]) as sandbox,
        ):
            argv, contract, stdin = role._review_sandbox_argv(
                repo, declared, expected_head="a" * 40,
                expected_base_head="b" * 40, review_diff=frozen,
            )
        self.assertEqual(["read-only-sandbox"], argv)
        self.assertEqual(role.CLAUDE_REVIEW_JSON_CONTRACT, contract)
        self.assertIn(frozen, stdin)
        prepare.assert_called_once_with(declared)
        actual = sandbox.call_args.args[1]
        self.assertEqual(declared, sandbox.call_args.kwargs["declared_command"])
        self.assertEqual(1, actual.count("-p"))
        self.assertEqual(1, actual.count("--safe-mode"))
        self.assertEqual("claude-fable-5", actual[actual.index("--model") + 1])
        self.assertEqual("high", actual[actual.index("--effort") + 1])
        self.assertEqual("plan", actual[actual.index("--permission-mode") + 1])
        self.assertEqual("1", actual[actual.index("--max-turns") + 1])
        self.assertIn("stdin", actual[-1].lower())
        self.assertNotIn("safe only", " ".join(actual))
        self.assertEqual("*", actual[actual.index("--disallowedTools") + 1])

    def test_claude_review_bound_input_rejects_unsafe_or_oversized_diff(self) -> None:
        command = (
            "/opt/grabowski-external/claude", "--model", "claude-opus-5-5",
            "--effort", "high", "--permission-mode", "plan",
            "Review only the exact diff",
        )
        for content, reason in (
            (b"\xff", "UTF-8"),
            (b"x" * (role.MAX_CLAUDE_REVIEW_INPUT_BYTES + 1), "exceeds"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(RuntimeError, reason):
                    role._claude_json_review_command(
                        command, expected_head="a" * 40,
                        expected_base_head="b" * 40, review_diff=content,
                    )

    def test_claude_result_requires_successful_typed_envelope(self) -> None:
        clean = {
            "type": "result", "subtype": "success", "is_error": False,
            "structured_output": {"verdict": "PASS", "findings": []},
        }
        review, error, metadata = role._extract_claude_review_document(
            json.dumps(clean).encode()
        )
        self.assertIsNone(error)
        self.assertEqual({"verdict": "PASS", "findings": []}, json.loads(review))
        self.assertEqual(role.CLAUDE_REVIEW_JSON_CONTRACT,
                         metadata["review_provider_contract"])
        for malformed in (
            b"not-json",
            b'{"verdict":"PASS","findings":[]}',
            json.dumps({**clean, "is_error": True}).encode(),
            json.dumps({**clean, "subtype": "error"}).encode(),
            json.dumps({**clean, "structured_output": []}).encode(),
            json.dumps({**clean, "structured_output": {
                "verdict": "PASS", "findings": [], "extra": "forged",
            }}).encode(),
        ):
            with self.subTest(malformed=malformed[:45]):
                document, rejected, _meta = role._extract_claude_review_document(
                    malformed
                )
                self.assertIsNone(document)
                self.assertIsNotNone(rejected)

    def test_claude_structured_findings_revalidated_locally(self) -> None:
        valid_finding = {
            "severity": "P2", "path": "src/role.py", "line": 12,
            "evidence": "Concrete broken trust boundary",
            "impact": "Incorrect irreversible reviewer receipt",
            "minimal_fix": "Validate the exact finding fields before signing",
        }
        envelope = {
            "type": "result", "subtype": "success", "is_error": False,
            "structured_output": {
                "verdict": "NEEDS_CHANGE", "findings": [valid_finding],
            },
        }
        document, error, _meta = role._extract_claude_review_document(
            json.dumps(envelope).encode()
        )
        self.assertIsNone(error)
        self.assertEqual(envelope["structured_output"], json.loads(document))
        mutations = (
            {},
            {**valid_finding, "extra": "forged"},
            {**valid_finding, "severity": "P0"},
            {**valid_finding, "severity": []},
            {**valid_finding, "line": 0},
            {**valid_finding, "line": True},
            {**valid_finding, "line": "12"},
            {**valid_finding, "path": " "},
            {**valid_finding, "evidence": ""},
            {**valid_finding, "impact": " "},
            {**valid_finding, "minimal_fix": ""},
        )
        for invalid in mutations:
            with self.subTest(invalid=invalid):
                payload = {
                    **envelope,
                    "structured_output": {
                        "verdict": "BLOCK", "findings": [invalid],
                    },
                }
                result, failure, _meta = role._extract_claude_review_document(
                    json.dumps(payload).encode()
                )
                self.assertIsNone(result)
                self.assertIsNotNone(failure)
        for payload in (
            {"verdict": "PASS", "findings": [valid_finding]},
            {"verdict": "BLOCK", "findings": []},
            {"verdict": "PENDING", "findings": []},
            {"verdict": [], "findings": []},
            {"verdict": {}, "findings": []},
            {"verdict": "PASS", "findings": {}},
        ):
            with self.subTest(payload=payload):
                result, failure, _meta = role._extract_claude_review_document(
                    json.dumps({
                        **envelope, "structured_output": payload,
                    }).encode()
                )
                self.assertIsNone(result)
                self.assertIsNotNone(failure)

    def test_claude_review_selects_only_the_bound_route(self) -> None:
        # Provider selection grants no authority to pass caller-supplied review text.
        # Dirty Claude still requires the verified frozen-writer artifact.
        source = [
            "claude", "--model", "claude-opus-5-5", "--effort", "high",
            "--permission-mode", "plan", "Please review the current draft",
        ]
        self.assertTrue(role._is_claude_review_route(source))
        self.assertFalse(role._is_claude_review_route(["grok"]))

    def test_dirty_claude_main_uses_same_verified_patch_as_grok(self) -> None:
        head, base, binding = "a" * 40, "b" * 40, "c" * 64
        patch = b"diff --git a/app.py b/app.py\n+frozen writer change\n"
        envelope = json.dumps({
            "type": "result", "subtype": "success", "is_error": False,
            "structured_output": {"verdict": "PASS", "findings": []},
        }).encode()
        completed = SimpleNamespace(
            returncode=0, stdout_sha256=hashlib.sha256(envelope).hexdigest(),
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            stdout_bytes=len(envelope), stderr_bytes=0,
            stdout_tail="", stderr_tail="",
            output_limit_exceeded=False, stdout_content_exceeded=False,
            stdout_content=envelope,
        )
        routes = (
            ("claude", "--model", "claude-opus-5-5", "--effort", "high",
             "--permission-mode", "plan", "Review the frozen change"),
            ("claude", "-p", "--safe-mode", "--permission-mode", "plan",
             "--model", "claude-fable-5", "--effort", "high", "Review the frozen change"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "gaw-b2345678"
            workspace.mkdir(mode=0o700)
            artifact = workspace / "writer.patch"
            artifact.write_bytes(patch)
            os.chmod(artifact, 0o600)
            sha = hashlib.sha256(patch).hexdigest()
            for index, command in enumerate(routes):
                with (
                    self.subTest(command=command),
                    mock.patch.dict(os.environ, {}, clear=True),
                    mock.patch.object(role, "current_binding",
                                      side_effect=[(head, binding, True)] * 2),
                    mock.patch.object(role, "committed_diff") as committed,
                    mock.patch.object(
                        role, "_review_sandbox_argv",
                        return_value=(["sandbox"], role.CLAUDE_REVIEW_JSON_CONTRACT, b"stdin"),
                    ) as sandbox,
                    mock.patch.object(role, "runtime_sandbox_argv", return_value=["runtime"]),
                    mock.patch.object(role, "run_bounded_capture", return_value=completed),
                ):
                    receipt_path = root / f"review-{index}.json"
                    self.assertEqual(role.main([
                        "--role", "review", "--repository", str(ROOT),
                        "--expected-head", head, "--expected-base-head", base,
                        "--expected-diff-sha256", binding,
                        "--expected-dirty", "true",
                        "--review-input-root", str(root),
                        "--review-input-path", str(artifact),
                        "--review-input-sha256", sha,
                        "--output", str(receipt_path), "--", *command,
                    ]), 0)
                    committed.assert_not_called()
                    self.assertEqual(patch, sandbox.call_args.kwargs["review_diff"])
                    self.assertEqual(
                        "frozen_writer_patch", sandbox.call_args.kwargs["review_input_source"]
                    )
                    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                    self.assertEqual("frozen_writer_patch", receipt["review_input_source"])
                    self.assertEqual(sha, receipt["review_input_sha256"])
                    self.assertEqual("PASS", receipt["verdict"])

    def test_dirty_claude_invalid_patch_hash_blocks_before_provider(self) -> None:
        head, base, binding = "a" * 40, "b" * 40, "c" * 64
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "gaw-b2345678"
            workspace.mkdir(mode=0o700)
            artifact = workspace / "writer.patch"
            artifact.write_bytes(b"diff --git a/file b/file\n+safe input\n")
            os.chmod(artifact, 0o600)
            with (
                mock.patch.dict(os.environ, {}, clear=True),
                mock.patch.object(role, "current_binding", return_value=(head, binding, True)),
                mock.patch.object(role, "_review_sandbox_argv") as sandbox,
                mock.patch.object(role, "run_bounded_capture") as execute,
                self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"),
            ):
                role.main([
                    "--role", "review", "--repository", str(ROOT),
                    "--expected-head", head, "--expected-base-head", base,
                    "--expected-diff-sha256", binding, "--expected-dirty", "true",
                    "--review-input-root", str(root),
                    "--review-input-path", str(artifact),
                    "--review-input-sha256", "0" * 64,
                    "--output", str(root / "invalid.json"), "--",
                    "claude", "--model", "claude-opus-5-5",
                    "--effort", "high", "--permission-mode", "plan", "Review this",
                ])
            sandbox.assert_not_called()
            execute.assert_not_called()

    def test_clean_claude_rejects_unexpected_frozen_patch(self) -> None:
        head, base, binding = "a" * 40, "b" * 40, "c" * 64
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(role, "current_binding", return_value=(head, binding, False)),
            mock.patch.object(role, "committed_diff") as committed,
            mock.patch.object(role, "_review_sandbox_argv") as sandbox,
            self.assertRaisesRegex(RuntimeError, "clean Claude review"),
        ):
            role.main([
                "--role", "review", "--repository", str(ROOT),
                "--expected-head", head, "--expected-base-head", base,
                "--expected-diff-sha256", binding, "--expected-dirty", "false",
                "--review-input-root", "/tmp/gaw-root",
                "--review-input-path", "/tmp/gaw-root/gaw-b2345678/writer.patch",
                "--review-input-sha256", "d" * 64,
                "--output", "/tmp/claude-clean-unexpected-artifact.json", "--",
                "claude", "--model", "claude-opus-5-5",
                "--effort", "high", "--permission-mode", "plan", "Review this",
            ])
        committed.assert_not_called()
        sandbox.assert_not_called()

    def test_claude_prompt_identifies_frozen_patch_not_committed_diff(self) -> None:
        declared = (
            "/opt/grabowski-external/claude", "--model", "claude-opus-5-5",
            "--effort", "high", "--permission-mode", "plan", "Review exact input",
        )
        diff = b"diff --git a/f b/f\n+frozen\n"
        actual, prompt = role._claude_json_review_command(
            declared, expected_head="a" * 40, expected_base_head="b" * 40,
            review_diff=diff, review_input_source="frozen_writer_patch",
        )
        self.assertIn(b"verified frozen writer patch", prompt)
        self.assertNotIn(b"committed Git diff", prompt)
        self.assertIn(hashlib.sha256(diff).hexdigest().encode(), prompt)
        self.assertIn(b"frozen", prompt)
        self.assertNotIn("frozen", " ".join(actual))
        self.assertIn("review input", actual[-1].lower())
        self.assertNotIn("git diff", actual[-1].lower())
        with self.assertRaisesRegex(RuntimeError, "source"):
            role._claude_json_review_command(
                declared, expected_head="a" * 40, expected_base_head="b" * 40,
                review_diff=diff, review_input_source="caller_supplied_text",
            )

    def test_claude_main_emits_job_bound_receipt_from_success_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            unit = "grabowski-job-a11111111111"
            directory = Path(temporary) / unit
            directory.mkdir(mode=0o700)
            output = directory / role.REVIEW_ATTEMPT_RECEIPT_NAME
            head, base, workspace = "a" * 40, "b" * 40, "c" * 64
            frozen_diff = b"diff --git a/source b/source\\n+only reviewed bytes\\n"
            prompt = b"exact immutable review input"
            envelope = json.dumps({
                "type": "result", "subtype": "success", "is_error": False,
                "structured_output": {"verdict": "PASS", "findings": []},
            }).encode()
            completed = SimpleNamespace(
                returncode=0,
                stdout_sha256=hashlib.sha256(envelope).hexdigest(),
                stderr_sha256=hashlib.sha256(b"").hexdigest(),
                stdout_bytes=len(envelope), stderr_bytes=0,
                stdout_tail="", stderr_tail="",
                output_limit_exceeded=False, stdout_content_exceeded=False,
                stdout_content=envelope,
            )
            environment = {
                "GRABOWSKI_REVIEW_ATTEMPT_UNIT": unit,
                "GRABOWSKI_JOB_UNIT": unit,
                "GRABOWSKI_JOB_ID": "a11111111111",
                "GRABOWSKI_JOB_ORIGIN_SHA256": "d" * 64,
                "GRABOWSKI_JOB_DIRECTORY": str(directory),
            }
            with (
                mock.patch.dict(os.environ, environment),
                mock.patch.object(
                    role, "current_binding",
                    side_effect=[(head, workspace, False)] * 2,
                ),
                mock.patch.object(
                    role, "committed_diff", return_value=frozen_diff
                ) as committed,
                mock.patch.object(
                    role, "_review_sandbox_argv",
                    return_value=(["sandbox"], role.CLAUDE_REVIEW_JSON_CONTRACT, prompt),
                ),
                mock.patch.object(role, "runtime_sandbox_argv", return_value=["runtime"]),
                mock.patch.object(
                    role, "run_bounded_capture", return_value=completed
                ) as execute,
            ):
                self.assertEqual(role.main([
                    "--role", "review", "--repository", str(ROOT),
                    "--expected-head", head,
                    "--expected-base-head", base,
                    "--expected-diff-sha256", workspace,
                    "--expected-dirty", "false",
                    "--output", str(output), "--",
                    "claude", "--model", "claude-opus-5-5",
                    "--effort", "high", "--permission-mode", "plan",
                    "Review only the exact frozen Git diff",
                ]), 0)
            committed.assert_called_once_with(ROOT, base, head)
            self.assertEqual(prompt, execute.call_args.kwargs["stdin_content"])
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual("PASS", receipt["verdict"])
            self.assertEqual([], receipt["findings"])
            self.assertEqual("passed", receipt["failure_classification"])
            self.assertEqual(unit, receipt["review_attempt_unit"])
            self.assertEqual("d" * 64, receipt["review_attempt_origin_sha256"])
            self.assertEqual("committed_diff", receipt["review_input_source"])
            self.assertEqual(
                hashlib.sha256(frozen_diff).hexdigest(),
                receipt["review_input_sha256"],
            )
            self.assertEqual(
                hashlib.sha256(prompt).hexdigest(),
                receipt["review_prompt_sha256"],
            )
            self.assertEqual(role.CLAUDE_REVIEW_JSON_CONTRACT,
                             receipt["review_provider_contract"])
            self.assertEqual(receipt["receipt_sha256"], role.digest({
                k: v for k, v in receipt.items() if k != "receipt_sha256"
            }))

    def test_claude_main_refuses_dirty_source_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "denied.json"
            head, base, workspace = "a" * 40, "b" * 40, "c" * 64
            with (
                mock.patch.dict(os.environ, {}, clear=True),
                mock.patch.object(
                    role, "current_binding",
                    return_value=(head, workspace, True),
                ),
                mock.patch.object(role, "committed_diff") as frozen,
                mock.patch.object(role, "_review_sandbox_argv") as sandbox,
                mock.patch.object(role, "run_bounded_capture") as execute,
                self.assertRaisesRegex(RuntimeError, "requires the frozen writer patch artifact"),
            ):
                role.main([
                    "--role", "review", "--repository", str(ROOT),
                    "--expected-head", head,
                    "--expected-base-head", base,
                    "--expected-diff-sha256", workspace,
                    "--expected-dirty", "true",
                    "--output", str(output), "--",
                    "claude", "--model", "claude-opus-5-5",
                    "--effort", "high", "--permission-mode", "plan",
                    "Review only the exact frozen Git diff",
                ])
            frozen.assert_not_called()
            sandbox.assert_not_called()
            execute.assert_not_called()
            self.assertFalse(output.exists())

    def test_codex_review_sandbox_inserts_exec_without_changing_declared_command(self) -> None:
        repo = Path("/tmp/repo")
        declared = [
            "codex",
            "--model",
            "gpt-5.6-sol",
            "--sandbox",
            "read-only",
            "--ask-for-approval",
            "never",
            "review this",
        ]
        prepared = PreparedSandboxCommand(
            command=("/usr/bin/python3", "-I", "codex-launcher", "exec", "review this")
        )
        with (
            mock.patch.object(
                role, "prepare_external_agent_command", return_value=prepared
            ) as prepare,
            mock.patch.object(role, "sandbox_argv", return_value=["sandbox"]) as sandbox_argv,
        ):
            argv, contract, prompt_bytes = role._review_sandbox_argv(
                repo,
                declared,
                expected_head="a" * 40,
                expected_base_head="b" * 40,
                review_diff=b"",
            )

        self.assertEqual(argv, ["sandbox"])
        self.assertIsNone(contract)
        self.assertIsNone(prompt_bytes)
        normalized = prepare.call_args.args[0]
        self.assertEqual(normalized[-2:], ["exec", "review this"])
        self.assertEqual(normalized[:-2], declared[:-1])
        self.assertEqual(sandbox_argv.call_args.args[1], list(prepared.command))
        self.assertEqual(sandbox_argv.call_args.kwargs["declared_command"], declared)

    def test_codex_review_sandbox_preserves_existing_exec(self) -> None:
        repo = Path("/tmp/repo")
        declared = [
            "codex",
            "--model",
            "gpt-5.6-sol",
            "--sandbox",
            "read-only",
            "--ask-for-approval",
            "never",
            "exec",
            "review this",
        ]
        prepared = PreparedSandboxCommand(
            command=("/usr/bin/python3", "-I", "codex-launcher", "exec", "review this")
        )
        with (
            mock.patch.object(
                role, "prepare_external_agent_command", return_value=prepared
            ) as prepare,
            mock.patch.object(role, "sandbox_argv", return_value=["sandbox"]),
        ):
            role._review_sandbox_argv(
                repo,
                declared,
                expected_head="a" * 40,
                expected_base_head="b" * 40,
                review_diff=b"",
            )

        prepare.assert_called_once_with(declared)

    def test_codex_review_sandbox_preserves_existing_noninteractive_subcommands(self) -> None:
        repo = Path("/tmp/repo")
        for subcommand in ("e", "review"):
            with self.subTest(subcommand=subcommand):
                declared = ["codex", subcommand, "review this"]
                prepared = PreparedSandboxCommand(
                    command=("/usr/bin/python3", "-I", "codex-launcher", subcommand, "review this")
                )
                with (
                    mock.patch.object(
                        role, "prepare_external_agent_command", return_value=prepared
                    ) as prepare,
                    mock.patch.object(role, "sandbox_argv", return_value=["sandbox"]),
                ):
                    role._review_sandbox_argv(
                        repo,
                        declared,
                        expected_head="a" * 40,
                        expected_base_head="b" * 40,
                        review_diff=b"",
                    )

                prepare.assert_called_once_with(declared)

    def test_codex_review_subcommand_detection_skips_global_option_values(self) -> None:
        declared = ["codex", "--model", "review", "review this"]
        self.assertIsNone(role._codex_declared_subcommand(declared))
        self.assertEqual(
            role._codex_review_command_for_headless_execution(declared),
            ["codex", "--model", "review", "exec", "review this"],
        )

    def test_codex_review_subcommand_detection_preserves_exec_with_subcommand_options(self) -> None:
        declared = ["codex", "exec", "--json", "review this"]
        self.assertEqual(role._codex_declared_subcommand(declared), "exec")
        self.assertEqual(
            role._codex_review_command_for_headless_execution(declared),
            declared,
        )

    def test_codex_review_root_image_options_are_normalized_before_exec(self) -> None:
        declared = [
            "codex",
            "--image",
            "shot.png",
            "detail.png",
            "--model",
            "gpt-5.6-sol",
            "review this",
        ]
        self.assertIsNone(role._codex_declared_subcommand(declared))
        self.assertEqual(
            role._codex_review_command_for_headless_execution(declared),
            [
                "codex",
                "--image=shot.png",
                "--image=detail.png",
                "--model",
                "gpt-5.6-sol",
                "exec",
                "review this",
            ],
        )

    def test_codex_review_attached_short_option_values_are_supported(self) -> None:
        for option in ("-mgpt-5.6-sol", "-sread-only", "-creview=true"):
            with self.subTest(option=option):
                declared = ["codex", option, "review this"]
                self.assertIsNone(role._codex_declared_subcommand(declared))
                self.assertEqual(
                    role._codex_review_command_for_headless_execution(declared),
                    ["codex", option, "exec", "review this"],
                )

    def test_codex_review_attached_image_value_is_normalized_before_exec(self) -> None:
        declared = ["codex", "-ishot.png", "review this"]
        self.assertIsNone(role._codex_declared_subcommand(declared))
        self.assertEqual(
            role._codex_review_command_for_headless_execution(declared),
            ["codex", "--image=shot.png", "exec", "review this"],
        )

    def test_codex_review_attached_image_equals_value_is_normalized_before_exec(self) -> None:
        declared = ["codex", "-i=shot.png", "review this"]
        self.assertIsNone(role._codex_declared_subcommand(declared))
        self.assertEqual(
            role._codex_review_command_for_headless_execution(declared),
            ["codex", "--image=shot.png", "exec", "review this"],
        )

    def test_codex_review_attached_image_values_preserve_variadic_group(self) -> None:
        for first in ("-ishot.png", "--image=shot.png"):
            with self.subTest(first=first):
                declared = ["codex", first, "detail.png", "review this"]
                self.assertIsNone(role._codex_declared_subcommand(declared))
                self.assertEqual(
                    role._codex_review_command_for_headless_execution(declared),
                    [
                        "codex",
                        "--image=shot.png",
                        "--image=detail.png",
                        "exec",
                        "review this",
                    ],
                )

    def test_codex_review_variadic_images_stop_at_headless_subcommand(self) -> None:
        declared = [
            "codex",
            "--image=shot.png",
            "detail.png",
            "exec",
            "--json",
            "review this",
        ]
        self.assertEqual(role._codex_declared_subcommand(declared), "exec")
        self.assertEqual(
            role._codex_review_command_for_headless_execution(declared),
            declared,
        )

    def test_codex_review_variadic_images_stop_at_unsupported_root_subcommand(self) -> None:
        for subcommand in ("login", "mcp-server"):
            with self.subTest(subcommand=subcommand):
                declared = [
                    "codex",
                    "--image=shot.png",
                    "detail.png",
                    subcommand,
                    "review this",
                ]
                self.assertEqual(role._codex_declared_subcommand(declared), subcommand)
                with self.assertRaisesRegex(
                    RuntimeError,
                    f"Codex review command declares unsupported subcommand: {subcommand}",
                ):
                    role._codex_review_command_for_headless_execution(declared)

    def test_codex_review_attached_image_empty_equals_is_rejected(self) -> None:
        declared = ["codex", "-i=", "review this"]
        with self.assertRaisesRegex(RuntimeError, "Codex global option -i is missing its value"):
            role._codex_review_command_for_headless_execution(declared)

    def test_codex_review_prompt_separator_is_preserved_after_exec(self) -> None:
        declared = ["codex", "--", "--version"]
        self.assertIsNone(role._codex_declared_subcommand(declared))
        self.assertEqual(
            role._codex_review_command_for_headless_execution(declared),
            ["codex", "exec", "--", "--version"],
        )

    def test_codex_review_prompt_separator_rejects_extra_positionals(self) -> None:
        declared = ["codex", "--", "review", "review this"]
        with self.assertRaisesRegex(RuntimeError, "extra positional arguments after --"):
            role._codex_review_command_for_headless_execution(declared)

    def test_codex_review_preserves_headless_subcommand_after_attached_global_option(self) -> None:
        declared = ["codex", "-mgpt-5.6-sol", "review", "review this"]
        self.assertEqual(role._codex_declared_subcommand(declared), "review")
        self.assertEqual(
            role._codex_review_command_for_headless_execution(declared),
            declared,
        )

    def test_review_sandbox_preserves_declared_command_for_provenance(self) -> None:
        repo = Path("/tmp/repo")
        declared = ["grok", "--model", "grok-4.6", "review this"]
        prepared = PreparedSandboxCommand(
            command=("/opt/grabowski-external/grok", "--model", "grok-4.6", "-p", "review this")
        )
        with (
            mock.patch.object(role, "prepare_external_agent_command", return_value=prepared),
            mock.patch.object(role, "sandbox_argv", return_value=["sandbox"]) as sandbox_argv,
        ):
            argv, contract, prompt_bytes = role._review_sandbox_argv(
                repo, declared, expected_head="a" * 40, expected_base_head="b" * 40, review_diff=b"diff"
            )
        self.assertEqual(argv, ["sandbox"])
        self.assertEqual(contract, role.GROK_REVIEW_STREAM_CONTRACT)
        self.assertIn(b"diff", prompt_bytes)
        self.assertEqual(
            sandbox_argv.call_args.kwargs["additional_read_only_data_fds"],
            ((0, role.GROK_REVIEW_PROMPT_TARGET),),
        )
        actual = sandbox_argv.call_args.args[1]
        self.assertEqual(actual[actual.index("--tools") + 1], "todo_write")
        self.assertEqual(
            actual[actual.index("--disallowed-tools") + 1],
            "todo_write,search_tool,use_tool,run_terminal_cmd,run_terminal_command",
        )
        self.assertEqual(sandbox_argv.call_args.kwargs["declared_command"], declared)
        self.assertEqual(
            actual[actual.index("--prompt-file") + 1],
            str(role.GROK_REVIEW_PROMPT_TARGET),
        )

    def test_terminal_json_object_accepts_unique_object_suffix_after_prose(self) -> None:
        review = role._terminal_json_object(
            "Reviewed the exact diff.\n\n{\n  \"verdict\": \"PASS\",\n  \"findings\": []\n}\n"
        )
        self.assertEqual(review, {"verdict": "PASS", "findings": []})
        self.assertIsNone(role._terminal_json_object("no final object"))
        self.assertIsNone(
            role._terminal_json_object(
                "```json\n{\"verdict\":\"PASS\",\"findings\":[]}\n```"
            )
        )

    def test_extract_stream_accepts_toolless_terminal_review(self) -> None:
        events = [
            {"type": "thought", "data": "review bound diff"},
            {"type": "available_commands", "tools": []},
            {"type": "usage", "usage": {"input_tokens": 1}},
            {"type": "memory_flush_started"},
            {"type": "memory_flush_completed"},
            {"type": "text", "data": "Reviewed.\n\n"},
            {"type": "text", "data": '{"verdict":"PASS","findings":[]}'},
            {"type": "end", "stopReason": "end_turn", "num_turns": 1},
        ]
        document, error, metadata = role._extract_grok_stream_review_document(
            stream_bytes(events), expected_head="a" * 40, expected_base_head="b" * 40
        )
        self.assertIsNone(error)
        self.assertEqual(json.loads(document), {"verdict": "PASS", "findings": []})
        self.assertEqual(metadata["review_provider_completed_tool_calls"], 0)
        self.assertEqual(metadata["review_provider_num_turns"], 1)

    def test_extract_stream_rejects_unknown_provider_event(self) -> None:
        events = [
            {"type": "available_commands", "tools": []},
            {"type": "memory_flush_future"},
            {"type": "text", "data": '{"verdict":"PASS","findings":[]}'},
            {"type": "end", "stopReason": "end_turn", "num_turns": 1},
        ]
        document, error, _ = role._extract_grok_stream_review_document(
            stream_bytes(events), expected_head="a" * 40, expected_base_head="b" * 40
        )
        self.assertIsNone(document)
        self.assertIn("unsupported event type", error)

    def test_extract_stream_requires_empty_tool_availability_evidence(self) -> None:
        base_events = [
            {"type": "text", "data": '{"verdict":"PASS","findings":[]}'},
            {"type": "end", "stopReason": "end_turn", "num_turns": 1},
        ]
        cases = (
            ([{"type": "available_commands", "tools": ["search_tool"]}, *base_events], "advertised disallowed tools"),
            (base_events, "did not prove an empty tool surface"),
            ([{"type": "available_commands", "tools": ""}, *base_events], "available tool evidence is invalid"),
        )
        for events, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                document, error, _ = role._extract_grok_stream_review_document(
                    stream_bytes(events), expected_head="a" * 40, expected_base_head="b" * 40
                )
                self.assertIsNone(document)
                self.assertIn(expected_error, error)

    def test_extract_stream_rejects_any_tool_use(self) -> None:
        events = [
            {"type": "tool_call", "toolCallId": "x", "toolName": "run_terminal_command", "rawInput": {"command": "git status"}},
            {"type": "end", "stopReason": "end_turn", "num_turns": 2},
        ]
        document, error, _ = role._extract_grok_stream_review_document(
            stream_bytes(events), expected_head="a" * 40, expected_base_head="b" * 40
        )
        self.assertIsNone(document)
        self.assertIn("attempted tool use", error)

    def test_extract_stream_fails_closed_on_bad_terminal_shape(self) -> None:
        availability = {"type": "available_commands", "tools": []}
        cases = (
            ([availability, {"type": "text", "data": '{"verdict":"PASS","findings":[]}'}, {"type": "end", "stopReason": "cancelled", "num_turns": 1}], "end_turn"),
            ([availability, {"type": "text", "data": "```json\n{\"verdict\":\"PASS\",\"findings\":[]}\n```"}, {"type": "end", "stopReason": "end_turn", "num_turns": 1}], "unique JSON object suffix"),
        )
        for events, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                document, error, _ = role._extract_grok_stream_review_document(
                    stream_bytes(events), expected_head="a" * 40, expected_base_head="b" * 40
                )
                self.assertIsNone(document)
                self.assertIn(expected_error, error)


    def test_grok_oversize_receipt_reports_the_applied_stream_limit(self) -> None:
        head = "a" * 40
        base = "b" * 40
        diff = "c" * 64
        completed = SimpleNamespace(
            returncode=0,
            stdout_sha256="d" * 64,
            stderr_sha256="e" * 64,
            stdout_bytes=role.MAX_GROK_REVIEW_STREAM_BYTES + 1,
            stderr_bytes=0,
            stdout_tail="",
            stderr_tail="",
            output_limit_exceeded=False,
            stdout_content_exceeded=True,
            stdout_content=None,
        )
        with (
            mock.patch.object(role, "current_binding", side_effect=[(head, diff, False), (head, diff, False)]),
            mock.patch.object(role, "committed_diff", return_value=b"diff"),
            mock.patch.object(role, "_review_sandbox_argv", return_value=(["sandbox"], role.GROK_REVIEW_STREAM_CONTRACT, b"prompt")),
            mock.patch.object(role, "runtime_sandbox_argv", return_value=["runtime"]),
            mock.patch.object(role, "run_bounded_capture", return_value=completed),
            mock.patch.object(role, "classify_result", return_value="invalid_review_output"),
            mock.patch.object(role, "write_receipt") as write_receipt,
        ):
            returncode = role.main(
                [
                    "--role", "review",
                    "--repository", str(ROOT),
                    "--expected-head", head,
                    "--expected-base-head", base,
                    "--expected-diff-sha256", diff,
                    "--expected-dirty", "false",
                    "--output", "/tmp/grok-oversize-receipt.json",
                    "--", "grok", "--model", "grok-4.6", "review this",
                ]
            )

        self.assertEqual(returncode, 126)
        payload = write_receipt.call_args.args[1]
        self.assertEqual(payload["review_input_source"], "committed_diff")
        self.assertEqual(payload["review_content_limit_bytes"], role.MAX_GROK_REVIEW_STREAM_BYTES)
        self.assertEqual(
            payload["error"],
            f"review stdout exceeds {role.MAX_GROK_REVIEW_STREAM_BYTES} bytes",
        )

    def test_grok_extracted_review_document_reapplies_review_json_limit(self) -> None:
        head = "a" * 40
        base = "b" * 40
        diff = "c" * 64
        stream = b"{}\n"
        completed = SimpleNamespace(
            returncode=0,
            stdout_sha256="d" * 64,
            stderr_sha256="e" * 64,
            stdout_bytes=len(stream),
            stderr_bytes=0,
            stdout_tail="",
            stderr_tail="",
            output_limit_exceeded=False,
            stdout_content_exceeded=False,
            stdout_content=stream,
        )
        oversized_document = json.dumps(
            {
                "verdict": "PASS",
                "findings": [],
                "padding": "x" * role.MAX_REVIEW_JSON_BYTES,
            },
            separators=(",", ":"),
        ).encode()
        self.assertGreater(len(oversized_document), role.MAX_REVIEW_JSON_BYTES)
        self.assertLess(len(oversized_document), role.MAX_GROK_REVIEW_STREAM_BYTES)

        with (
            mock.patch.object(role, "current_binding", side_effect=[(head, diff, False), (head, diff, False)]),
            mock.patch.object(role, "committed_diff", return_value=b"diff"),
            mock.patch.object(role, "_review_sandbox_argv", return_value=(["sandbox"], role.GROK_REVIEW_STREAM_CONTRACT, b"prompt")),
            mock.patch.object(role, "runtime_sandbox_argv", return_value=["runtime"]),
            mock.patch.object(role, "run_bounded_capture", return_value=completed),
            mock.patch.object(
                role,
                "_extract_grok_stream_review_document",
                return_value=(oversized_document, None, {"review_provider_stream_contract": role.GROK_REVIEW_STREAM_CONTRACT}),
            ),
            mock.patch.object(role, "classify_result", return_value="invalid_review_output"),
            mock.patch.object(role, "write_receipt") as write_receipt,
        ):
            returncode = role.main(
                [
                    "--role", "review",
                    "--repository", str(ROOT),
                    "--expected-head", head,
                    "--expected-base-head", base,
                    "--expected-diff-sha256", diff,
                    "--expected-dirty", "false",
                    "--output", "/tmp/grok-document-oversize-receipt.json",
                    "--", "grok", "--model", "grok-4.6", "review this",
                ]
            )

        self.assertEqual(returncode, 126)
        payload = write_receipt.call_args.args[1]
        self.assertEqual(payload["verdict"], "INVALID")
        self.assertEqual(
            payload["error"],
            f"review document exceeds {role.MAX_REVIEW_JSON_BYTES} bytes",
        )


if __name__ == "__main__":
    unittest.main()
from pathlib import Path
import textwrap


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"unexpected {label} anchor: {text.count(old)}")
    return text.replace(old, new, 1)


def patch_source(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    source = replace_once(
        source,
        "from __future__ import annotations\n\nfrom datetime import datetime, timezone\n",
        "from __future__ import annotations\n\nfrom contextlib import contextmanager\nfrom datetime import datetime, timezone\n",
        "contextlib import",
    )
    source = replace_once(
        source,
        "import base64\nimport hashlib\n",
        "import base64\nimport fcntl\nimport hashlib\n",
        "fcntl import",
    )
    helper = textwrap.dedent(
        '''

        def _audit_append_lock_path(audit_path: Path | None = None) -> Path:
            target = AUDIT_LOG if audit_path is None else audit_path
            return target.parent / f".{target.name}.lock"


        @contextmanager
        def _exclusive_audit_append_lock(audit_path: Path | None = None):
            """Serialize audit verification and append across independent processes."""
            target = AUDIT_LOG if audit_path is None else audit_path
            root = _state_root()
            try:
                parent = target.parent.resolve(strict=True)
            except OSError as exc:
                raise PermissionError("cannot resolve audit log parent") from exc
            if parent != root:
                raise PermissionError("audit log must be directly inside Grabowski state")

            lock_path = _audit_append_lock_path(target)
            if lock_path.is_symlink():
                raise PermissionError(f"Audit append lock may not be a symlink: {lock_path}")
            flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(lock_path, flags, 0o600)
            except OSError as exc:
                raise PermissionError("cannot safely open audit append lock") from exc

            locked = False
            try:
                opened = os.fstat(descriptor)
                linked = os.stat(lock_path, follow_symlinks=False)
                if not statmod.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                    raise PermissionError("audit append lock must be one regular file")
                if opened.st_uid != os.geteuid():
                    raise PermissionError("audit append lock owner is invalid")
                if statmod.S_IMODE(opened.st_mode) != 0o600:
                    raise PermissionError("audit append lock mode must be 0600")
                if opened.st_dev != linked.st_dev or opened.st_ino != linked.st_ino:
                    raise PermissionError("audit append lock changed while opening")

                fcntl.flock(descriptor, fcntl.LOCK_EX)
                locked = True
                current = os.stat(lock_path, follow_symlinks=False)
                if (
                    not statmod.S_ISREG(current.st_mode)
                    or current.st_dev != opened.st_dev
                    or current.st_ino != opened.st_ino
                    or current.st_uid != opened.st_uid
                    or current.st_nlink != opened.st_nlink
                ):
                    raise PermissionError("audit append lock changed while held")
                yield
            finally:
                if locked:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
        '''
    )
    source = replace_once(
        source,
        "\n\ndef _audit_record_hash(record: dict[str, Any]) -> str:\n",
        helper + "\n\ndef _audit_record_hash(record: dict[str, Any]) -> str:\n",
        "audit helper",
    )

    start = source.index("def _append_audit(record: dict[str, Any]) -> None:\n")
    end = source.index("\n\ndef _audit_records() -> list[dict[str, Any]]:\n", start)
    lines = source[start:end].splitlines()
    if len(lines) < 3 or lines[1] != "    with AUDIT_APPEND_LOCK:":
        raise SystemExit("unexpected audit append shape")
    nested = [
        lines[0],
        lines[1],
        "        with _exclusive_audit_append_lock(AUDIT_LOG):",
    ]
    nested.extend(("    " + line) if line else line for line in lines[2:])
    source = source[:start] + "\n".join(nested) + source[end:]
    path.write_text(source, encoding="utf-8")


def patch_tests(path: Path) -> None:
    tests = path.read_text(encoding="utf-8")
    tests = replace_once(
        tests,
        "import json\nimport os\nfrom pathlib import Path\n",
        "import json\nimport multiprocessing\nimport os\nfrom pathlib import Path\nimport queue\n",
        "multiprocessing import",
    )
    worker = textwrap.dedent(
        '''

        def _audit_append_process_worker(
            state_dir: str,
            audit_log: str,
            ready,
            release,
            attempting,
            results,
        ) -> None:
            grabowski_mcp.STATE_DIR = Path(state_dir)
            grabowski_mcp.AUDIT_LOG = Path(audit_log)
            grabowski_mcp.QUARANTINE_DIR = Path(state_dir) / "quarantine"
            grabowski_mcp.KILL_SWITCH_PATH = Path(state_dir) / "operator-kill-switch"
            ready.set()
            if not release.wait(5):
                results.put(("error", "release timeout"))
                return
            attempting.set()
            try:
                grabowski_mcp._append_audit(
                    {"operation": "cross-process-test", "path": "/test"}
                )
            except BaseException as exc:
                results.put(("error", f"{type(exc).__name__}: {exc}"))
            else:
                results.put(("ok", None))
        '''
    )
    tests = replace_once(
        tests,
        "\n\ndef _static_tool_guard_requirements() -> tuple[dict[str, tuple[str, ...]], set[str]]:\n",
        worker
        + "\n\ndef _static_tool_guard_requirements() -> tuple[dict[str, tuple[str, ...]], set[str]]:\n",
        "worker",
    )
    test_case = textwrap.indent(
        textwrap.dedent(
            '''

            def test_audit_append_waits_for_cross_process_lock(self) -> None:
                if "fork" not in multiprocessing.get_all_start_methods():
                    self.skipTest("cross-process flock test requires fork")
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    _work, _secret, _browser, _export, state, *patches = self._patched_runtime(root)
                    with patches[0], patches[1], patches[2], patches[3], patches[4]:
                        context = multiprocessing.get_context("fork")
                        ready = context.Event()
                        release = context.Event()
                        attempting = context.Event()
                        results = context.Queue()
                        audit = state / "write-audit.jsonl"
                        process = context.Process(
                            target=_audit_append_process_worker,
                            args=(
                                str(state),
                                str(audit),
                                ready,
                                release,
                                attempting,
                                results,
                            ),
                        )
                        process.start()
                        try:
                            self.assertTrue(ready.wait(5))
                            with grabowski_mcp._exclusive_audit_append_lock(audit):
                                release.set()
                                self.assertTrue(attempting.wait(5))
                                with self.assertRaises(queue.Empty):
                                    results.get(timeout=0.4)
                                self.assertTrue(process.is_alive())
                            self.assertEqual(results.get(timeout=5), ("ok", None))
                            process.join(5)
                            self.assertFalse(process.is_alive())
                            self.assertEqual(process.exitcode, 0)
                        finally:
                            release.set()
                            process.join(5)
                            if process.is_alive():
                                process.terminate()
                                process.join(5)
                            process.close()
                            results.close()

                        status = grabowski_mcp._verify_audit_log(audit)
                        self.assertTrue(status["valid"])
                        self.assertEqual(status["records"], 1)
                        lock_path = grabowski_mcp._audit_append_lock_path(audit)
                        self.assertTrue(lock_path.is_file())
                        self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)
            '''
        ),
        "    ",
    )
    tests = replace_once(
        tests,
        "\n    def test_replace_quarantines_preimage_and_rolls_back(self) -> None:\n",
        test_case + "\n    def test_replace_quarantines_preimage_and_rolls_back(self) -> None:\n",
        "test insertion",
    )
    path.write_text(tests, encoding="utf-8")


patch_source(Path("src/grabowski_mcp.py"))
patch_tests(Path("tests/test_operator_v2_runtime.py"))

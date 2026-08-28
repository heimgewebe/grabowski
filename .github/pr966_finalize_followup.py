#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BROKER = ROOT / "tools" / "grabowski_privileged_broker.py"
TESTS = ROOT / "tests" / "test_privileged_broker_peer.py"
DOCS = ROOT / "docs" / "privileged-broker-bootstrap.md"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, got {count}")
    return text.replace(old, new, 1)


def replace_test(text: str, name: str, next_name: str, replacement: str) -> str:
    start = text.find(f"    def {name}(")
    end = text.find(f"\n    def {next_name}(", start)
    if start < 0 or end < 0:
        raise SystemExit(f"test boundary missing: {name} -> {next_name}")
    return text[:start] + replacement.rstrip() + "\n\n" + text[end + 1:]


broker = BROKER.read_text(encoding="utf-8")

broker = replace_once(
    broker,
    '''    if argv[0] == "/usr/bin/install":
        bindings = [binding for value in argv[1:] if (binding := _package_stage_binding(value)) is not None]
        if not bindings:
            raise PermissionError("package install mentions stage root without a canonical stage binding")
        if len({binding[0] for binding in bindings}) != 1:
            raise PermissionError("package install spans multiple plans")
        return {"kind": "mutation", "plan_id": bindings[0][0], "package_paths": [], "exact_evidence": False}
    if argv[0] == "/usr/bin/rm":
        bindings = [binding for value in argv[1:] if (binding := _package_stage_binding(value)) is not None]
        if not bindings or len({binding[0] for binding in bindings}) != 1:
            raise PermissionError("package cleanup stage binding is invalid")
        return {"kind": "mutation", "plan_id": bindings[0][0], "package_paths": [], "exact_evidence": False}
''',
    '''    if argv[0] == "/usr/bin/install":
        stage_values = [
            value for value in argv[1:]
            if isinstance(value, str) and _argv_mentions_package_stage([value])
        ]
        bindings = [_package_stage_binding(value) for value in stage_values]
        if not bindings or any(binding is None for binding in bindings):
            raise PermissionError("package install stage binding is invalid")
        canonical = [binding for binding in bindings if binding is not None]
        if len({binding[0] for binding in canonical}) != 1:
            raise PermissionError("package install spans multiple plans")
        return {"kind": "mutation", "plan_id": canonical[0][0], "package_paths": [], "exact_evidence": False}
    if argv[0] == "/usr/bin/rm":
        stage_values = [
            value for value in argv[1:]
            if isinstance(value, str) and _argv_mentions_package_stage([value])
        ]
        bindings = [_package_stage_binding(value) for value in stage_values]
        if not bindings or any(binding is None for binding in bindings):
            raise PermissionError("package cleanup stage binding is invalid")
        canonical = [binding for binding in bindings if binding is not None]
        if len({binding[0] for binding in canonical}) != 1:
            raise PermissionError("package cleanup spans multiple plans")
        return {"kind": "mutation", "plan_id": canonical[0][0], "package_paths": [], "exact_evidence": False}
''',
    "canonical install/rm stage arguments",
)

broker = replace_once(
    broker,
    '''            value.get("package_preflight_completed") is not True
            or value.get("package_plan_id") != plan_id
            or value.get("package_paths") != required_paths
''',
    '''            value.get("package_preflight_completed") is not True
            or value.get("package_operation") != "apt_preflight"
            or value.get("package_exact_evidence") is not True
            or value.get("package_plan_id") != plan_id
            or value.get("package_paths") != required_paths
''',
    "explicit preflight operation binding",
)

broker = replace_once(
    broker,
    '''        or not isinstance(paths, list)
        or not paths
        or any(not isinstance(path, str) or _package_stage_binding(path) is None for path in paths)
        or not isinstance(guard_sha256, str)
''',
    '''        or not isinstance(paths, list)
        or not paths
        or any(
            not isinstance(path, str)
            or (binding := _package_stage_binding(path)) is None
            or binding[0] != plan_id
            or binding[2] is None
            for path in paths
        )
        or not isinstance(guard_sha256, str)
''',
    "replay marker exact plan/file binding",
)

BROKER.write_text(broker, encoding="utf-8")


tests = TESTS.read_text(encoding="utf-8")
tests = replace_once(
    tests,
    '''                    "stdout_bytes": 4,
                    "stdout_truncated": False,
                }
''',
    '''                    "stdout_bytes": 4,
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                }
''',
    "generic output evidence stderr completeness",
)

tests = replace_test(
    tests,
    "test_package_stage_operation_requires_exact_dpkg_files",
    "test_package_sha256_output_is_exact_path_bound",
    r'''    def test_package_stage_operation_requires_exact_dpkg_files(self) -> None:
        plan_id = "20260827T010203Z-123456abcdef"
        deb = str(broker_tool.PACKAGE_UPDATE_STAGE_ROOT / plan_id / "debs" / "a.deb")

        preflight_argv = broker_tool._expected_package_dpkg_preflight_argv([deb])
        preflight = broker_tool._package_stage_operation(preflight_argv)
        self.assertEqual(preflight["kind"], "preflight")
        self.assertEqual(preflight["operation"], "apt_preflight")
        self.assertEqual(preflight["plan_id"], plan_id)
        self.assertEqual(preflight["package_paths"], [deb])
        self.assertIs(preflight["exact_evidence"], True)

        apply_argv = broker_tool._expected_package_apt_systemd_argv(plan_id, [deb])
        operation = broker_tool._package_stage_operation(apply_argv)
        self.assertEqual(operation["kind"], "apply")
        self.assertEqual(operation["operation"], "apt_apply")
        self.assertEqual(operation["plan_id"], plan_id)
        self.assertEqual(operation["package_paths"], [deb])
        self.assertIs(operation["exact_evidence"], True)

        with self.assertRaisesRegex(PermissionError, "exact released simulation"):
            broker_tool._package_stage_operation([
                "/usr/bin/dpkg", "--log", "--dry-run", "--install", deb,
            ])

        missing_wait = list(apply_argv)
        missing_wait.remove("--wait")
        with self.assertRaisesRegex(PermissionError, "exact synchronous local APT apply"):
            broker_tool._package_stage_operation(missing_wait)

        remote_wrapper = list(apply_argv)
        remote_wrapper.insert(2, "--host=example.invalid")
        with self.assertRaisesRegex(PermissionError, "exact synchronous local APT apply"):
            broker_tool._package_stage_operation(remote_wrapper)

        noncanonical = (
            str(broker_tool.PACKAGE_UPDATE_STAGE_ROOT)
            + "//"
            + plan_id
            + "/debs/a.deb"
        )
        self.assertTrue(broker_tool._argv_mentions_package_stage([noncanonical]))
        with self.assertRaises(PermissionError):
            broker_tool._package_stage_operation([
                "/usr/bin/dpkg", "--simulate", "--refuse-downgrade",
                "--force-confold", "--install", noncanonical,
            ])

        lexical_escape = str(broker_tool.PACKAGE_UPDATE_STAGE_ROOT) + "/../outside.deb"
        self.assertTrue(broker_tool._argv_mentions_package_stage([lexical_escape]))
        with self.assertRaises(PermissionError):
            broker_tool._package_stage_operation([
                "/usr/bin/dpkg", "--simulate", "--refuse-downgrade",
                "--force-confold", "--install", lexical_escape,
            ])''',
)

tests = replace_test(
    tests,
    "test_package_apply_exact_evidence_rejects_superset",
    "test_package_apply_revalidates_evidence_under_lock_before_spawn",
    r'''    def test_package_apply_plan_wide_evidence_accepts_operation_subset(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            stage_root = root / "stages"
            evidence_root = root / "evidence"
            stage_root.mkdir(mode=0o700)
            evidence_root.mkdir(mode=0o700)
            plan_id = "20260827T010203Z-123456abcdef"
            deb_dir = stage_root / plan_id / "debs"
            snap_dir = stage_root / plan_id / "snaps"
            deb_dir.mkdir(parents=True, mode=0o700)
            snap_dir.mkdir(parents=True, mode=0o700)
            deb = deb_dir / "a.deb"
            snap = snap_dir / "a.snap"
            deb.write_bytes(b"deb")
            snap.write_bytes(b"snap")
            deb.chmod(0o600)
            snap.chmod(0o600)
            paths = [str(deb), str(snap)]
            hashes = {
                path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                for path in paths
            }
            evidence = {
                "schema_version": 1,
                "kind": broker_tool.OUTPUT_EVIDENCE_KIND,
                "request_id": "b" * 32,
                "peer_uid": os.geteuid(),
                "peer_unit": "grabowski-operator.service",
                "timestamp_unix": int(broker_tool.time.time()),
                "package_plan_id": plan_id,
                "package_paths": paths,
                "package_sha256": hashes,
            }
            evidence["evidence_sha256"] = broker_tool.canonical_sha256(evidence)
            proof = evidence_root / "proof.json"
            proof.write_text(json.dumps(evidence), encoding="utf-8")
            proof.chmod(0o640)
            operation = {
                "kind": "apply",
                "operation": "apt_apply",
                "plan_id": plan_id,
                "package_paths": [str(deb)],
                "exact_evidence": True,
            }
            with (
                mock.patch.object(broker_tool, "PACKAGE_UPDATE_STAGE_ROOT", stage_root),
                mock.patch.object(broker_tool, "OUTPUT_EVIDENCE_ROOT", evidence_root),
            ):
                selected = broker_tool._find_package_apply_evidence(
                    operation,
                    peer_uid=os.geteuid(),
                    peer_unit="grabowski-operator.service",
                )
            self.assertEqual(selected["evidence_sha256"], evidence["evidence_sha256"])''',
)

start = tests.find("    def test_package_apply_revalidates_evidence_under_lock_before_spawn(")
end = tests.find("\n\nif __name__ == \"__main__\":", start)
if start < 0 or end < 0:
    raise SystemExit("last package apply test boundary missing")
tests = tests[:start] + r'''    def test_package_apply_revalidates_evidence_under_lock_before_spawn(self) -> None:
        events: list[str] = []
        operation = {
            "kind": "apply",
            "operation": "snap_install",
            "plan_id": "20260827T010203Z-123456abcdef",
            "package_paths": [
                "/var/lib/heim-pc/package-update-stages/20260827T010203Z-123456abcdef/snaps/a.snap"
            ],
            "exact_evidence": True,
        }

        class Lock:
            def __enter__(self):
                events.append("lock-enter")
            def __exit__(self, exc_type, exc, tb):
                events.append("lock-exit")

        process = mock.Mock(returncode=0)
        process.communicate.return_value = (b"", b"")

        def evidence(*args, **kwargs):
            events.append("evidence")
            return {
                "evidence_sha256": "c" * 64,
                "request_id": "d" * 32,
                "timestamp_unix": int(broker_tool.time.time()),
            }

        def replay_check(*args, **kwargs):
            events.append("replay-check")
            return {"binding": "ok"}

        def consume(*args, **kwargs):
            events.append("consume")
            return {"path": "/state/consumed.json", "sha256": "a" * 64}

        def popen(*args, **kwargs):
            events.append("popen")
            return process

        reference = {
            "request_id": "e" * 32,
            "reference_sha256": "f" * 64,
            "action": broker_tool.POWER_ACTION,
            "target": "{}",
        }
        execution = {
            "mode": "argv-json",
            "argv": ["/usr/bin/true"],
            "cwd": "/",
            "timeout_seconds": 5,
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }
        with (
            mock.patch.object(broker_tool, "_package_stage_operation", return_value=operation),
            mock.patch.object(broker_tool, "_package_stage_lock", side_effect=lambda: Lock()),
            mock.patch.object(broker_tool, "_find_package_apply_evidence", side_effect=evidence),
            mock.patch.object(broker_tool, "_assert_package_apply_not_consumed", side_effect=replay_check),
            mock.patch.object(broker_tool, "_consume_package_apply", side_effect=consume),
            mock.patch.object(broker_tool.subprocess, "Popen", side_effect=popen),
            mock.patch.object(broker_tool, "append_audit"),
        ):
            result = broker_tool._execute_broker_command(
                reference=reference,
                execution=execution,
                operator_peer=self.peer(),
            )
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(
            events,
            ["lock-enter", "evidence", "replay-check", "popen", "consume", "lock-exit"],
        )
        self.assertEqual(result["record"]["package_apply_evidence_sha256"], "c" * 64)
        self.assertEqual(result["record"]["package_apply_consumed_sha256"], "a" * 64)
        self.assertEqual(result["output_evidence_status"], "published")
        self._output_evidence.assert_called_once()

    def test_package_apply_consumption_blocks_exact_replay_only_after_success_marker(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            state = root / "state"
            stage_root = root / "stages"
            consumed_root = state / "package-update-apply-consumed"
            stage_root.mkdir(mode=0o700)
            plan_id = "20260827T010203Z-123456abcdef"
            snap = stage_root / plan_id / "snaps" / "a.snap"
            snap.parent.mkdir(parents=True, mode=0o700)
            snap.write_bytes(b"snap")
            snap.chmod(0o600)
            operation = {
                "kind": "apply",
                "operation": "snap_install",
                "plan_id": plan_id,
                "package_paths": [str(snap)],
                "exact_evidence": True,
            }
            guard = {"evidence_sha256": "a" * 64}
            install_argv = ["/usr/bin/snap", "install", str(snap)]
            ack_argv = ["/usr/bin/snap", "ack", str(snap)]
            with (
                mock.patch.object(broker_tool, "STATE", state),
                mock.patch.object(broker_tool, "PACKAGE_UPDATE_STAGE_ROOT", stage_root),
                mock.patch.object(
                    broker_tool,
                    "PACKAGE_UPDATE_APPLY_CONSUMED_ROOT",
                    consumed_root,
                ),
            ):
                binding = broker_tool._assert_package_apply_not_consumed(
                    operation,
                    guard_evidence=guard,
                    argv=install_argv,
                )
                broker_tool._consume_package_apply(binding)
                with self.assertRaisesRegex(PermissionError, "already consumed"):
                    broker_tool._assert_package_apply_not_consumed(
                        operation,
                        guard_evidence=guard,
                        argv=install_argv,
                    )
                distinct = broker_tool._assert_package_apply_not_consumed(
                    operation,
                    guard_evidence=guard,
                    argv=ack_argv,
                )
                self.assertNotEqual(
                    broker_tool._package_apply_consumption_path(binding),
                    broker_tool._package_apply_consumption_path(distinct),
                )

    def test_apt_apply_requires_exact_guard_bound_preflight_evidence(self) -> None:
        plan_id = "20260827T010203Z-123456abcdef"
        deb = str(broker_tool.PACKAGE_UPDATE_STAGE_ROOT / plan_id / "debs" / "a.deb")
        operation = {
            "kind": "apply",
            "operation": "apt_apply",
            "plan_id": plan_id,
            "package_paths": [deb],
            "exact_evidence": True,
        }
        guard = {
            "evidence_sha256": "a" * 64,
            "timestamp_unix": 100,
        }
        preflight = {
            "evidence_sha256": "b" * 64,
            "request_id": "c" * 32,
            "package_preflight_completed": True,
            "package_operation": "apt_preflight",
            "package_exact_evidence": True,
            "package_plan_id": plan_id,
            "package_paths": [deb],
            "package_preflight_guard_evidence_sha256": "a" * 64,
            "argv_sha256": broker_tool._argv_sha256(
                broker_tool._expected_package_dpkg_preflight_argv([deb])
            ),
            "peer_uid": 1000,
            "peer_unit": "grabowski-operator.service",
            "returncode": 0,
            "timed_out": False,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "timestamp_unix": 101,
        }
        with (
            mock.patch.object(
                broker_tool,
                "_package_evidence_candidates",
                return_value=[Path("/evidence/preflight.json")],
            ),
            mock.patch.object(
                broker_tool,
                "_read_package_output_evidence",
                return_value=preflight,
            ),
            mock.patch.object(broker_tool.time, "time", return_value=102),
        ):
            selected = broker_tool._find_package_preflight_evidence(
                operation,
                guard_evidence=guard,
                peer_uid=1000,
                peer_unit="grabowski-operator.service",
            )
            self.assertEqual(selected["evidence_sha256"], "b" * 64)
            bad = dict(preflight)
            bad["package_operation"] = "snap_install"
            with mock.patch.object(
                broker_tool,
                "_read_package_output_evidence",
                return_value=bad,
            ):
                with self.assertRaisesRegex(PermissionError, "no fresh authenticated"):
                    broker_tool._find_package_preflight_evidence(
                        operation,
                        guard_evidence=guard,
                        peer_uid=1000,
                        peer_unit="grabowski-operator.service",
                    )

    def test_failed_package_apply_does_not_consume_guard_operation(self) -> None:
        operation = {
            "kind": "apply",
            "operation": "snap_install",
            "plan_id": "20260827T010203Z-123456abcdef",
            "package_paths": [
                "/var/lib/heim-pc/package-update-stages/20260827T010203Z-123456abcdef/snaps/a.snap"
            ],
            "exact_evidence": True,
        }
        process = mock.Mock(returncode=1)
        process.communicate.return_value = (b"", b"failed")
        reference = {
            "request_id": "e" * 32,
            "reference_sha256": "f" * 64,
            "action": broker_tool.POWER_ACTION,
            "target": "{}",
        }
        execution = {
            "mode": "argv-json",
            "argv": ["/usr/bin/true"],
            "cwd": "/",
            "timeout_seconds": 5,
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }
        with (
            mock.patch.object(broker_tool, "_package_stage_operation", return_value=operation),
            mock.patch.object(broker_tool, "_package_stage_lock", return_value=nullcontext()),
            mock.patch.object(
                broker_tool,
                "_find_package_apply_evidence",
                return_value={
                    "evidence_sha256": "a" * 64,
                    "request_id": "b" * 32,
                    "timestamp_unix": int(broker_tool.time.time()),
                },
            ),
            mock.patch.object(
                broker_tool,
                "_assert_package_apply_not_consumed",
                return_value={"binding": "ok"},
            ),
            mock.patch.object(broker_tool, "_consume_package_apply") as consume,
            mock.patch.object(broker_tool.subprocess, "Popen", return_value=process),
            mock.patch.object(broker_tool, "append_audit"),
        ):
            result = broker_tool._execute_broker_command(
                reference=reference,
                execution=execution,
                operator_peer=self.peer(),
            )
        self.assertEqual(result["returncode"], 1)
        consume.assert_not_called()
        self.assertEqual(result["output_evidence_status"], "unavailable")

    def test_truncated_stderr_blocks_public_output_evidence(self) -> None:
        record = {
            "schema_version": 1,
            "timestamp_unix": 123,
            "request_id": "7" * 32,
            "reference_sha256": "6" * 64,
            "action": broker_tool.POWER_ACTION,
            "mode": "argv-json",
            "argv_sha256": "5" * 64,
            "cwd_sha256": "4" * 64,
            "peer_uid": 1000,
            "peer_unit": "grabowski-operator.service",
            "returncode": 0,
            "timed_out": False,
            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "stdout_bytes": 0,
            "stdout_truncated": False,
            "stderr_truncated": True,
        }
        with self.assertRaisesRegex(ValueError, "incomplete"):
            broker_tool._write_output_evidence(record)
''' + tests[end:]
TESTS.write_text(tests, encoding="utf-8")


docs = DOCS.read_text(encoding="utf-8")
old = """Für Paket-Stage-Operationen schließt der Broker zusätzlich das Readback→Apply-Replayfenster. Klassifizierte Stage-Copies, Hash-Readbacks, lokale APT-/Snap-Applies und Stage-Cleanup teilen einen root-eigenen cross-process `flock`. Ein erfolgreicher `sha256sum`-Beleg bindet bei Paketartefakten zusätzlich die kanonische Plan-ID, die exakten Stage-Pfade und deren SHA-256-Digests. Unmittelbar vor einem lokalen Apply sucht der Broker unter demselben Lock einen frischen, peer- und plan-gebundenen root-eigenen Beleg, verlangt für `dpkg` exakt dieselbe DEB-Dateimenge, hasht alle anzuwendenden Artefakte erneut und startet den Prozess nur bei identischen Bytes. Der Lock bleibt bis zum Prozessende gehalten. Rekursives `dpkg --recursive` sowie unklassifizierte Operationen, die den Paket-Stage-Root erwähnen, werden fail-closed abgewiesen. Damit kann ein später replaytes Stage-Copy nicht zwischen authentifiziertem Readback und Apply wirksam werden. Nach erfolgreichem Apply publiziert der Broker noch unter demselben Lock einen root-eigenen `0640`-Completion-Beleg für exakt die ausgeführte argv. Dieser bindet Plan-ID, exakte Paketpfade und den zuvor konsumierten Hash-Evidence-Digest; fehlgeschlagene, abgebrochene oder abgeschnittene Applies erhalten keinen Completion-Beleg.
"""
new = """Für Paket-Stage-Operationen schließt der Broker zusätzlich das Readback→Preflight→Apply-Replayfenster. Klassifizierte Stage-Copies, Hash-Readbacks, der APT-Preflight, lokale APT-/Snap-Applies und Stage-Cleanup teilen einen root-eigenen cross-process `flock`. Ein erfolgreicher `sha256sum`-Beleg bindet die kanonische Plan-ID, die gelesenen Stage-Pfade und deren SHA-256-Digests. Ein planweiter Beleg darf APT- und Snap-Artefakte gemeinsam enthalten; jede privilegierte Einzeloperation muss jedoch eine Teilmenge desselben Plans sein und ihre eigenen Bytes unmittelbar vor Ausführung erneut erfolgreich gegen diesen Beleg hashen.

Der APT-Preflight ist ausschließlich die exakte lokale argv `/usr/bin/dpkg --simulate --refuse-downgrade --force-confold --install <DEBs>`. Nur ein erfolgreicher, ungekürzter Preflight erzeugt einen root-eigenen `0640`-Beleg; dieser bindet Plan, exakte DEB-Reihenfolge, Peer, exakte argv und den Hash-Evidence-Digest. Der folgende APT-Apply ist ausschließlich der freigegebene synchrone lokale `systemd-run --system --wait --collect --pipe ... -- /usr/bin/dpkg --refuse-downgrade --force-confold --install <DEBs>` mit der vollständig erwarteten Isolation. Fehlendes `--wait`, Remote-/Machine-Ausführung, zusätzliche oder veränderte Wrapper-Optionen sowie andere `dpkg`-Optionen werden fail-closed abgewiesen. Vor dem APT-Apply muss ein frischer erfolgreicher Preflight mit demselben Peer, Plan, derselben DEB-Liste und demselben Hash-Evidence-Digest vorliegen.

Snap-`ack` und Snap-`install` gelten beide als mutierende Apply-Operationen. Nach einem erfolgreichen Apply schreibt der Broker noch unter demselben Lock atomar einen root-eigenen `0600`-Verbrauchsmarker, gebunden an Plan, exakte Paketpfade, Hash-Evidence-Digest und exakte Apply-argv. Erst danach kann öffentlicher Completion-Beleg publiziert werden. Derselbe planweite Hash-Beleg darf damit mehrere verschiedene vorgesehene Operationen autorisieren, aber eine bereits erfolgreich ausgeführte identische Operation nicht erneut. Fehlgeschlagene oder zeitüberschrittene Applies verbrauchen die Operation nicht. Kann der Verbrauchsmarker nach bereits erfolgreicher Mutation nicht sicher persistiert werden, endet der Broker fail-closed und publiziert keinen erfolgreichen Completion-Beleg; eine partielle Markerdatei bleibt absichtlich ein administrativ zu prüfender Sperrzustand.

Nichtkanonische Stage-Pfade — auch alternative Schreibweisen mit doppelten Separatoren oder lexikalischen `..`-Anteilen — werden bereits bei Erwähnung erkannt und können den Stage-Guard nicht umgehen. Öffentliche Hash-, Preflight- und Apply-Evidenz wird nur bei erfolgreichem Returncode ohne Timeout und ohne abgeschnittenes stdout oder stderr publiziert. Der Paket-Lock bleibt bis zum Prozessende und zur erfolgreichen Replay-Markierung gehalten.
"""
docs = replace_once(docs, old, new, "package broker contract documentation")
DOCS.write_text(docs, encoding="utf-8")

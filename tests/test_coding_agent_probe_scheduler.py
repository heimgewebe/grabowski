from __future__ import annotations

import fcntl
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
import signal
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "coding_agent_probe_scheduler.py"
SPEC = importlib.util.spec_from_file_location(
    "coding_agent_probe_scheduler", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
SCHEDULER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCHEDULER)

TEST_SCRUBBED_ENV = ("ROUTER_AUTH_ENV_A", "ROUTER_AUTH_ENV_B")


class CodingAgentProbeSchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.expected_scrub_patch = mock.patch.object(
            SCHEDULER,
            "EXPECTED_ROUTER_SCRUBBED_API_KEY_ENV",
            TEST_SCRUBBED_ENV,
        )
        self.expected_scrub_patch.start()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "state.json"
        self.lock = self.root / "probe.lock"
        self.receipt = self.root / "receipt.json"
        self.failure = self.root / "failure.json"
        self.router = self.root / "agent-route"
        self.router_digest = self.root / "router.sha256"
        self.codex_sessions = self.root / "codex-sessions"
        self.codex_sessions.mkdir()
        self.initial = {
            "schema_version": 2,
            "updated_at": "2026-07-18T15:00:00Z",
            "catalog_sha256": "catalog",
            "catalog": {},
            "pools": {"pool": {"status": "available"}},
            "routes": {"route": {"runs": 7}},
            "history": {"marker": {"value": 1}},
        }
        self.state.write_text(json.dumps(self.initial), encoding="utf-8")
        os.chmod(self.state, 0o600)

    def tearDown(self) -> None:
        self.expected_scrub_patch.stop()
        self.temporary.cleanup()

    @staticmethod
    def _process_is_live(process_id: int) -> bool:
        try:
            stat_payload = Path(f"/proc/{process_id}/stat").read_text(encoding="ascii")
        except FileNotFoundError:
            return False
        except PermissionError:
            return True
        try:
            state = stat_payload.rsplit(")", 1)[1].strip().split(maxsplit=1)[0]
        except IndexError:
            return True
        return state not in {"X", "Z"}

    def _wait_for_positive_pid(
        self, path: Path, *, timeout_seconds: float
    ) -> int:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            try:
                process_id = int(path.read_text(encoding="ascii").strip())
            except (FileNotFoundError, ValueError):
                time.sleep(0.02)
                continue
            if process_id > 0:
                return process_id
            time.sleep(0.02)
        self.fail(
            f"PID file did not contain a positive integer before timeout: {path}"
        )

    def test_wait_for_positive_pid_tolerates_empty_existing_file(self) -> None:
        pid_path = self.root / "child.pid"
        pid_path.touch()
        with (
            mock.patch.object(Path, "read_text", side_effect=["", "321\n"]) as read_text,
            mock.patch.object(time, "sleep") as sleep,
        ):
            process_id = self._wait_for_positive_pid(pid_path, timeout_seconds=1)
        self.assertEqual(321, process_id)
        self.assertEqual(2, read_text.call_count)
        sleep.assert_called_once_with(0.02)

    def write_router(
        self,
        *,
        mutate_history: bool = False,
        tamper_digest: bool = False,
        spark_configured: bool = False,
        fail_probe: bool = False,
    ) -> None:
        program = f"""\
#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import sys

state_path = Path({str(self.state)!r})
if sys.argv[1] == "probe":
    if {fail_probe!r}:
        raise SystemExit(9)
    state = json.loads(state_path.read_text())
    body = {{
        "schema_version": 2,
        "observed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "harnesses": {{"codex": {{"available": True, "binary": "/fake/codex"}}}} if {spark_configured!r} else {{}},
        "providers": {{"codex": {{"available": True, "models": {["gpt-5.3-codex-spark"] if spark_configured else []!r}}}}},
        "verified_quota_pools": [],
        "api_key_environment_scrubbed": {list(TEST_SCRUBBED_ENV)!r},
        "model_invocations": 0,
        "paid_api_requests_authorized": 0,
    }}
    digest_fields = (
        "schema_version",
        "observed_at",
        "harnesses",
        "providers",
        "verified_quota_pools",
        "api_key_environment_scrubbed",
        "model_invocations",
        "paid_api_requests_authorized",
    )
    canonical = json.dumps(
        {{field: body[field] for field in digest_fields}},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    body["catalog_probe_sha256"] = hmac.new(
        b"grabowski-coding-agent-probe-v3", canonical, hashlib.sha256
    ).hexdigest()
    if {tamper_digest!r}:
        body["catalog_probe_sha256"] = "0" * 64
    state["catalog"] = body
    state["updated_at"] = body["observed_at"]
    if {mutate_history!r}:
        state["history"] = {{"changed": True}}
    temporary = state_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state))
    os.replace(temporary, state_path)
    print(json.dumps(body))
elif sys.argv[1] == "set-quota":
    state = json.loads(state_path.read_text())
    def value(name):
        return sys.argv[sys.argv.index(name) + 1]
    pool_id = value("--pool")
    status = value("--status")
    pool = state.setdefault("pools", {{}}).setdefault(pool_id, {{}})
    if status in {{"unknown", "available"}}:
        for field in ("blocked_reason", "cooldown_until", "remaining_ratio", "reset_at"):
            pool.pop(field, None)
    pool["status"] = status
    if "--remaining-ratio" in sys.argv:
        pool["remaining_ratio"] = float(value("--remaining-ratio"))
    if "--reset-at" in sys.argv:
        pool["reset_at"] = value("--reset-at")
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if "--verified-now" in sys.argv:
        pool["verified_at"] = now
    pool["updated_at"] = now
    state["updated_at"] = now
    temporary = state_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state))
    os.replace(temporary, state_path)
    print(json.dumps({{"updated": True, "pool": pool_id, "pool_state": pool}}))
elif sys.argv[1] == "status":
    state = json.loads(state_path.read_text())
    print(json.dumps({{
        "schema_version": 2,
        "catalog_fresh": True,
        "automatic_execution_authorized": False,
        "pools": state.get("pools", {{}}),
    }}))
else:
    raise SystemExit(2)
"""
        self.router.write_text(textwrap.dedent(program), encoding="utf-8")
        os.chmod(self.router, 0o700)
        digest = hashlib.sha256(self.router.read_bytes()).hexdigest()
        self.router_digest.write_text(digest + "\n", encoding="ascii")
        os.chmod(self.router_digest, 0o600)

    def arguments(self) -> list[str]:
        return [
            "--router",
            str(self.router),
            "--router-sha256-file",
            str(self.router_digest),
            "--state",
            str(self.state),
            "--lock",
            str(self.lock),
            "--receipt",
            str(self.receipt),
            "--failure",
            str(self.failure),
            "--codex-sessions-root",
            str(self.codex_sessions),
            "--timeout-seconds",
            "10",
        ]

    def write_codex_quota_receipt(
        self,
        *,
        observed_at: datetime,
        used_percent: float,
        reset_at: datetime,
        mode: int = 0o600,
        filename: str = "rollout-test.jsonl",
    ) -> Path:
        day = self.codex_sessions / observed_at.strftime("%Y/%m/%d")
        day.mkdir(parents=True, exist_ok=True)
        event = {
            "timestamp": observed_at.isoformat().replace("+00:00", "Z"),
            "type": "event_msg",
            "payload": {
                "type": "token_count",
                "info": None,
                "rate_limits": {
                    "limit_id": "codex",
                    "limit_name": None,
                    "plan_type": "prolite",
                    "primary": {
                        "used_percent": used_percent,
                        "window_minutes": 10080,
                        "resets_at": int(reset_at.timestamp()),
                    },
                    "secondary": None,
                    "individual_limit": None,
                    "rate_limit_reached_type": None,
                    "spend_control_reached": None,
                    "credits": {
                        "balance": "0",
                        "has_credits": False,
                        "unlimited": False,
                    },
                },
            },
        }
        path = day / filename
        path.write_text(json.dumps(event) + "\n", encoding="utf-8")
        os.chmod(path, mode)
        return path

    def test_collect_codex_quota_uses_freshest_valid_provider_receipt(self) -> None:
        now = datetime(2026, 8, 2, 8, 0, tzinfo=timezone.utc)
        self.write_codex_quota_receipt(
            observed_at=now - timedelta(hours=2),
            used_percent=40,
            reset_at=now + timedelta(days=6),
            filename="rollout-older.jsonl",
        )
        self.write_codex_quota_receipt(
            observed_at=now - timedelta(minutes=5),
            used_percent=97,
            reset_at=now + timedelta(days=5),
            filename="rollout-newer.jsonl",
        )
        observation = SCHEDULER.collect_codex_quota_observation(
            self.codex_sessions, now=now
        )
        self.assertEqual("available", observation["status"])
        self.assertEqual(0.03, observation["remaining_ratio"])
        self.assertEqual(97.0, observation["used_percent"])
        self.assertEqual("prolite", observation["plan_type"])
        self.assertFalse(observation["purchased_credits_available"])
        self.assertFalse(observation["paid_fallback_authorized"])
        self.assertEqual(0, observation["model_invocations"])
        self.assertRegex(observation["observation_sha256"], r"^[0-9a-f]{64}$")

    def test_codex_quota_event_uses_most_restrictive_window(self) -> None:
        now = datetime(2026, 8, 2, 8, 0, tzinfo=timezone.utc)
        observed_at = now - timedelta(minutes=1)
        event = {
            "timestamp": observed_at.isoformat().replace("+00:00", "Z"),
            "type": "event_msg",
            "payload": {
                "rate_limits": {
                    "limit_id": "codex",
                    "primary": {
                        "used_percent": 99,
                        "window_minutes": 300,
                        "resets_at": int((now + timedelta(hours=1)).timestamp()),
                    },
                    "secondary": {
                        "used_percent": 64,
                        "window_minutes": 10080,
                        "resets_at": int((now + timedelta(days=5)).timestamp()),
                    },
                    "individual_limit": None,
                }
            },
        }
        observation = SCHEDULER._codex_quota_event(
            event, now=now, line_sha256="c" * 64
        )
        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual("primary", observation["limiting_window"])
        self.assertEqual(0.01, observation["remaining_ratio"])
        self.assertEqual(2, len(observation["limits"]))

        event["payload"]["rate_limits"]["primary"]["used_percent"] = 100
        event["payload"]["rate_limits"]["secondary"]["used_percent"] = 100
        tied = SCHEDULER._codex_quota_event(
            event, now=now, line_sha256="d" * 64
        )
        self.assertIsNotNone(tied)
        assert tied is not None
        self.assertEqual("exhausted", tied["status"])
        self.assertEqual("secondary", tied["limiting_window"])
        self.assertEqual(
            (now + timedelta(days=5)).isoformat().replace("+00:00", "Z"),
            tied["reset_at"],
        )

    def test_collect_codex_quota_marks_full_usage_exhausted(self) -> None:
        now = datetime(2026, 8, 2, 8, 0, tzinfo=timezone.utc)
        self.write_codex_quota_receipt(
            observed_at=now - timedelta(minutes=3),
            used_percent=100,
            reset_at=now + timedelta(days=5),
        )
        observation = SCHEDULER.collect_codex_quota_observation(
            self.codex_sessions, now=now
        )
        self.assertEqual("exhausted", observation["status"])
        self.assertEqual(0.0, observation["remaining_ratio"])
        self.assertFalse(observation["paid_fallback_authorized"])

    def test_codex_quota_event_rejects_overflow_and_implausible_reset(self) -> None:
        now = datetime(2026, 8, 2, 8, 0, tzinfo=timezone.utc)
        base = {
            "timestamp": (now - timedelta(minutes=1)).isoformat().replace(
                "+00:00", "Z"
            ),
            "type": "event_msg",
            "payload": {
                "rate_limits": {
                    "limit_id": "codex",
                    "primary": {
                        "used_percent": 50,
                        "window_minutes": 10080,
                        "resets_at": 10**30,
                    },
                }
            },
        }
        self.assertIsNone(
            SCHEDULER._codex_quota_event(
                base, now=now, line_sha256="a" * 64
            )
        )
        base["payload"]["rate_limits"]["primary"]["resets_at"] = int(
            (now + timedelta(days=20)).timestamp()
        )
        self.assertIsNone(
            SCHEDULER._codex_quota_event(
                base, now=now, line_sha256="b" * 64
            )
        )

    def test_collect_codex_quota_rejects_writable_sessions_directory(self) -> None:
        os.chmod(self.codex_sessions, 0o777)
        observation = SCHEDULER.collect_codex_quota_observation(
            self.codex_sessions,
            now=datetime(2026, 8, 2, 8, 0, tzinfo=timezone.utc),
        )
        self.assertEqual("unknown", observation["status"])
        self.assertEqual("no_fresh_provider_quota_receipt", observation["reason"])

    def test_collect_codex_quota_bounds_directory_enumeration(self) -> None:
        for name in ("a", "b", "c"):
            (self.codex_sessions / name).write_text("x", encoding="utf-8")
        with mock.patch.object(SCHEDULER, "MAX_CODEX_DIRECTORY_ENTRIES", 2):
            observation = SCHEDULER.collect_codex_quota_observation(
                self.codex_sessions,
                now=datetime(2026, 8, 2, 8, 0, tzinfo=timezone.utc),
            )
        self.assertEqual("unknown", observation["status"])
        self.assertEqual("no_fresh_provider_quota_receipt", observation["reason"])

    def test_collect_codex_quota_ignores_stale_and_unsafe_receipts(self) -> None:
        now = datetime(2026, 8, 2, 8, 0, tzinfo=timezone.utc)
        self.write_codex_quota_receipt(
            observed_at=now - timedelta(days=3),
            used_percent=99,
            reset_at=now + timedelta(days=4),
            filename="rollout-stale.jsonl",
        )
        self.write_codex_quota_receipt(
            observed_at=now - timedelta(minutes=1),
            used_percent=1,
            reset_at=now + timedelta(days=6),
            mode=0o644,
            filename="rollout-unsafe.jsonl",
        )
        observation = SCHEDULER.collect_codex_quota_observation(
            self.codex_sessions, now=now
        )
        self.assertEqual("unknown", observation["status"])
        self.assertEqual("no_fresh_provider_quota_receipt", observation["reason"])

    @staticmethod
    def direct_codex_results(
        *, spark_used_percent: float = 0.0, spark_credits: object = None
    ) -> tuple[dict[str, object], dict[str, object]]:
        reset_main = 1787197929
        reset_spark = 1787774582
        model_result = {
            "data": [
                {
                    "id": SCHEDULER.CODEX_SPARK_MODEL,
                    "model": SCHEDULER.CODEX_SPARK_MODEL,
                    "displayName": SCHEDULER.CODEX_SPARK_LIMIT_NAME,
                    "hidden": False,
                    "supportedReasoningEfforts": [
                        {"reasoningEffort": "low", "description": "Fast"},
                        {"reasoningEffort": "medium", "description": "Balanced"},
                        {"reasoningEffort": "high", "description": "Deep"},
                        {"reasoningEffort": "xhigh", "description": "Extra deep"},
                    ],
                }
            ]
        }
        rate_result = {
            "rateLimitsByLimitId": {
                "codex": {
                    "limitId": "codex",
                    "limitName": None,
                    "planType": "prolite",
                    "primary": {
                        "usedPercent": 100.0,
                        "resetsAt": reset_main,
                        "windowDurationMins": 300,
                    },
                    "secondary": None,
                    "credits": {"hasCredits": False, "unlimited": False},
                    "rateLimitReachedType": "rate_limit_reached",
                },
                SCHEDULER.CODEX_SPARK_LIMIT_ID: {
                    "limitId": SCHEDULER.CODEX_SPARK_LIMIT_ID,
                    "limitName": SCHEDULER.CODEX_SPARK_LIMIT_NAME,
                    "planType": "prolite",
                    "primary": {
                        "usedPercent": spark_used_percent,
                        "resetsAt": reset_spark,
                        "windowDurationMins": 10080,
                    },
                    "secondary": None,
                    "credits": spark_credits,
                    "rateLimitReachedType": None,
                },
            },
            "rateLimitResetCredits": {"availableCount": 0},
        }
        return model_result, rate_result

    def test_codex_app_server_parser_binds_separate_spark_pool(self) -> None:
        model_result, rate_result = self.direct_codex_results()
        observations = SCHEDULER.parse_codex_app_server_observations(
            model_result,
            rate_result,
            observed_at="2026-08-19T20:04:35Z",
        )
        main = observations[SCHEDULER.CODEX_QUOTA_POOL]
        spark = observations[SCHEDULER.CODEX_SPARK_QUOTA_POOL]
        self.assertEqual("exhausted", main["status"])
        self.assertEqual(0.0, main["remaining_ratio"])
        self.assertEqual("available", spark["status"])
        self.assertEqual(1.0, spark["remaining_ratio"])
        self.assertEqual("prolite", spark["plan_type"])
        self.assertEqual(SCHEDULER.CODEX_SPARK_LIMIT_ID, spark["provider_limit_id"])
        self.assertFalse(spark["paid_fallback_authorized"])
        self.assertEqual(0, spark["model_invocations"])

    def test_codex_app_server_collector_uses_metadata_only_stdio_protocol(self) -> None:
        model_result, rate_result = self.direct_codex_results()
        fake_codex = self.root / "codex-app-server-fake"
        source_codex_home = self.root / "codex-home"
        source_codex_home.mkdir(mode=0o700)
        (source_codex_home / "auth.json").write_text("{}", encoding="utf-8")
        (source_codex_home / "config.toml").write_text("model = \"test\"\n", encoding="utf-8")
        os.chmod(source_codex_home / "auth.json", 0o600)
        os.chmod(source_codex_home / "config.toml", 0o600)
        program = f"""\
#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
MODEL = {model_result!r}
RATE = {rate_result!r}
home = Path(os.environ["CODEX_HOME"])
assert os.environ["CODEX_SQLITE_HOME"] == str(home)
assert home.is_dir()
assert (home / "auth.json").is_symlink()
assert (home / "config.toml").is_symlink()
assert (home / "auth.json").read_text() == "{{}}"
assert "model" in (home / "config.toml").read_text()
assert os.readlink(home / "auth.json").startswith("/proc/self/fd/")
assert os.readlink(home / "config.toml").startswith("/proc/self/fd/")
(home / "state_5.sqlite").write_text("temporary-state")
for line in sys.stdin:
    value = json.loads(line)
    method = value.get("method")
    if method == "initialized":
        continue
    response_id = value.get("id")
    if method == "initialize":
        result = {{}}
    elif method == "model/list":
        result = MODEL
    elif method == "account/rateLimits/read":
        result = RATE
    else:
        print(json.dumps({{"id": response_id, "error": {{"message": "unexpected"}}}}), flush=True)
        continue
    print(json.dumps({{"id": response_id, "result": result}}), flush=True)
"""
        fake_codex.write_text(textwrap.dedent(program), encoding="utf-8")
        os.chmod(fake_codex, 0o700)

        observations = SCHEDULER.collect_codex_app_server_observations(
            fake_codex,
            environment=SCHEDULER.sanitized_environment(),
            timeout_seconds=3,
            state_directory=self.root,
            source_codex_home=source_codex_home,
        )

        self.assertEqual("exhausted", observations[SCHEDULER.CODEX_QUOTA_POOL]["status"])
        self.assertEqual(
            "available", observations[SCHEDULER.CODEX_SPARK_QUOTA_POOL]["status"]
        )
        self.assertEqual(
            0, observations[SCHEDULER.CODEX_SPARK_QUOTA_POOL]["model_invocations"]
        )
        self.assertFalse(
            observations[SCHEDULER.CODEX_SPARK_QUOTA_POOL]["paid_fallback_authorized"]
        )
        self.assertEqual(
            [],
            [item.name for item in self.root.iterdir() if item.name.startswith(".codex-metadata-")],
        )

    def test_codex_app_server_parser_rejects_nonbaseline_spark_evidence(self) -> None:
        cases = []
        model_result, rate_result = self.direct_codex_results()
        hidden_model = json.loads(json.dumps(model_result))
        hidden_model["data"][0]["hidden"] = True
        cases.append((hidden_model, rate_result))
        model_result, rate_result = self.direct_codex_results(spark_credits={})
        cases.append((model_result, rate_result))
        model_result, rate_result = self.direct_codex_results()
        mismatched_plan = json.loads(json.dumps(rate_result))
        mismatched_plan["rateLimitsByLimitId"][SCHEDULER.CODEX_SPARK_LIMIT_ID][
            "planType"
        ] = "enterprise"
        cases.append((model_result, mismatched_plan))
        model_result, rate_result = self.direct_codex_results()
        reset_credits = json.loads(json.dumps(rate_result))
        reset_credits["rateLimitResetCredits"]["availableCount"] = 1
        cases.append((model_result, reset_credits))
        for candidate_model, candidate_rate in cases:
            with self.subTest(candidate_rate=candidate_rate):
                with self.assertRaises(SCHEDULER.ProbeSchedulerError):
                    SCHEDULER.parse_codex_app_server_observations(
                        candidate_model, candidate_rate
                    )

    def test_scheduler_updates_main_and_spark_from_direct_provider_metadata(self) -> None:
        self.write_router(spark_configured=True)
        model_result, rate_result = self.direct_codex_results()
        direct = SCHEDULER.parse_codex_app_server_observations(
            model_result,
            rate_result,
            observed_at="2026-08-19T20:04:35Z",
        )
        with mock.patch.object(
            SCHEDULER,
            "collect_codex_app_server_observations",
            return_value=direct,
        ):
            result = SCHEDULER.main(self.arguments())
        self.assertEqual(0, result)
        after = json.loads(self.state.read_text(encoding="utf-8"))
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        self.assertEqual("exhausted", after["pools"][SCHEDULER.CODEX_QUOTA_POOL]["status"])
        spark = after["pools"][SCHEDULER.CODEX_SPARK_QUOTA_POOL]
        self.assertEqual("available", spark["status"])
        self.assertEqual(1.0, spark["remaining_ratio"])
        self.assertEqual(
            "fresh_provider_observation",
            receipt["quota_updates"][SCHEDULER.CODEX_SPARK_QUOTA_POOL]["reason"],
        )
        self.assertTrue(receipt["spark_configured"])
        self.assertEqual(0, receipt["model_invocations"])
        self.assertEqual(0, receipt["paid_api_requests_authorized"])

    def test_scheduler_clears_stale_spark_when_direct_metadata_is_unavailable(self) -> None:
        now = datetime.now(timezone.utc)
        self.initial["pools"][SCHEDULER.CODEX_SPARK_QUOTA_POOL] = {
            "status": "available",
            "remaining_ratio": 0.8,
            "reset_at": (now + timedelta(days=1))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "verified_at": (now - timedelta(minutes=1))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        self.state.write_text(json.dumps(self.initial), encoding="utf-8")
        self.write_router(spark_configured=True)
        direct = {
            SCHEDULER.CODEX_QUOTA_POOL: SCHEDULER._unknown_codex_direct_observation(
                SCHEDULER.CODEX_QUOTA_POOL, "test-unavailable"
            ),
            SCHEDULER.CODEX_SPARK_QUOTA_POOL: SCHEDULER._unknown_codex_direct_observation(
                SCHEDULER.CODEX_SPARK_QUOTA_POOL, "test-unavailable"
            ),
        }
        with mock.patch.object(
            SCHEDULER,
            "collect_codex_app_server_observations",
            return_value=direct,
        ):
            result = SCHEDULER.main(self.arguments())
        self.assertEqual(0, result)
        after = json.loads(self.state.read_text(encoding="utf-8"))
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        spark = after["pools"][SCHEDULER.CODEX_SPARK_QUOTA_POOL]
        self.assertEqual("unknown", spark["status"])
        self.assertNotIn("remaining_ratio", spark)
        self.assertNotIn("reset_at", spark)
        self.assertEqual({}, receipt["quota_updates"])
        self.assertEqual(
            "provider_metadata_refresh_started_to_unknown",
            receipt["spark_preclear"]["reason"],
        )

    def test_scheduler_preclears_spark_before_later_probe_failure(self) -> None:
        now = datetime.now(timezone.utc)
        self.initial["pools"][SCHEDULER.CODEX_SPARK_QUOTA_POOL] = {
            "status": "available",
            "remaining_ratio": 0.9,
            "reset_at": (now + timedelta(days=1))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "verified_at": (now - timedelta(minutes=1))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        self.state.write_text(json.dumps(self.initial), encoding="utf-8")
        self.write_router(spark_configured=True, fail_probe=True)
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(1, result)
        after = json.loads(self.state.read_text(encoding="utf-8"))
        spark = after["pools"][SCHEDULER.CODEX_SPARK_QUOTA_POOL]
        self.assertEqual("unknown", spark["status"])
        self.assertNotIn("remaining_ratio", spark)
        self.assertNotIn("reset_at", spark)
        failure = json.loads(self.failure.read_text(encoding="utf-8"))
        self.assertEqual("failed", failure["status"])
        self.assertEqual(0, failure["model_invocations"])
        self.assertEqual(0, failure["paid_api_requests_authorized"])

    def test_scheduler_applies_exact_codex_quota_without_paid_fallback(self) -> None:
        now = datetime.now(timezone.utc)
        reset_at = now + timedelta(days=5)
        self.write_codex_quota_receipt(
            observed_at=now - timedelta(minutes=2),
            used_percent=97,
            reset_at=reset_at,
        )
        self.write_router()
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(0, result)
        after = json.loads(self.state.read_text(encoding="utf-8"))
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        pool = after["pools"][SCHEDULER.CODEX_QUOTA_POOL]
        self.assertEqual("available", pool["status"])
        self.assertEqual(0.03, pool["remaining_ratio"])
        self.assertEqual(
            reset_at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            pool["reset_at"],
        )
        self.assertTrue(receipt["quota_state_updated"])
        self.assertEqual("fresh_provider_observation", receipt["quota_update_reason"])
        self.assertEqual(0.03, receipt["quota_observation"]["remaining_ratio"])
        self.assertFalse(
            receipt["quota_observation"]["paid_fallback_authorized"]
        )
        self.assertEqual(0, receipt["model_invocations"])
        self.assertEqual(0, receipt["paid_api_requests_authorized"])

    def test_scheduler_clears_expired_quota_to_unknown(self) -> None:
        now = datetime.now(timezone.utc)
        self.initial["pools"][SCHEDULER.CODEX_QUOTA_POOL] = {
            "status": "exhausted",
            "remaining_ratio": 0.0,
            "reset_at": (now - timedelta(minutes=1))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "verified_at": (now - timedelta(days=1))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        self.state.write_text(json.dumps(self.initial), encoding="utf-8")
        self.write_router()
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(0, result)
        after = json.loads(self.state.read_text(encoding="utf-8"))
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        pool = after["pools"][SCHEDULER.CODEX_QUOTA_POOL]
        self.assertEqual("unknown", pool["status"])
        self.assertNotIn("remaining_ratio", pool)
        self.assertNotIn("reset_at", pool)
        self.assertTrue(receipt["quota_state_updated"])
        self.assertEqual("expired_reset_to_unknown", receipt["quota_update_reason"])
        self.assertEqual("unknown", receipt["quota_observation"]["status"])

    def test_scheduler_unknown_quota_preserves_existing_pool_state(self) -> None:
        now = datetime.now(timezone.utc)
        self.initial["pools"][SCHEDULER.CODEX_QUOTA_POOL] = {
            "status": "available",
            "remaining_ratio": 0.42,
            "reset_at": (now + timedelta(days=1))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "verified_at": (now - timedelta(minutes=1))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        self.state.write_text(json.dumps(self.initial), encoding="utf-8")
        self.write_router()
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(0, result)
        after = json.loads(self.state.read_text(encoding="utf-8"))
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        self.assertEqual(
            self.initial["pools"][SCHEDULER.CODEX_QUOTA_POOL],
            after["pools"][SCHEDULER.CODEX_QUOTA_POOL],
        )
        self.assertFalse(receipt["quota_state_updated"])
        self.assertEqual("unknown", receipt["quota_observation"]["status"])

    def test_success_preserves_history_scrubs_keys_and_writes_readback_receipt(
        self,
    ) -> None:
        self.write_router()
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(0, result)
        after = json.loads(self.state.read_text(encoding="utf-8"))
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        self.assertEqual(self.initial["history"], after["history"])
        self.assertEqual("ok", receipt["status"])
        self.assertTrue(receipt["status_readback"]["catalog_fresh"])
        self.assertFalse(receipt["status_readback"]["automatic_execution_authorized"])
        self.assertEqual(0, receipt["model_invocations"])
        self.assertEqual(0, receipt["paid_api_requests_authorized"])
        self.assertEqual(
            len(SCHEDULER.FORBIDDEN_API_KEY_ENV),
            receipt["api_key_environment_removed_count"],
        )
        self.assertFalse(self.failure.exists())

    def test_probe_validation_rejects_plain_sha256_without_domain_binding(self) -> None:
        probe = {
            "schema_version": 2,
            "observed_at": SCHEDULER.iso_now(),
            "harnesses": {},
            "providers": {},
            "verified_quota_pools": [],
            "api_key_environment_scrubbed": list(TEST_SCRUBBED_ENV),
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        canonical = json.dumps(
            {field: probe[field] for field in SCHEDULER.PROBE_DIGEST_FIELDS},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        probe["catalog_probe_sha256"] = hashlib.sha256(canonical).hexdigest()
        with self.assertRaisesRegex(
            SCHEDULER.ProbeSchedulerError, "digest does not match"
        ):
            SCHEDULER.validate_probe(probe)

    def test_probe_validation_rejects_tampered_scrub_claim_outside_digest(self) -> None:
        probe = {
            "schema_version": 2,
            "observed_at": SCHEDULER.iso_now(),
            "harnesses": {},
            "providers": {},
            "verified_quota_pools": [],
            "api_key_environment_scrubbed": list(TEST_SCRUBBED_ENV),
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        digest = SCHEDULER.probe_digest(probe)
        probe["catalog_probe_sha256"] = digest
        probe["api_key_environment_scrubbed"] = ["ROUTER_AUTH_ENV_A"]
        self.assertNotEqual(digest, SCHEDULER.probe_digest(probe))
        with self.assertRaisesRegex(SCHEDULER.ProbeSchedulerError, "digest does not match"):
            SCHEDULER.validate_probe(probe)

    def test_probe_validation_rejects_invalid_verified_pool_claims(self) -> None:
        base = {
            "schema_version": 2,
            "observed_at": SCHEDULER.iso_now(),
            "harnesses": {},
            "providers": {},
            "api_key_environment_scrubbed": list(TEST_SCRUBBED_ENV),
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        for value in (
            ["grok-com", "grok-com"],
            ["unknown"],
            [{"pool": "grok-com"}],
        ):
            with self.subTest(value=value):
                probe = {**base, "verified_quota_pools": value}
                probe["catalog_probe_sha256"] = SCHEDULER.probe_digest(probe)
                with self.assertRaisesRegex(
                    SCHEDULER.ProbeSchedulerError, "verified_quota_pools"
                ):
                    SCHEDULER.validate_probe(probe)

    def test_probe_validation_rejects_unknown_fields_and_nonzero_execution_claims(self) -> None:
        base = {
            "schema_version": 2,
            "observed_at": SCHEDULER.iso_now(),
            "harnesses": {},
            "providers": {},
            "verified_quota_pools": [],
            "api_key_environment_scrubbed": list(TEST_SCRUBBED_ENV),
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        unknown = {**base, "password": "must-not-be-stored"}
        unknown["catalog_probe_sha256"] = SCHEDULER.probe_digest(base)
        with self.assertRaisesRegex(SCHEDULER.ProbeSchedulerError, "exact metadata-only schema"):
            SCHEDULER.validate_probe(unknown)
        for field in ("model_invocations", "paid_api_requests_authorized"):
            with self.subTest(field=field):
                probe = {**base, field: 1}
                probe["catalog_probe_sha256"] = SCHEDULER.probe_digest(probe)
                with self.assertRaisesRegex(SCHEDULER.ProbeSchedulerError, f"{field} must be integer zero"):
                    SCHEDULER.validate_probe(probe)

    def test_state_validation_preserves_same_catalog_and_adds_only_verified_time(self) -> None:
        probe = {
            "schema_version": 2,
            "observed_at": "2026-07-20T11:00:00Z",
            "harnesses": {},
            "providers": {},
            "verified_quota_pools": ["opencode-free", "openhands-account"],
            "api_key_environment_scrubbed": list(TEST_SCRUBBED_ENV),
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        probe["catalog_probe_sha256"] = SCHEDULER.probe_digest(probe)
        before = {
            **self.initial,
            "pools": {
                "pool": {"status": "available"},
                "grok-com": {
                    "status": "unknown",
                    "verified_at": "2026-07-19T00:00:00Z",
                },
                "jules-account": {
                    "status": "unknown",
                    "verified_at": "2026-07-19T00:00:00Z",
                },
                "opencode-free": {"status": "unknown"},
                "openhands-account": {"status": "unknown"},
            },
        }
        after = json.loads(json.dumps(before))
        after["catalog"] = probe
        after["pools"]["grok-com"].pop("verified_at")
        after["pools"]["jules-account"].pop("verified_at")
        after["pools"]["opencode-free"]["verified_at"] = probe["observed_at"]
        after["pools"]["openhands-account"]["verified_at"] = probe["observed_at"]
        SCHEDULER.validate_state_after_probe(before, after, probe)

        tampered = json.loads(json.dumps(after))
        tampered["pools"]["pool"]["status"] = "blocked"
        with self.assertRaisesRegex(
            SCHEDULER.ProbeSchedulerError, "beyond verified timestamps"
        ):
            SCHEDULER.validate_state_after_probe(before, tampered, probe)

    def test_probe_validation_accepts_all_canonical_verified_pools(self) -> None:
        probe = {
            "schema_version": 2,
            "observed_at": SCHEDULER.iso_now(),
            "harnesses": {},
            "providers": {},
            "verified_quota_pools": list(SCHEDULER.PROBE_VERIFIABLE_QUOTA_POOLS),
            "api_key_environment_scrubbed": list(TEST_SCRUBBED_ENV),
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        probe["catalog_probe_sha256"] = SCHEDULER.probe_digest(probe)
        SCHEDULER.validate_probe(probe)

    def test_state_validation_requires_exact_reset_after_catalog_change(self) -> None:
        probe = {
            "schema_version": 2,
            "observed_at": "2026-07-20T11:00:00Z",
            "harnesses": {},
            "providers": {},
            "verified_quota_pools": ["jules-account"],
            "api_key_environment_scrubbed": list(TEST_SCRUBBED_ENV),
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        probe["catalog_probe_sha256"] = SCHEDULER.probe_digest(probe)
        after = {
            "schema_version": 2,
            "updated_at": probe["observed_at"],
            "catalog_sha256": "new-catalog",
            "catalog": probe,
            "pools": {
                "jules-account": {"verified_at": probe["observed_at"]}
            },
            "routes": {},
            "history": self.initial["history"],
        }
        SCHEDULER.validate_state_after_probe(self.initial, after, probe)

        stale_routes = json.loads(json.dumps(after))
        stale_routes["routes"] = self.initial["routes"]
        with self.assertRaisesRegex(
            SCHEDULER.ProbeSchedulerError, "reset route history"
        ):
            SCHEDULER.validate_state_after_probe(self.initial, stale_routes, probe)

        stale_pools = json.loads(json.dumps(after))
        stale_pools["pools"]["pool"] = self.initial["pools"]["pool"]
        with self.assertRaisesRegex(
            SCHEDULER.ProbeSchedulerError, "reset pool state"
        ):
            SCHEDULER.validate_state_after_probe(self.initial, stale_pools, probe)

    def test_history_mutation_fails_closed_and_records_bounded_failure(self) -> None:
        self.write_router(mutate_history=True)
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(1, result)
        failure = json.loads(self.failure.read_text(encoding="utf-8"))
        self.assertEqual("failed", failure["status"])
        self.assertEqual("ProbeSchedulerError", failure["error_type"])
        self.assertEqual("probe_scheduler_failed_closed", failure["error"])
        self.assertFalse(self.receipt.exists())

    def test_router_digest_mismatch_fails_before_execution(self) -> None:
        self.write_router()
        before = self.state.read_bytes()
        self.router_digest.write_text("0" * 64 + "\n", encoding="ascii")
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(1, result)
        self.assertEqual(before, self.state.read_bytes())
        failure = json.loads(self.failure.read_text(encoding="utf-8"))
        self.assertEqual("ProbeSchedulerError", failure["error_type"])
        self.assertEqual("probe_scheduler_failed_closed", failure["error"])
        self.assertFalse(self.receipt.exists())

    def test_tampered_probe_digest_fails_closed(self) -> None:
        self.write_router(tamper_digest=True)
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(1, result)
        failure = json.loads(self.failure.read_text(encoding="utf-8"))
        self.assertEqual("ProbeSchedulerError", failure["error_type"])
        self.assertEqual("probe_scheduler_failed_closed", failure["error"])
        self.assertFalse(self.receipt.exists())

    def test_probe_digest_safety_guard_rejects_sensitive_fields(self) -> None:
        with self.assertRaisesRegex(
            SCHEDULER.ProbeSchedulerError,
            r"sensitive field: providers\.claude\.auth\.password",
        ):
            SCHEDULER.assert_probe_digest_safe(
                {"providers": {"claude": {"auth": {"password": "redacted"}}}}
            )
        for sensitive_field in ("token_hint", "auth_secret", "credential_value"):
            with self.subTest(sensitive_field=sensitive_field):
                with self.assertRaisesRegex(
                    SCHEDULER.ProbeSchedulerError, "sensitive field"
                ):
                    SCHEDULER.assert_probe_digest_safe({sensitive_field: "redacted"})
        SCHEDULER.assert_probe_digest_safe(
            {
                "api_key_environment_scrubbed": ["ROUTER_AUTH_ENV_A"],
                "context_token_count": 4096,
            }
        )

    def test_lock_contention_is_a_clean_noop(self) -> None:
        self.write_router()
        descriptor = os.open(self.lock, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = SCHEDULER.main(self.arguments())
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        self.assertEqual(0, result)
        self.assertFalse(self.receipt.exists())
        self.assertFalse(self.failure.exists())

    def test_router_special_mode_bits_fail_before_execution(self) -> None:
        for special_bit in (stat.S_ISUID, stat.S_ISGID, stat.S_ISVTX):
            with self.subTest(special_bit=oct(special_bit)):
                self.write_router()
                os.chmod(self.router, 0o700 | special_bit)
                before = self.state.read_bytes()
                result = SCHEDULER.main(self.arguments())
                self.assertEqual(1, result)
                self.assertEqual(before, self.state.read_bytes())
                self.assertFalse(self.receipt.exists())
                self.failure.unlink(missing_ok=True)

    def test_router_digest_pin_special_mode_bits_fail_closed(self) -> None:
        for special_bit in (stat.S_ISUID, stat.S_ISGID, stat.S_ISVTX):
            with self.subTest(special_bit=oct(special_bit)):
                self.write_router()
                os.chmod(self.router_digest, 0o600 | special_bit)
                before = self.state.read_bytes()
                result = SCHEDULER.main(self.arguments())
                self.assertEqual(1, result)
                self.assertEqual(before, self.state.read_bytes())
                self.assertFalse(self.receipt.exists())
                self.failure.unlink(missing_ok=True)

    def test_router_symlink_is_rejected_before_execution(self) -> None:
        self.write_router()
        real_router = self.root / "agent-route.real"
        self.router.replace(real_router)
        self.router.symlink_to(real_router)
        before = self.state.read_bytes()
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(1, result)
        self.assertEqual(before, self.state.read_bytes())
        self.assertFalse(self.receipt.exists())

    def test_state_symlink_is_rejected_before_execution(self) -> None:
        self.write_router()
        real_state = self.root / "state.real.json"
        self.state.replace(real_state)
        self.state.symlink_to(real_state)
        before = real_state.read_bytes()
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(1, result)
        self.assertEqual(before, real_state.read_bytes())
        self.assertFalse(self.receipt.exists())
        self.assertTrue(self.failure.exists())

    def test_router_digest_pin_directory_fails_before_execution(self) -> None:
        self.write_router()
        before = self.state.read_bytes()
        self.router_digest.unlink()
        self.router_digest.mkdir()
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(1, result)
        self.assertEqual(before, self.state.read_bytes())
        self.assertFalse(self.receipt.exists())
        self.assertTrue(self.failure.exists())

    def test_unreadable_state_fails_closed(self) -> None:
        self.write_router()
        os.chmod(self.state, 0o000)
        try:
            result = SCHEDULER.main(self.arguments())
        finally:
            os.chmod(self.state, 0o600)
        self.assertEqual(1, result)
        self.assertFalse(self.receipt.exists())
        self.assertTrue(self.failure.exists())

    def test_command_output_is_rejected_before_unbounded_buffering(self) -> None:
        environment = dict(os.environ)
        programs = {
            "stdout": "import sys; sys.stdout.write('x' * 4096)",
            "stderr": "import sys; sys.stderr.write('x' * 4096)",
        }
        for stream, program in programs.items():
            with (
                self.subTest(stream=stream),
                mock.patch.object(SCHEDULER, "MAX_COMMAND_OUTPUT_BYTES", 1024),
                self.assertRaisesRegex(
                    SCHEDULER.ProbeSchedulerError,
                    "command output exceeded the limit",
                ),
            ):
                SCHEDULER.run_json_command(
                    [sys.executable, "-c", program],
                    environment=environment,
                    timeout_seconds=5,
                )

    def test_command_timeout_terminates_the_child_process_group(self) -> None:
        started = time.monotonic()
        with self.assertRaisesRegex(
            SCHEDULER.ProbeSchedulerError,
            "command failed to execute",
        ):
            SCHEDULER.run_json_command(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                environment=dict(os.environ),
                timeout_seconds=1,
            )
        self.assertLess(time.monotonic() - started, 5)

    def test_termination_does_not_reap_leader_before_final_group_kill(self) -> None:
        process = mock.Mock()
        process.pid = 12345
        events: list[tuple[str, object]] = []
        process.wait.side_effect = lambda timeout: events.append(("wait", timeout))

        with (
            mock.patch.object(
                SCHEDULER.os,
                "killpg",
                side_effect=lambda process_group_id, sent_signal: events.append(
                    ("killpg", (process_group_id, sent_signal))
                ),
            ),
            mock.patch.object(
                SCHEDULER.time,
                "sleep",
                side_effect=lambda seconds: events.append(("sleep", seconds)),
            ),
        ):
            SCHEDULER.terminate_process_group(process)

        self.assertEqual(
            [
                ("killpg", (12345, signal.SIGTERM)),
                ("sleep", SCHEDULER.PROCESS_TERMINATION_GRACE_SECONDS),
                ("killpg", (12345, signal.SIGKILL)),
                ("wait", SCHEDULER.PROCESS_TERMINATION_GRACE_SECONDS),
            ],
            events,
        )

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux /proc")
    def test_termination_preserves_descendant_grace_after_leader_exit(self) -> None:
        child_pid_path = self.root / "graceful-child.pid"
        child_ready_path = self.root / "graceful-child.ready"
        cleanup_started_path = self.root / "cleanup.started"
        cleanup_completed_path = self.root / "cleanup.completed"
        child_program = "\n".join(
            (
                "from pathlib import Path",
                "import signal, sys, time",
                "ready, started, completed = map(Path, sys.argv[1:4])",
                "def handle(signum, frame):",
                "    started.write_text('1', encoding='ascii')",
                "    time.sleep(0.15)",
                "    completed.write_text('1', encoding='ascii')",
                "    raise SystemExit(0)",
                "signal.signal(signal.SIGTERM, handle)",
                "ready.write_text('1', encoding='ascii')",
                "time.sleep(30)",
            )
        )
        parent_program = "\n".join(
            (
                "from pathlib import Path",
                "import subprocess, sys, time",
                "pid_path, ready, started, completed = map(Path, sys.argv[1:5])",
                "child = subprocess.Popen(",
                "    [sys.executable, '-c', sys.argv[5], str(ready), str(started), str(completed)],",
                "    stdout=subprocess.DEVNULL,",
                "    stderr=subprocess.DEVNULL,",
                ")",
                "deadline = time.monotonic() + 5",
                "while not ready.exists():",
                "    if time.monotonic() >= deadline: raise SystemExit(3)",
                "    time.sleep(0.01)",
                "pid_path.write_text(str(child.pid), encoding='ascii')",
                "time.sleep(30)",
            )
        )
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                parent_program,
                str(child_pid_path),
                str(child_ready_path),
                str(cleanup_started_path),
                str(cleanup_completed_path),
                child_program,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        child_pid = None
        try:
            child_pid = self._wait_for_positive_pid(
                child_pid_path,
                timeout_seconds=5,
            )
            self.assertEqual(process.pid, os.getpgid(process.pid))
            with mock.patch.object(SCHEDULER, "PROCESS_TERMINATION_GRACE_SECONDS", 0.5):
                SCHEDULER.terminate_process_group(process)
            self.assertTrue(cleanup_started_path.exists())
            self.assertTrue(cleanup_completed_path.exists())
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
            if child_pid is not None and self._process_is_live(child_pid):
                os.kill(child_pid, signal.SIGKILL)

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux /proc")
    def test_timeout_kills_term_resistant_descendant_after_leader_exit(self) -> None:
        child_pid_path = self.root / "term-resistant-child.pid"
        program = "\n".join(
            (
                "from pathlib import Path",
                "import signal, subprocess, sys, time",
                "child = subprocess.Popen(",
                "    [sys.executable, '-c',",
                "     'import signal, time; '",
                "     'signal.signal(signal.SIGTERM, signal.SIG_IGN); '",
                "     'time.sleep(30)'],",
                "    stdout=subprocess.DEVNULL,",
                "    stderr=subprocess.DEVNULL,",
                ")",
                "Path(sys.argv[1]).write_text(str(child.pid), encoding='ascii')",
                "time.sleep(30)",
            )
        )
        child_pid = None
        try:
            with self.assertRaisesRegex(
                SCHEDULER.ProbeSchedulerError,
                "command failed to execute",
            ):
                SCHEDULER.run_json_command(
                    [sys.executable, "-c", program, str(child_pid_path)],
                    environment=dict(os.environ),
                    timeout_seconds=2,
                )
            child_pid = self._wait_for_positive_pid(
                child_pid_path,
                timeout_seconds=3,
            )
            deadline = time.monotonic() + 5
            while self._process_is_live(child_pid) and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertFalse(self._process_is_live(child_pid))
        finally:
            if child_pid is not None and self._process_is_live(child_pid):
                os.kill(child_pid, signal.SIGKILL)

    def test_output_reads_never_exceed_remaining_budget_plus_one(self) -> None:
        with mock.patch.object(SCHEDULER, "MAX_COMMAND_OUTPUT_BYTES", 1024):
            self.assertEqual(1025, SCHEDULER.bounded_output_read_size(0))
            self.assertEqual(25, SCHEDULER.bounded_output_read_size(1000))
            self.assertEqual(1, SCHEDULER.bounded_output_read_size(1024))
            self.assertEqual(1, SCHEDULER.bounded_output_read_size(2048))

    def test_invalid_command_json_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            SCHEDULER.ProbeSchedulerError,
            "command did not return JSON",
        ):
            SCHEDULER.run_json_command(
                [sys.executable, "-c", "print('not-json')"],
                environment=dict(os.environ),
                timeout_seconds=5,
            )

    def test_atomic_write_uses_private_mode_without_path_chmod(self) -> None:
        target = self.root / "nested" / "private.json"
        with mock.patch.object(
            SCHEDULER.os,
            "chmod",
            side_effect=AssertionError("path chmod is unsafe"),
        ):
            SCHEDULER.atomic_write_private(target, {"ok": True})
        self.assertEqual(0o600, stat.S_IMODE(target.stat().st_mode))
        self.assertEqual({"ok": True}, json.loads(target.read_text(encoding="utf-8")))

    def test_safe_unlink_tolerates_disappearance_after_lstat(self) -> None:
        target = self.root / "vanishing.json"
        target.write_text("{}", encoding="utf-8")
        with mock.patch.object(Path, "unlink", side_effect=FileNotFoundError):
            SCHEDULER.safe_unlink(target)


if __name__ == "__main__":
    unittest.main()

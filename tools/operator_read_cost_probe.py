#!/usr/bin/env python3
"""Bounded, synthetic audit cost probe; never opens operator state.

Uses the repository's test loaders. Fixture creation and validation are excluded
from timings. Each measured operation executes in a fresh interpreter. The
Python verification cache is cold; the OS page cache is not controlled.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from contextlib import ExitStack, contextmanager
import gc
import hashlib
import importlib
import json
import os
from pathlib import Path
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import threading
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CASES = ("verify", "snapshot", "query_limit1", "projection", "health_audit_only")


SOURCE_BINDING_FILES = ("grabowski_mcp.py", "grabowski_audit_query.py", "grabowski_read_surface.py")
TEST_LOADER_BINDING_FILES = ("test_operator_v2_runtime.py", "test_audit_segments.py", "test_read_surface.py")


def python_tree_sha256(directory):
    """Bind every regular import/input file, refusing symlinked source trees."""
    root = ROOT / directory
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("synthetic benchmark Python source tree is unsafe")
    digest = hashlib.sha256()
    count = total = 0

    def fail_walk(error):
        raise RuntimeError("synthetic benchmark source tree enumeration failed") from error

    for base, directories, files in os.walk(root, topdown=True, followlinks=False, onerror=fail_walk):
        current = Path(base)
        if not stat.S_ISDIR(current.lstat().st_mode):
            raise RuntimeError("synthetic benchmark Python source directory is unsafe")
        for name in sorted(directories):
            child = current / name
            if not stat.S_ISDIR(child.lstat().st_mode):
                raise RuntimeError("synthetic benchmark Python source directory is unsafe")
        # Cached bytecode is deliberately ignored; isolated -B/-X workers
        # cannot execute it from these paths.
        directories[:] = sorted(name for name in directories if name != "__pycache__")
        for name in sorted(files):
            path = current / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError("synthetic benchmark Python source file is unsafe")
            total += metadata.st_size
            count += 1
            if count > 10000 or total > 256 * 1024 * 1024:
                raise RuntimeError("synthetic benchmark source tree exceeds bounded input budget")
            relative = path.relative_to(root).as_posix().encode("utf-8")
            digest.update(len(relative).to_bytes(4, "big"))
            digest.update(relative)
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    if count == 0:
        raise RuntimeError("synthetic benchmark Python source tree is empty")
    return digest.hexdigest()


def benchmark_input_hashes():
    """Pin direct modules and both local Python trees before/after every worker."""
    return {
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "source_sha256": {
            name: hashlib.sha256((ROOT / "src" / name).read_bytes()).hexdigest()
            for name in SOURCE_BINDING_FILES
        },
        "test_loader_sha256": {
            name: hashlib.sha256((ROOT / "tests" / name).read_bytes()).hexdigest()
            for name in TEST_LOADER_BINDING_FILES
        },
        "python_tree_sha256": {
            directory: python_tree_sha256(directory)
            for directory in ("src", "tests")
        },
    }


def require_benchmark_inputs(expected):
    if not isinstance(expected, dict) or benchmark_input_hashes() != expected:
        raise RuntimeError("synthetic benchmark input hashes changed during run")


def modules():
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
        raise RuntimeError("run the synthetic benchmark with system Python -I -S -B")
    if sys.prefix != sys.base_prefix or Path(sys.executable).parent.parent.name == ".venv":
        raise RuntimeError("use system Python; runtime deployment imports are excluded")
    if (ROOT / "src" / "deployment-manifest.json").exists():
        raise RuntimeError("source deployment manifest must be absent")
    sys.path[:0] = [str(ROOT / "tests"), str(ROOT / "src")]
    base = importlib.import_module("test_operator_v2_runtime").grabowski_mcp
    query = importlib.import_module("test_audit_segments").grabowski_audit_query
    surface = importlib.import_module("test_read_surface").read_surface
    return base, query, surface


def forbidden(*args, **kwargs):
    raise AssertionError("external source excluded from synthetic audit probe")


@contextmanager
def isolated(state):
    state = Path(state).resolve(strict=True)
    marker = state.parent / "synthetic-probe-owner.json"
    if not marker.is_file() or json.loads(marker.read_text()) != {"kind": "synthetic-audit-probe-v1"}:
        raise ValueError("owned synthetic fixture required")
    if not state.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        raise ValueError("fixtures must be in the temporary directory")
    base, query, surface = modules()
    audit = state / "write-audit.jsonl"
    if audit.is_symlink():
        raise ValueError("symlink audit forbidden")
    deployment = {
        "completion_status": "complete", "release_id": "synthetic-probe",
        "repo_head": "0" * 40,
        **{key: True for key in surface.DEPLOYMENT_INTEGRITY_FIELDS},
    }
    friction = {
        "available": False, "integrity_valid": False,
        "reason": "excluded_by_probe", "events": [],
        "snapshot_sha256": None, "has_more": False,
    }
    fake_tasks = types.ModuleType("grabowski_tasks")
    fake_tasks._row_raw = forbidden
    fake_tasks._terminal_convergence_evidence = forbidden
    replacements = (
        (base, "STATE_DIR", state), (base, "AUDIT_LOG", audit),
        (base, "QUARANTINE_DIR", state / "quarantine"),
        (base, "KILL_SWITCH_PATH", state / "operator-kill-switch"),
        (base, "_deployment_metadata", lambda: dict(deployment)),
        (base, "_kill_switch_state", lambda: {"engaged": False}),
        (base, "grabowski_status", lambda *a, **k: {}),
        (query, "base", base), (surface, "base", base),
        (surface, "audit_query", query),
        (surface, "time", types.SimpleNamespace(time=lambda: 1790179500)),
        (surface.audit_signal, "_audit_friction_signal_source", lambda: dict(friction)),
    )
    with ExitStack() as stack:
        for module, name, replacement in replacements:
            stack.enter_context(patch.object(module, name, new=replacement, create=True))
        stack.enter_context(patch.dict(sys.modules, {
            "grabowski_mcp": base, "grabowski_audit_query": query,
            "grabowski_tasks": fake_tasks,
        }))
        base.AUDIT_SEGMENT_VERIFICATION_CACHE.clear()
        yield base, query, surface, audit


def make_fixture(state, count, payload_bytes):
    state.mkdir(mode=0o700)
    with isolated(state) as (base, _query, _surface, audit):
        fd = os.open(audit, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_APPEND, 0o600)
        status = {"records": 0, "legacy_records": 0, "v2_records": 0, "last_record_sha256": None}
        try:
            for index in range(count):
                record = {
                    "operation": "synthetic-cost-probe", "index": index,
                    "timestamp": "2026-09-23T16:00:00Z", "payload": "x" * payload_bytes,
                }
                enriched, payload = base._enriched_audit_record(record, status)
                if os.fstat(fd).st_size + len(payload) + base.AUDIT_ROTATION_RESERVE_BYTES > base.MAX_AUDIT_BYTES:
                    base._rotate_audit_segment(audit, fd, status, next_record_bytes=len(payload))
                    os.close(fd)
                    fd = os.open(audit, os.O_RDWR | os.O_APPEND)
                    head, _predecessor = base._read_audit_head_unlocked(audit)
                    status = head[2]
                    enriched, payload = base._enriched_audit_record(record, status)
                base._write_all(fd, payload)
                status["records"] += 1
                status["v2_records"] += 1
                status["last_record_sha256"] = enriched["record_sha256"]
            os.fsync(fd)
        finally:
            os.close(fd)
        verified = base._verify_audit_log(audit)
        if verified.get("valid") is not True or verified.get("chain_valid") is not True:
            raise AssertionError(verified)
        if verified["total_records"] != count + verified["archived_segment_count"]:
            raise AssertionError("fixture record count mismatch")
        return {
            "user_records": count, "total_records": verified["total_records"],
            "segments": verified["archived_segment_count"],
            "active_bytes": audit.stat().st_size,
            "fixture_bytes": sum(p.stat().st_size for p in state.rglob("*") if p.is_file()),
            "payload_bytes": payload_bytes,
        }


def rss(field="VmRSS"):
    with open("/proc/self/status", encoding="ascii") as stream:
        for line in stream:
            if line.startswith(field + ":"):
                return int(line.split()[1])
    return None


class JsonCounter:
    def __init__(self, original, counts, label):
        self.original, self.counts, self.label = original, counts, label

    def __getattr__(self, name):
        return getattr(self.original, name)

    def loads(self, *args, **kwargs):
        value = self.original.loads(*args, **kwargs)
        self.counts[self.label + ".json_loads"] += 1
        if isinstance(value, dict) and "audit_schema_version" in value:
            self.counts[self.label + ".audit_record_decodes"] += 1
        return value


@contextmanager
def instrument(base, query, surface, decode, contend=False):
    counts = defaultdict(int)
    original_read, original_acquire = base._read_audit_descriptor, base._acquire_flock
    original_coordination = base._audit_coordination_lock
    measuring_thread = threading.get_ident()
    contender = None
    contention = {}

    def compete(path):
        started = time.perf_counter_ns()
        try:
            with original_coordination(path, exclusive=True):
                contention["outcome"] = "acquired"
        except RuntimeError as exc:
            contention["outcome"] = "timeout" if str(exc) == "Audit lock acquisition timed out" else "unexpected_error"
            contention["error"] = str(exc)
        finally:
            contention["elapsed_ms"] = (time.perf_counter_ns() - started) / 1e6

    def read(descriptor, path):
        data = original_read(descriptor, path)
        if threading.get_ident() == measuring_thread:
            counts["audit_descriptor_reads"] += 1
            counts["audit_descriptor_bytes"] += len(data)
        return data

    def acquire(descriptor, *, exclusive):
        started = time.perf_counter_ns()
        try:
            return original_acquire(descriptor, exclusive=exclusive)
        finally:
            if threading.get_ident() == measuring_thread:
                elapsed = time.perf_counter_ns() - started
                counts["flock_acquire_count"] += 1
                counts["flock_acquire_ns_total"] += elapsed
                counts["flock_acquire_ns_max"] = max(counts["flock_acquire_ns_max"], elapsed)

    @contextmanager
    def coordination(path, *, exclusive):
        nonlocal contender
        with original_coordination(path, exclusive=exclusive):
            if contend and contender is None and not exclusive:
                contender = threading.Thread(target=compete, args=(path,))
                contender.start()
            started = time.perf_counter_ns()
            try:
                yield
            finally:
                if threading.get_ident() == measuring_thread:
                    elapsed = time.perf_counter_ns() - started
                    counts["coordination_hold_count"] += 1
                    counts["coordination_hold_ns_total"] += elapsed
                    counts["coordination_hold_ns_max"] = max(counts["coordination_hold_ns_max"], elapsed)

    with ExitStack() as stack:
        for name, replacement in (
            ("_read_audit_descriptor", read), ("_acquire_flock", acquire),
            ("_audit_coordination_lock", coordination),
        ):
            stack.enter_context(patch.object(base, name, new=replacement))
        if decode:
            for label, module in (("base", base), ("query", query), ("surface", surface)):
                stack.enter_context(patch.object(module, "json", new=JsonCounter(module.json, counts, label)))
        try:
            yield counts
        finally:
            if contender is not None:
                contender.join(timeout=10)
                if contender.is_alive():
                    raise RuntimeError("synthetic lock contender did not finish")
                counts["exclusive_contender"] = contention


def run_case(state, case, warm, decode, contend=False):
    with isolated(state) as (base, query, surface, audit):
        calls = {
            "verify": lambda: base._verify_audit_log(audit),
            "snapshot": lambda: base._audit_records_snapshot(),
            "query_limit1": lambda: query.query_audit({}, limit=1, order="desc", path=audit),
            "projection": lambda: surface.grabowski_audit_projection(view="minimal", top_limit=10, fields=None),
            "health_audit_only": lambda: surface.grabowski_runtime_health(),
        }
        if warm:
            warm_result = calls[case]()
            del warm_result
        gc.collect()
        before = rss()
        peak_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        hwm_before = rss("VmHWM")
        with instrument(base, query, surface, decode, contend) as counts:
            cpu_start, start = time.process_time_ns(), time.perf_counter_ns()
            result = calls[case]()
            elapsed, cpu = time.perf_counter_ns() - start, time.process_time_ns() - cpu_start
            after, peak = rss(), resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if case == "snapshot":
            valid, records = result[1].get("valid") is True, len(result[0])
            semantics = {}
        elif case in ("verify", "health_audit_only"):
            valid = result.get("audit_valid" if case == "health_audit_only" else "valid") is True
            records = result.get("audit_total_records" if case == "health_audit_only" else "total_records")
            semantics = {}
        elif case == "query_limit1":
            valid = result["returned"] == len(result["items"]) == 1
            valid = valid and result["truncated"] == (result["result_truncated"] or result["scan"]["scan_truncated"])
            records = result["scan"].get("scanned_records")
            semantics = {key: result[key] for key in ("returned", "truncated", "matched_total_known", "scan")}
        else:
            valid, records = isinstance(result, dict), None
            semantics = {"keys": sorted(result), "semantic_validation": "separate regression tests required"}
        del result
        gc.collect()
        if not valid:
            raise AssertionError("invalid measured operation")
        return {
            "case": case, "warm_python_cache": warm, "decode_instrumentation": decode,
            "valid": valid, "observed_records": records,
            "elapsed_ms": elapsed / 1e6, "cpu_ms": cpu / 1e6,
            "baseline_rss_kib": before, "rss_after_call_kib": after,
            "process_peak_rss_kib": peak, "process_peak_before_kib": peak_before,
            "rss_hwm_before_kib": hwm_before, "rss_hwm_after_kib": rss("VmHWM"),
            "rss_after_gc_kib": rss(), "synthetic_contention": contend,
            "counters": dict(counts), "semantics": semantics,
            "scope": "synthetic_library_call",
            "worker_python_flags": {
                "isolated": sys.flags.isolated,
                "no_site": sys.flags.no_site,
                "dont_write_bytecode": sys.flags.dont_write_bytecode,
            },
        }


MAX_SWEEP_RECORDS = 1_500_000
MAX_SWEEP_SIZES = 5
MAX_ESTIMATED_FIXTURE_BYTES = 1536 * 1024 * 1024


def validate_sweep(records, cases, payload_bytes):
    try:
        sizes = [int(value) for value in records.split(",")]
    except ValueError as exc:
        raise ValueError("record list must contain integers") from exc
    selected = cases.split(",")
    if (
        not sizes or len(sizes) > MAX_SWEEP_SIZES
        or len(set(sizes)) != len(sizes)
        or any(size < 1 or size > 1_500_000 for size in sizes)
        or sum(sizes) > MAX_SWEEP_RECORDS
    ):
        raise ValueError("record sizes must be unique, 1..1500000, at most 5 and total <=1500000")
    if not selected or len(selected) > len(CASES) or len(set(selected)) != len(selected) or any(item not in CASES for item in selected):
        raise ValueError("benchmark cases must be distinct supported operations")
    if not 0 <= payload_bytes <= 4096:
        raise ValueError("payload bytes must be in 0..4096")
    if any(size * (payload_bytes + 512) > MAX_ESTIMATED_FIXTURE_BYTES for size in sizes):
        raise ValueError("estimated fixture exceeds 1.5 GiB budget")
    return sizes, selected


def require_fixture_space(directory, records, payload_bytes):
    estimate = records * (payload_bytes + 512)
    if shutil.disk_usage(directory).free < 2 * estimate + 512 * 1024 * 1024:
        raise RuntimeError("insufficient temporary disk space for bounded synthetic fixture")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", default="1000,100000,1000000")
    parser.add_argument("--cases", default=",".join(CASES))
    parser.add_argument("--payload-bytes", type=int, default=768)
    parser.add_argument("--warm", action="store_true")
    parser.add_argument("--count-decodes", action="store_true")
    parser.add_argument("--contend", action="store_true")
    parser.add_argument("--worker-state")
    parser.add_argument("--worker-case", choices=CASES)
    parser.add_argument("--expected-input-hashes")
    args = parser.parse_args()
    if args.worker_state:
        if args.expected_input_hashes is None:
            parser.error("worker must receive parent input hashes")
        try:
            pinned = json.loads(args.expected_input_hashes)
        except ValueError as exc:
            raise RuntimeError("synthetic benchmark input binding is invalid") from exc
        require_benchmark_inputs(pinned)
        result = run_case(Path(args.worker_state), args.worker_case, args.warm, args.count_decodes, args.contend)
        require_benchmark_inputs(pinned)
        print(json.dumps(result), flush=True)
        return
    if args.expected_input_hashes is not None:
        parser.error("--expected-input-hashes is worker-only")
    try:
        sizes, cases = validate_sweep(args.records, args.cases, args.payload_bytes)
    except ValueError as exc:
        parser.error(str(exc))
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    pinned = benchmark_input_hashes()
    binding = {
        "head": head, **pinned,
        "interpreter": sys.executable, "python": sys.version.split()[0],
        "parent_python_flags": {
            "isolated": sys.flags.isolated,
            "no_site": sys.flags.no_site,
            "dont_write_bytecode": sys.flags.dont_write_bytecode,
        },
    }
    with tempfile.TemporaryDirectory(prefix="operator-read-cost-p0-") as directory:
        parent = Path(directory)
        (parent / "synthetic-probe-owner.json").write_text(json.dumps({"kind": "synthetic-audit-probe-v1"}))
        cache = parent / "worker-bytecode"
        cache.mkdir(mode=0o700)
        for count in sizes:
            require_benchmark_inputs(pinned)
            state = parent / str(count)
            require_fixture_space(parent, count, args.payload_bytes)
            try:
                fixture = make_fixture(state, count, args.payload_bytes)
                require_benchmark_inputs(pinned)
                print(json.dumps({"event": "fixture_verified", **binding, **fixture}), flush=True)
                for case in cases:
                    require_benchmark_inputs(pinned)
                    argv = [
                        sys.executable, "-I", "-S", "-B", "-X", f"pycache_prefix={cache}",
                        str(Path(__file__).resolve()),
                        "--worker-state", str(state), "--worker-case", case,
                        "--expected-input-hashes", json.dumps(pinned, sort_keys=True, separators=(",", ":")),
                    ]
                    if args.warm:
                        argv.append("--warm")
                    if args.count_decodes:
                        argv.append("--count-decodes")
                    if args.contend:
                        argv.append("--contend")
                    completed = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, timeout=300, check=True)
                    require_benchmark_inputs(pinned)
                    result = json.loads(completed.stdout)
                    print(json.dumps({**binding, "fixture": fixture, **result}), flush=True)
            finally:
                if state.is_dir():
                    shutil.rmtree(state)


if __name__ == "__main__":
    main()

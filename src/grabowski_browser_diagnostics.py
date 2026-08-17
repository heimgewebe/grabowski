"""Bounded read-only diagnostics for one Grabowski-managed browser worker.

This module is intentionally tooling-only.  It observes one already-running
Chrome/CDP worker through its Grabowski registry identity and never accepts an
arbitrary debugging endpoint.  CDP is used only to enable diagnostic domains
and passively collect bounded events.  No page action, navigation, reload,
DOM mutation, retry authority, routing decision, credential access or backend
promotion lives here.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
from typing import Any

operator: Any | None = None
resources: Any | None = None
workers: Any | None = None


def _runtime_modules() -> tuple[Any, Any, Any]:
    global operator, resources, workers
    if operator is None:
        operator = importlib.import_module("grabowski_operator")
    if resources is None:
        resources = importlib.import_module("grabowski_resources")
    if workers is None:
        workers = importlib.import_module("grabowski_workers")
    return operator, resources, workers

SCHEMA_VERSION = 1
DEFAULT_CAPTURE_MS = 750
MIN_CAPTURE_MS = 100
MAX_CAPTURE_MS = 5_000
DEFAULT_MAX_EVENTS = 20
MAX_EVENTS = 50
MAX_NODE_OUTPUT_BYTES = 65_536
MAX_TEXT_HASHED_BYTES = 1_048_576

_HASH_RE = re.compile(r"[0-9a-f]{64}")
_SAFE_METHOD_RE = re.compile(r"[A-Z]{1,16}")
_SAFE_TOKEN_RE = re.compile(r"[A-Za-z0-9._+/-]{1,80}")

NODE_SOURCE = r"""
import {createHash} from 'node:crypto';
import http from 'node:http';

const request = JSON.parse(process.argv[1]);
let ws = null;
let nextId = 1;
const pending = new Map();
const consoleEvents = [];
const networkEvents = [];
const networkIndex = new Map();

function digest(value) {
  return createHash('sha256').update(String(value ?? ''), 'utf8').digest('hex');
}
function textBytes(value) {
  return Buffer.byteLength(String(value ?? ''), 'utf8');
}
function boundedToken(value, limit = 80) {
  const token = String(value ?? '').replace(/\s+/g, ' ').trim().slice(0, limit);
  return /^[A-Za-z0-9._+/-]{1,80}$/.test(token) ? token : '';
}
function urlSummary(value) {
  try {
    const parsed = new URL(String(value));
    return {
      scheme: boundedToken(parsed.protocol.replace(/:$/, ''), 16),
      host_sha256: digest(parsed.hostname.toLowerCase()),
      path_sha256: digest(parsed.pathname || '/'),
      query_present: Boolean(parsed.search),
      fragment_present: Boolean(parsed.hash),
    };
  } catch {
    return {
      scheme: '', host_sha256: digest(''), path_sha256: digest(''),
      query_present: false, fragment_present: false,
    };
  }
}
function argumentSummary(arg) {
  const type = boundedToken(arg && arg.type, 24);
  const subtype = boundedToken(arg && arg.subtype, 24);
  const className = boundedToken(arg && arg.className, 80);
  let raw = '';
  if (arg && Object.prototype.hasOwnProperty.call(arg, 'value')) raw = String(arg.value ?? '');
  else if (arg && typeof arg.unserializableValue === 'string') raw = arg.unserializableValue;
  else if (arg && typeof arg.description === 'string') raw = arg.description;
  return {
    type,
    subtype,
    class_name: className,
    value_sha256: digest(raw),
    value_bytes: Math.min(textBytes(raw), 1048576),
  };
}
function consoleLocation(params) {
  const frames = params && params.stackTrace && Array.isArray(params.stackTrace.callFrames)
    ? params.stackTrace.callFrames : [];
  const first = frames[0] || {};
  return {
    url: urlSummary(first.url || ''),
    line_number: Number.isInteger(first.lineNumber) && first.lineNumber >= 0
      ? Math.min(first.lineNumber, 2147483647) : null,
    column_number: Number.isInteger(first.columnNumber) && first.columnNumber >= 0
      ? Math.min(first.columnNumber, 2147483647) : null,
  };
}
function addConsole(params, source) {
  if (consoleEvents.length >= request.max_events) return;
  const args = Array.isArray(params && params.args) ? params.args.slice(0, 16) : [];
  const rawText = source === 'log'
    ? String(params && params.entry && params.entry.text || '')
    : args.map((arg) => {
        if (arg && Object.prototype.hasOwnProperty.call(arg, 'value')) return String(arg.value ?? '');
        if (arg && typeof arg.unserializableValue === 'string') return arg.unserializableValue;
        if (arg && typeof arg.description === 'string') return arg.description;
        return '';
      }).join(' ');
  const logEntry = source === 'log' && params && params.entry ? params.entry : null;
  consoleEvents.push({
    source,
    level: boundedToken(logEntry ? logEntry.level : params && params.type, 24),
    text_sha256: digest(rawText),
    text_bytes: Math.min(textBytes(rawText), 1048576),
    arguments: args.map(argumentSummary),
    location: logEntry
      ? {url: urlSummary(logEntry.url || ''), line_number: Number.isInteger(logEntry.lineNumber) ? Math.max(0, Math.min(logEntry.lineNumber, 2147483647)) : null, column_number: null}
      : consoleLocation(params),
  });
}
function requestRecord(params) {
  const req = params && params.request ? params.request : {};
  const requestId = String(params && params.requestId || '');
  return {
    request_id_sha256: digest(requestId),
    method: /^[A-Z]{1,16}$/.test(String(req.method || '')) ? String(req.method) : '',
    resource_type: boundedToken(params && params.type, 32),
    initiator_type: boundedToken(params && params.initiator && params.initiator.type, 32),
    url: urlSummary(req.url || ''),
    has_post_data: Boolean(req.hasPostData),
    status: null,
    mime_type: '',
    protocol: '',
    from_disk_cache: false,
    from_service_worker: false,
  };
}
function addRequest(params) {
  if (networkEvents.length >= request.max_events) return;
  const requestId = String(params && params.requestId || '');
  if (!requestId || networkIndex.has(requestId)) return;
  networkIndex.set(requestId, networkEvents.length);
  networkEvents.push(requestRecord(params));
}
function addResponse(params) {
  const requestId = String(params && params.requestId || '');
  const index = networkIndex.get(requestId);
  if (!Number.isInteger(index) || index < 0 || index >= networkEvents.length) return;
  const response = params && params.response ? params.response : {};
  const record = networkEvents[index];
  record.status = Number.isFinite(response.status)
    ? Math.max(0, Math.min(Math.trunc(response.status), 999)) : null;
  record.mime_type = boundedToken(response.mimeType, 80);
  record.protocol = boundedToken(response.protocol, 32);
  record.from_disk_cache = Boolean(response.fromDiskCache);
  record.from_service_worker = Boolean(response.fromServiceWorker);
}
function emit(payload, status = 0) {
  process.stdout.write(JSON.stringify(payload) + '\n');
  process.exitCode = status;
}
async function connect(url) {
  return await new Promise((resolve, reject) => {
    ws = new WebSocket(url);
    const timer = setTimeout(() => reject(new Error('transport')), request.timeout_ms);
    ws.onopen = () => { clearTimeout(timer); resolve(); };
    ws.onerror = () => { clearTimeout(timer); reject(new Error('transport')); };
    ws.onmessage = (event) => {
      let message;
      try { message = JSON.parse(event.data); } catch { return; }
      if (message.method === 'Runtime.consoleAPICalled') addConsole(message.params || {}, 'runtime');
      else if (message.method === 'Log.entryAdded') addConsole(message.params || {}, 'log');
      else if (message.method === 'Network.requestWillBeSent') addRequest(message.params || {});
      else if (message.method === 'Network.responseReceived') addResponse(message.params || {});
      if (message.id && pending.has(message.id)) {
        const entry = pending.get(message.id);
        pending.delete(message.id);
        clearTimeout(entry.timer);
        if (message.error) entry.reject(new Error('protocol'));
        else entry.resolve(message.result || {});
      }
    };
    ws.onclose = () => {
      for (const entry of pending.values()) {
        clearTimeout(entry.timer);
        entry.reject(new Error('transport'));
      }
      pending.clear();
    };
  });
}
async function call(method, params = {}) {
  if (!ws || ws.readyState !== WebSocket.OPEN) throw new Error('transport');
  const id = nextId++;
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error('protocol'));
    }, request.timeout_ms);
    pending.set(id, {resolve, reject, timer});
    ws.send(JSON.stringify({id, method, params}));
  });
}

try {
  const rawTargets = await new Promise((resolve, reject) => {
    const requestHandle = http.get({
      host: '127.0.0.1',
      port: request.port,
      path: '/json/list',
      timeout: request.timeout_ms,
    }, (response) => {
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error('target-discovery'));
        return;
      }
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => {
        body += chunk;
        if (Buffer.byteLength(body, 'utf8') > 262144) {
          response.destroy(new Error('target-discovery'));
        }
      });
      response.on('end', () => resolve(body));
      response.on('error', () => reject(new Error('target-discovery')));
    });
    requestHandle.on('timeout', () => requestHandle.destroy(new Error('target-discovery')));
    requestHandle.on('error', () => reject(new Error('target-discovery')));
  });
  let targets;
  try { targets = JSON.parse(rawTargets); }
  catch { throw new Error('target-discovery'); }
  if (!Array.isArray(targets)) throw new Error('target-discovery');
  const matches = targets.filter((target) => {
    if (!target || target.type !== 'page' || typeof target.webSocketDebuggerUrl !== 'string') return false;
    try {
      const endpoint = new URL(target.webSocketDebuggerUrl);
      const loopbackHosts = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);
      return endpoint.protocol === 'ws:' && loopbackHosts.has(endpoint.hostname) &&
        Number(endpoint.port) === request.port;
    } catch { return false; }
  });
  if (matches.length !== 1) throw new Error('target-discovery');
  await connect(matches[0].webSocketDebuggerUrl);
  await call('Runtime.enable');
  await call('Log.enable');
  await call('Network.enable');
  await new Promise((resolve) => setTimeout(resolve, request.capture_ms));
  emit({
    schema_version: 1,
    ok: true,
    result_code: 'ok',
    target: {url: urlSummary(matches[0].url || '')},
    console: consoleEvents,
    network: networkEvents,
  }, 0);
} catch (error) {
  emit({
    schema_version: 1,
    ok: false,
    result_code: ['transport', 'protocol', 'target-discovery'].includes(error.message)
      ? error.message : 'protocol',
    target: null,
    console: [],
    network: [],
  }, 1);
} finally {
  try { if (ws) ws.close(); } catch {}
}
"""


class BrowserDiagnosticsError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(f"browser diagnostics failed: {code}")
        self.code = code


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
    ).hexdigest()


def _checked_capture_ms(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("capture_ms must be an integer")
    if not MIN_CAPTURE_MS <= value <= MAX_CAPTURE_MS:
        raise ValueError(f"capture_ms must be between {MIN_CAPTURE_MS} and {MAX_CAPTURE_MS}")
    return value


def _checked_max_events(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("max_events must be an integer")
    if not 1 <= value <= MAX_EVENTS:
        raise ValueError(f"max_events must be between 1 and {MAX_EVENTS}")
    return value


def _worker_identity(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "worker_id": record["worker_id"],
        "kind": record["kind"],
        "unit": record["unit"],
        "executable": record["executable"],
        "port": record["port"],
        "profile_path": record["profile_path"],
        "config_path": record["config_path"],
        "created_at_unix": record["created_at_unix"],
    }


def _live_worker_record(worker_id: str, *, min_remaining_seconds: int) -> tuple[dict[str, Any], str]:
    _, runtime_resources, runtime_workers = _runtime_modules()
    record = runtime_workers._row(worker_id)
    if record.get("kind") != "browser":
        raise BrowserDiagnosticsError("worker-kind")
    identifier = str(record.get("worker_id") or "")
    port = record.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise BrowserDiagnosticsError("worker-binding")
    expected_unit = f"grabowski-browser-worker-{identifier}.service"
    if record.get("unit") != expected_unit:
        raise BrowserDiagnosticsError("worker-binding")
    config_path = Path(str(record.get("config_path") or ""))
    expected_directory = runtime_workers.WORKER_STATE / "instances" / identifier
    if (
        config_path != expected_directory / "worker.json"
        or expected_directory.is_symlink()
        or runtime_workers.WORKER_STATE not in expected_directory.parents
    ):
        raise BrowserDiagnosticsError("worker-binding")
    profile_path = record.get("profile_path")
    if not isinstance(profile_path, str) or not profile_path:
        raise BrowserDiagnosticsError("worker-binding")
    observed = runtime_workers._observe(record)
    if observed.get("state") != "running":
        raise BrowserDiagnosticsError("worker-not-running")
    owner = f"worker:{identifier}"
    now = runtime_workers._now()
    try:
        lease_keys = json.loads(record["lease_keys_json"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise BrowserDiagnosticsError("worker-lease") from exc
    expected_lease_keys = {
        f"port:{port}",
        f"browser-profile:{profile_path}",
    }
    if (
        not isinstance(lease_keys, list)
        or any(not isinstance(key, str) for key in lease_keys)
        or set(lease_keys) != expected_lease_keys
        or len(lease_keys) != len(expected_lease_keys)
    ):
        raise BrowserDiagnosticsError("worker-lease")
    for key in sorted(expected_lease_keys):
        lease = runtime_resources.inspect_resource(key)
        if (
            not isinstance(lease, dict)
            or lease.get("owner_id") != owner
            or not isinstance(lease.get("expires_at_unix"), int)
            or lease["expires_at_unix"] < now + min_remaining_seconds
        ):
            raise BrowserDiagnosticsError("worker-lease")
    return record, _sha256_json(_worker_identity(record))


def _safe_hash(value: Any) -> str:
    text = str(value or "")
    return text if _HASH_RE.fullmatch(text) else hashlib.sha256(b"").hexdigest()


def _safe_token(value: Any, limit: int = 80) -> str:
    text = str(value or "")[:limit]
    return text if _SAFE_TOKEN_RE.fullmatch(text) else ""


def _safe_nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return min(value, 2_147_483_647)


def _url_summary(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    return {
        "scheme": _safe_token(raw.get("scheme"), 16),
        "host_sha256": _safe_hash(raw.get("host_sha256")),
        "path_sha256": _safe_hash(raw.get("path_sha256")),
        "query_present": bool(raw.get("query_present")),
        "fragment_present": bool(raw.get("fragment_present")),
    }


def _argument_summary(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    value_bytes = _safe_nonnegative_int(raw.get("value_bytes"))
    return {
        "type": _safe_token(raw.get("type"), 24),
        "subtype": _safe_token(raw.get("subtype"), 24),
        "class_name": _safe_token(raw.get("class_name"), 80),
        "value_sha256": _safe_hash(raw.get("value_sha256")),
        "value_bytes": min(value_bytes or 0, MAX_TEXT_HASHED_BYTES),
    }


def _console_event(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    location = raw.get("location") if isinstance(raw.get("location"), dict) else {}
    arguments = raw.get("arguments") if isinstance(raw.get("arguments"), list) else []
    text_bytes = _safe_nonnegative_int(raw.get("text_bytes"))
    return {
        "source": _safe_token(raw.get("source"), 16),
        "level": _safe_token(raw.get("level"), 24),
        "text_sha256": _safe_hash(raw.get("text_sha256")),
        "text_bytes": min(text_bytes or 0, MAX_TEXT_HASHED_BYTES),
        "arguments": [_argument_summary(item) for item in arguments[:16]],
        "location": {
            "url": _url_summary(location.get("url")),
            "line_number": _safe_nonnegative_int(location.get("line_number")),
            "column_number": _safe_nonnegative_int(location.get("column_number")),
        },
    }


def _network_event(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    status = raw.get("status")
    if isinstance(status, bool) or not isinstance(status, int) or not 0 <= status <= 999:
        status = None
    method = str(raw.get("method") or "")
    return {
        "request_id_sha256": _safe_hash(raw.get("request_id_sha256")),
        "method": method if _SAFE_METHOD_RE.fullmatch(method) else "",
        "resource_type": _safe_token(raw.get("resource_type"), 32),
        "initiator_type": _safe_token(raw.get("initiator_type"), 32),
        "url": _url_summary(raw.get("url")),
        "has_post_data": bool(raw.get("has_post_data")),
        "status": status,
        "mime_type": _safe_token(raw.get("mime_type"), 80),
        "protocol": _safe_token(raw.get("protocol"), 32),
        "from_disk_cache": bool(raw.get("from_disk_cache")),
        "from_service_worker": bool(raw.get("from_service_worker")),
    }


def _normalize_node_payload(payload: Any, *, max_events: int) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise BrowserDiagnosticsError("receipt-schema")
    if payload.get("ok") is not True or payload.get("result_code") != "ok":
        code = payload.get("result_code") if isinstance(payload.get("result_code"), str) else "protocol"
        raise BrowserDiagnosticsError(code if code in {"transport", "protocol", "target-discovery"} else "protocol")
    console = payload.get("console") if isinstance(payload.get("console"), list) else []
    network = payload.get("network") if isinstance(payload.get("network"), list) else []
    target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
    return {
        "target": {"url": _url_summary(target.get("url"))},
        "console": [_console_event(item) for item in console[:max_events]],
        "network": [_network_event(item) for item in network[:max_events]],
    }


def _node_executable() -> Path:
    node = shutil.which("node")
    if not node:
        raise BrowserDiagnosticsError("node-unavailable")
    alias = Path(node)
    if not alias.is_absolute():
        raise BrowserDiagnosticsError("node-unavailable")
    target = alias.resolve(strict=True)
    metadata = target.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(target, os.X_OK):
        raise BrowserDiagnosticsError("node-unavailable")
    return alias


def _run_node_capture(record: dict[str, Any], *, capture_ms: int, max_events: int) -> dict[str, Any]:
    request = {
        "schema_version": 1,
        "port": record["port"],
        "capture_ms": capture_ms,
        "max_events": max_events,
        "timeout_ms": min(10_000, max(2_000, capture_ms + 2_000)),
    }
    runtime_operator, _runtime_resources, _runtime_workers = _runtime_modules()
    execution = runtime_operator._run(
        [str(_node_executable()), "--input-type=module", "-e", NODE_SOURCE, json.dumps(request, separators=(",", ":"))],
        cwd=runtime_operator.HOME,
        timeout_seconds=max(15, capture_ms // 1000 + 12),
        max_output_bytes=MAX_NODE_OUTPUT_BYTES,
    )
    lines = [line for line in execution.get("stdout", "").splitlines() if line.strip()]
    if not lines:
        raise BrowserDiagnosticsError("no-receipt")
    try:
        payload = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise BrowserDiagnosticsError("receipt-json") from exc
    normalized = _normalize_node_payload(payload, max_events=max_events)
    if execution.get("returncode") != 0:
        raise BrowserDiagnosticsError("protocol")
    return normalized


def observe_browser_diagnostics(
    worker_id: str,
    *,
    capture_ms: int = DEFAULT_CAPTURE_MS,
    max_events: int = DEFAULT_MAX_EVENTS,
) -> dict[str, Any]:
    """Passively observe bounded diagnostics for one live managed browser worker."""
    capture = _checked_capture_ms(capture_ms)
    limit = _checked_max_events(max_events)
    remaining = max(10, capture // 1000 + 10)
    before, identity_sha256 = _live_worker_record(
        worker_id, min_remaining_seconds=remaining
    )
    diagnostic = _run_node_capture(before, capture_ms=capture, max_events=limit)
    after, after_identity_sha256 = _live_worker_record(
        worker_id, min_remaining_seconds=5
    )
    if after_identity_sha256 != identity_sha256:
        raise BrowserDiagnosticsError("worker-changed")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_browser_diagnostics",
        "state": "observed",
        "worker_id": before["worker_id"],
        "worker_binding_sha256": identity_sha256,
        "capture_ms": capture,
        "limits": {"max_events_per_stream": limit, "max_console_arguments": 16},
        "target": diagnostic["target"],
        "console": {"count": len(diagnostic["console"]), "events": diagnostic["console"]},
        "network": {"count": len(diagnostic["network"]), "events": diagnostic["network"]},
        "screenshot": {
            "state": "not_implemented",
            "reason": "bounded_artifact_boundary_required",
        },
        "read_only": True,
        "page_effects": False,
        "production_adapter_changed": False,
        "retry_authorized": False,
        "does_not_establish": [
            "console_or_network_payload_contents",
            "request_or_response_headers",
            "request_or_response_bodies",
            "cookies_or_credentials",
            "browser_action_authority",
            "semantic_gateway_expansion",
            "production_backend_promotion",
            "performance_superiority",
            "retry_authority",
        ],
    }


def failure_report(exc: BaseException) -> dict[str, Any]:
    code = exc.code if isinstance(exc, BrowserDiagnosticsError) else type(exc).__name__
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_browser_diagnostics",
        "state": "failed_closed",
        "result_code": str(code)[:80],
        "read_only": True,
        "page_effects": False,
        "production_adapter_changed": False,
        "retry_authorized": False,
        "does_not_establish": [
            "browser_action_authority",
            "diagnostic_unavailability_is_permanent",
            "safe_unchanged_retry",
            "production_backend_promotion",
        ],
    }

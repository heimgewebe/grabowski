from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Callable
import urllib.error
import urllib.request


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_RESPONSE_BYTES = 5_000_000
UPDATE_KEYS = (
    "name",
    "description",
    "nodes",
    "connections",
    "nodeGroups",
    "settings",
    "staticData",
    "pinData",
)
REQUIRED_UPDATE_KEYS = ("name", "nodes", "connections", "settings")
SECRET_KEY_NAMES = {
    "apikey",
    "api_key",
    "accesstoken",
    "access_token",
    "refreshtoken",
    "refresh_token",
    "password",
    "clientsecret",
    "client_secret",
    "privatekey",
    "private_key",
    "bearertoken",
    "bearer_token",
}


class N8nProviderError(RuntimeError):
    """Fail-closed provider error whose message must not contain secret material."""


@dataclass(frozen=True)
class ProviderProfile:
    name: str
    origin: str
    workflow_id: str
    source_node_name: str
    source_node_id: str
    source_node_type: str
    source_type_version: float
    credential_type: str
    downstream_node_name: str
    forbidden_substrings: tuple[str, ...]


PROVIDER_PROFILES: dict[str, ProviderProfile] = {
    "forrest-transcription-post-done-v1": ProviderProfile(
        name="forrest-transcription-post-done-v1",
        origin="https://tb5mwp.app.n8n.cloud",
        workflow_id="7uokWleaiOP5yewH",
        source_node_name="Transcribe Audio (Whisper)",
        source_node_id="817cafb7-5d86-4419-a653-e5563f88046b",
        source_node_type="@n8n/n8n-nodes-langchain.openAi",
        source_type_version=2.3,
        credential_type="openAiApi",
        downstream_node_name="AI Agent",
        forbidden_substrings=("/transcribe",),
    )
}

UrlOpen = Callable[..., Any]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise N8nProviderError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _profile(name: Any) -> ProviderProfile:
    if not isinstance(name, str) or name not in PROVIDER_PROFILES:
        raise N8nProviderError("unknown n8n provider profile")
    return PROVIDER_PROFILES[name]


def public_profile(name: str) -> dict[str, Any]:
    profile = _profile(name)
    return {
        "name": profile.name,
        "origin": profile.origin,
        "workflowId": profile.workflow_id,
        "sourceNodeName": profile.source_node_name,
        "sourceNodeId": profile.source_node_id,
        "sourceNodeType": profile.source_node_type,
        "sourceTypeVersion": profile.source_type_version,
        "credentialType": profile.credential_type,
        "downstreamNodeName": profile.downstream_node_name,
        "forbiddenSubstrings": list(profile.forbidden_substrings),
    }


def _api_key(secret_data: bytes) -> str:
    try:
        text = secret_data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise N8nProviderError("n8n API-key secret is not UTF-8 text") from exc
    if "\x00" in text:
        raise N8nProviderError("n8n API-key secret contains NUL")
    value = text.strip()
    if not value or "\n" in value or "\r" in value:
        raise N8nProviderError("n8n API-key secret must contain exactly one non-empty line")
    return value


def _read_response(response: Any) -> bytes:
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise N8nProviderError("n8n provider response exceeds bounded size")
    return raw


def _request(
    profile: ProviderProfile,
    api_key: str,
    *,
    method: str,
    payload: dict[str, Any] | None = None,
    urlopen: UrlOpen = urllib.request.urlopen,
) -> tuple[int, bytes]:
    if method not in {"GET", "PUT"}:
        raise N8nProviderError("unsupported n8n provider method")
    body = None
    headers = {
        "X-N8N-API-KEY": api_key,
        "Accept": "application/json",
    }
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    url = f"{profile.origin}/api/v1/workflows/{profile.workflow_id}"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=30) as response:
            return int(response.status), _read_response(response)
    except urllib.error.HTTPError as exc:
        try:
            exc.read(MAX_RESPONSE_BYTES + 1)
        except Exception:
            pass
        raise N8nProviderError(f"n8n provider returned HTTP {exc.code} for {method}") from None
    except N8nProviderError:
        raise
    except Exception as exc:
        raise N8nProviderError(f"n8n provider request failed: {type(exc).__name__}") from exc


def _parse_workflow(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise N8nProviderError("n8n workflow response is not valid JSON") from exc
    if not isinstance(value, dict):
        raise N8nProviderError("n8n workflow response is not an object")
    return value


def _nodes(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = workflow.get("nodes")
    if not isinstance(nodes, list) or not all(isinstance(item, dict) for item in nodes):
        raise N8nProviderError("workflow nodes contract is invalid")
    names = [item.get("name") for item in nodes]
    if not all(isinstance(name, str) and name for name in names):
        raise N8nProviderError("workflow contains an unnamed node")
    if len(set(names)) != len(names):
        raise N8nProviderError("workflow contains duplicate node names")
    return nodes


def _node(workflow: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [item for item in _nodes(workflow) if item.get("name") == name]
    if len(matches) != 1:
        raise N8nProviderError("expected workflow node is absent or ambiguous")
    return matches[0]


def _outgoing(workflow: dict[str, Any], name: str) -> list[Any]:
    value = (((workflow.get("connections") or {}).get(name) or {}).get("main") or [])
    if not isinstance(value, list):
        raise N8nProviderError("source connection contract is invalid")
    return value


def _outgoing_count(value: list[Any]) -> int:
    count = 0
    for branch in value:
        if not isinstance(branch, list):
            raise N8nProviderError("source connection branch contract is invalid")
        for edge in branch:
            if not isinstance(edge, dict):
                raise N8nProviderError("source connection edge contract is invalid")
            count += 1
    return count


def _walk_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child)


def _reject_embedded_secret_values(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in SECRET_KEY_NAMES and isinstance(child, str) and child.strip():
                raise N8nProviderError("workflow contains an embedded secret-like value")
            _reject_embedded_secret_values(child)
    elif isinstance(value, list):
        for child in value:
            _reject_embedded_secret_values(child)


def _credential_bound(node: dict[str, Any], credential_type: str) -> bool:
    ref = (node.get("credentials") or {}).get(credential_type)
    return (
        isinstance(ref, dict)
        and isinstance(ref.get("id"), str)
        and bool(ref.get("id"))
        and isinstance(ref.get("name"), str)
        and bool(ref.get("name"))
    )


def _expected_edge(profile: ProviderProfile) -> list[list[dict[str, Any]]]:
    return [[{"node": profile.downstream_node_name, "type": "main", "index": 0}]]


def validate_workflow(
    profile: ProviderProfile,
    workflow: dict[str, Any],
    raw: bytes,
    *,
    expected_state: str,
    expected_version_id: str | None = None,
    expected_response_sha256: str | None = None,
) -> dict[str, Any]:
    if expected_state not in {"isolated", "final"}:
        raise N8nProviderError("expected_state must be isolated or final")
    response_sha256 = _sha256(raw)
    if expected_response_sha256 is not None:
        if response_sha256 != _validate_sha256(expected_response_sha256, "expected_response_sha256"):
            raise N8nProviderError("workflow response SHA-256 mismatch")
    version_id = workflow.get("versionId")
    if not isinstance(version_id, str) or not version_id:
        raise N8nProviderError("workflow versionId is unavailable")
    if expected_version_id is not None and version_id != expected_version_id:
        raise N8nProviderError("workflow version mismatch")
    if workflow.get("id") != profile.workflow_id:
        raise N8nProviderError("workflow id mismatch")
    if workflow.get("active") is not False:
        raise N8nProviderError("workflow must remain inactive")

    source = _node(workflow, profile.source_node_name)
    downstream = _node(workflow, profile.downstream_node_name)
    if source.get("id") != profile.source_node_id:
        raise N8nProviderError("source node id mismatch")
    if source.get("type") != profile.source_node_type:
        raise N8nProviderError("source node type mismatch")
    if source.get("typeVersion") != profile.source_type_version:
        raise N8nProviderError("source node typeVersion mismatch")
    params = source.get("parameters") or {}
    if not isinstance(params, dict):
        raise N8nProviderError("source node parameters contract is invalid")
    if params.get("resource") != "audio" or params.get("operation") != "transcribe":
        raise N8nProviderError("source node audio/transcribe contract mismatch")
    if params.get("binaryPropertyName", "data") != "data":
        raise N8nProviderError("source node binary property mismatch")
    if not _credential_bound(source, profile.credential_type):
        raise N8nProviderError("source node lacks the required owner-bound credential")
    if not isinstance(downstream.get("id"), str) or not downstream.get("id"):
        raise N8nProviderError("downstream node lacks a stable id")

    outgoing = _outgoing(workflow, profile.source_node_name)
    count = _outgoing_count(outgoing)
    if expected_state == "isolated" and count != 0:
        raise N8nProviderError("source node is not isolated")
    if expected_state == "final" and outgoing != _expected_edge(profile):
        raise N8nProviderError("source node final edge mismatch")
    for forbidden in profile.forbidden_substrings:
        if any(forbidden in text for text in _walk_strings(workflow)):
            raise N8nProviderError("workflow contains a forbidden legacy provider reference")

    return {
        "workflowId": profile.workflow_id,
        "versionId": version_id,
        "responseSha256": response_sha256,
        "active": False,
        "sourceNodeId": profile.source_node_id,
        "sourceNodeType": profile.source_node_type,
        "sourceTypeVersion": profile.source_type_version,
        "credentialType": profile.credential_type,
        "credentialBound": True,
        "downstreamNodeId": downstream.get("id"),
        "outgoingCount": count,
        "state": expected_state,
        "legacyProviderReferencePresent": False,
    }


def _update_payload(workflow: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key in UPDATE_KEYS:
        if key not in workflow:
            continue
        value = workflow[key]
        if value is None and key not in REQUIRED_UPDATE_KEYS:
            continue
        payload[key] = deepcopy(value)
    missing = [key for key in REQUIRED_UPDATE_KEYS if key not in payload]
    if missing:
        raise N8nProviderError("workflow lacks required n8n update fields")
    _reject_embedded_secret_values(payload)
    return payload


def build_single_edge_payload(profile: ProviderProfile, workflow: dict[str, Any]) -> dict[str, Any]:
    baseline = _update_payload(workflow)
    result = deepcopy(baseline)
    connections = result.get("connections")
    if not isinstance(connections, dict):
        raise N8nProviderError("workflow connections contract is invalid")
    result["connections"] = deepcopy(connections)
    result["connections"][profile.source_node_name] = {"main": _expected_edge(profile)}

    comparison = deepcopy(result)
    comparison["connections"] = deepcopy(baseline["connections"])
    if comparison != baseline:
        raise N8nProviderError("single-edge payload changes more than connections")
    before_connections = deepcopy(baseline["connections"])
    after_connections = deepcopy(result["connections"])
    before_source = before_connections.get(profile.source_node_name)
    after_source = after_connections.get(profile.source_node_name)
    before_connections.pop(profile.source_node_name, None)
    after_connections.pop(profile.source_node_name, None)
    if before_connections != after_connections:
        raise N8nProviderError("single-edge payload changes unrelated connections")
    before_count = _outgoing_count(((before_source or {}).get("main") or [])) if isinstance(before_source, dict) else 0
    if before_count != 0:
        raise N8nProviderError("single-edge payload pre-state is not isolated")
    if not isinstance(after_source, dict) or after_source.get("main") != _expected_edge(profile):
        raise N8nProviderError("single-edge payload post-state is not exact")
    return result


def verify(
    *,
    provider_profile: str,
    secret_data: bytes,
    expected_state: str,
    urlopen: UrlOpen = urllib.request.urlopen,
) -> dict[str, Any]:
    profile = _profile(provider_profile)
    key = _api_key(secret_data)
    status, raw = _request(profile, key, method="GET", urlopen=urlopen)
    if status != 200:
        raise N8nProviderError("n8n workflow read did not return HTTP 200")
    workflow = _parse_workflow(raw)
    observed = validate_workflow(profile, workflow, raw, expected_state=expected_state)
    return {
        "ok": True,
        "mode": "verify",
        "providerProfile": profile.name,
        "providerOrigin": profile.origin,
        "providerMutationPerformed": False,
        "observed": observed,
    }


def apply(
    *,
    provider_profile: str,
    secret_data: bytes,
    expected_version_id: str,
    expected_response_sha256: str,
    urlopen: UrlOpen = urllib.request.urlopen,
) -> dict[str, Any]:
    profile = _profile(provider_profile)
    _validate_sha256(expected_response_sha256, "expected_response_sha256")
    if not isinstance(expected_version_id, str) or not expected_version_id:
        raise N8nProviderError("expected_version_id must be non-empty")
    key = _api_key(secret_data)

    status, raw = _request(profile, key, method="GET", urlopen=urlopen)
    if status != 200:
        raise N8nProviderError("n8n workflow pre-read did not return HTTP 200")
    workflow = _parse_workflow(raw)
    pre = validate_workflow(
        profile,
        workflow,
        raw,
        expected_state="isolated",
        expected_version_id=expected_version_id,
        expected_response_sha256=expected_response_sha256,
    )
    payload = build_single_edge_payload(profile, workflow)
    payload_sha256 = _sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))

    prewrite_status, prewrite_raw = _request(profile, key, method="GET", urlopen=urlopen)
    if prewrite_status != 200:
        raise N8nProviderError("n8n workflow pre-write re-read did not return HTTP 200")
    prewrite_workflow = _parse_workflow(prewrite_raw)
    prewrite = validate_workflow(
        profile,
        prewrite_workflow,
        prewrite_raw,
        expected_state="isolated",
        expected_version_id=expected_version_id,
        expected_response_sha256=expected_response_sha256,
    )

    write_status, _ = _request(profile, key, method="PUT", payload=payload, urlopen=urlopen)
    if write_status not in {200, 201}:
        raise N8nProviderError("n8n workflow update did not return a success status")

    post_status, post_raw = _request(profile, key, method="GET", urlopen=urlopen)
    if post_status != 200:
        raise N8nProviderError("n8n workflow post-read did not return HTTP 200")
    post_workflow = _parse_workflow(post_raw)
    post_version = post_workflow.get("versionId")
    if post_version == expected_version_id:
        raise N8nProviderError("n8n workflow version did not advance")
    post = validate_workflow(profile, post_workflow, post_raw, expected_state="final")

    return {
        "ok": True,
        "mode": "apply",
        "providerProfile": profile.name,
        "providerOrigin": profile.origin,
        "providerMutationPerformed": True,
        "effect": {
            "kind": "n8n-workflow-single-edge-add",
            "sourceNodeName": profile.source_node_name,
            "downstreamNodeName": profile.downstream_node_name,
            "payloadSha256": payload_sha256,
        },
        "pre": pre,
        "preWrite": prewrite,
        "post": post,
        "concurrencyContract": "exact-preconditions-revalidated-before-put-no-atomic-provider-cas",
    }

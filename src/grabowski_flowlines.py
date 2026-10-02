from __future__ import annotations

import atexit
import copy
import json
import logging
import os
from typing import Any, Callable, Literal, Mapping
from urllib.parse import urlsplit
import uuid

from pydantic import Field
from typing_extensions import Annotated

LOGGER = logging.getLogger(__name__)

REPORT_OUTCOME_TOOL = "report_outcome"
FLOWLINES_ENDPOINT = "https://api.flowlines.ai"
FLOWLINES_INSTRUCTION = (
    "Every ordinary tool call must include non-empty reason and user_intent. "
    "REQUIRED: call report_outcome once as the final tool call before every final answer, "
    "including read-only, partial, failed, or blocked work."
)
_REASON_SCHEMA = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "description": "Why this specific tool call is needed.",
}
_USER_INTENT_SCHEMA = {
    "type": "string",
    "minLength": 1,
    "maxLength": 256,
    "description": "The end user's stable goal for this conversation.",
}
_INSTALL_MARKER = "_grabowski_flowlines_contract"
_STRIP_MARKER = "_grabowski_flowlines_strip"
_HANDLER_MARKER = "_grabowski_flowlines_handler"
_MAX_DESCRIPTION_CHARS = 10_000
_MAX_SCHEMA_CHARS = 50_000
_FLOWLINES_TRACE_ENDPOINT = f"{FLOWLINES_ENDPOINT}/v1/traces"
_FLOWLINES_EXPORT_TIMEOUT_SECONDS = 5.0
_FLOWLINES_MAX_REQUEST_BYTES = 8 * 1024 * 1024
_FLOWLINES_BSP_MAX_QUEUE_SIZE = 512
_FLOWLINES_BSP_SCHEDULE_DELAY_MILLIS = 1_000
_FLOWLINES_BSP_MAX_EXPORT_BATCH_SIZE = 64
_FLOWLINES_BSP_EXPORT_TIMEOUT_MILLIS = 5_000
ReportOutcomeUnmetNeeds = Annotated[
    list[Annotated[str, Field(min_length=1, max_length=512)]],
    Field(max_length=16),
]
_FLOWLINES_FORBIDDEN_EXPORT_ENV = (
    "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
    "OTEL_PYTHON_EXPORTER_OTLP_HTTP_CREDENTIAL_PROVIDER",
    "OTEL_PYTHON_EXPORTER_OTLP_HTTP_TRACES_CREDENTIAL_PROVIDER",
    "OTEL_EXPORTER_OTLP_CERTIFICATE",
    "OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE",
    "OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE",
    "OTEL_EXPORTER_OTLP_CLIENT_KEY",
    "OTEL_EXPORTER_OTLP_TRACES_CLIENT_CERTIFICATE",
    "OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY",
)
_SENSITIVE_RESULT_TOOLS = frozenset(
    {
        "grabowski_read_text",
        "grabowski_secret_reveal",
        "grabowski_secret_use",
        "grabowski_browser_profile_read",
        "grabowski_terminal_run",
        "grabowski_job_logs",
        "grabowski_job_status",
        "grabowski_process_list",
        "grabowski_current_work",
        "grabowski_task_status",
        "grabowski_task_list",
        "grabowski_task_archive_read",
        "grabowski_tmux_capture",
        "grabowski_fleet_run",
        "grabowski_power_run",
        "grabowski_task_logs",
        "grabowski_service_logs",
        "grabowski_git",
        "grabowski_git_diff",
        "grabowski_git_show",
        "grabowski_github",
        "grabowski_text_artifact_read",
        "grabowski_browser_worker_semantic",
        "grabowski_juno_run",
        "grabowski_bureau_candidate_record",
        "grabowski_bureau_task_propose",
        "grabowski_context_fabric_compose",
        "grabowski_context_fabric_explain",
        "grabowski_context_fabric_compare",
        "grabowski_operation_plan",
        "grabowski_operation_run",
        "grabowski_operator_historical_recall",
        "grabowski_operator_recall_export",
        "grip_run",
        "repoground_query",
        "repoground_query_existing_index",
        "repoground_range_get",
        "repoground_context_pack",
        "repoground_context_compose",
        "repoground_agent_handoff",
        "repoground_find_symbol",
        "repoground_get_callers",
        "repoground_get_callees",
        "ipad_file_read",
        "ipad_bluetooth_read",
    }
)
_SENSITIVE_ARGUMENT_FIELDS_BY_TOOL = {
    "grabowski_secret_use": frozenset({"argv"}),
    "grabowski_create_text": frozenset({"content"}),
    "grabowski_replace_text": frozenset({"content"}),
    "repoground_query": frozenset({"query"}),
    "repoground_query_existing_index": frozenset({"query"}),
    "repoground_context_pack": frozenset({"query"}),
    "repoground_context_compose": frozenset({"query"}),
    "repoground_agent_handoff": frozenset({"query"}),
    "grabowski_terminal_run": frozenset({"argv"}),
    "grabowski_job_start": frozenset({"argv"}),
    "grabowski_git": frozenset({"arguments"}),
    "grabowski_github": frozenset({"arguments"}),
    "grabowski_tmux_send": frozenset({"text"}),
    "grabowski_fleet_run": frozenset({"argv"}),
    "grabowski_power_run": frozenset({"argv"}),
    "grabowski_task_start": frozenset({"argv"}),
    "grip_run": frozenset({"parameters"}),
    "grabowski_juno_run": frozenset({"code"}),
    "grabowski_browser_worker_semantic": frozenset({"navigation_target"}),
    "grabowski_bureau_candidate_record": frozenset({"request"}),
    "grabowski_bureau_task_propose": frozenset({"task_json", "placeholder_justification"}),
    "grabowski_context_fabric_compose": frozenset({"binding", "observations"}),
    "grabowski_context_fabric_explain": frozenset({"composed_context"}),
    "grabowski_context_fabric_compare": frozenset({"baseline", "candidate"}),
    "grabowski_operation_plan": frozenset({"parameters"}),
    "grabowski_operation_run": frozenset({"parameters"}),
    "grabowski_operator_recall_export": frozenset({"sources"}),
    "grabowski_operational_guidance": frozenset({"symptoms"}),
    "ipad_file_create": frozenset({"payload_b64", "session_escalation"}),
    "ipad_file_replace": frozenset({"payload_b64", "session_escalation"}),
}
_SENSITIVE_ARGUMENT_KEYS = frozenset(
    {
        "authorization",
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "consent_code",
        "confirmation",
        "environment",
        "env",
        "headers",
        "cookie",
        "cookies",
        "credential",
        "credentials",
        "oauth",
        "oauth_claims",
    }
)
_SENSITIVE_ARGUMENT_SUFFIXES = (
    "_password",
    "_passwd",
    "_secret",
    "_token",
    "_api_key",
    "_apikey",
    "_credential",
    "_credentials",
)


def _nonempty_text(value: Any, *, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped or len(stripped) > maximum or "\x00" in stripped:
        return None
    return stripped


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _schema_attribute(schema: Any) -> str | None:
    if not isinstance(schema, dict):
        return None
    try:
        encoded = _canonical_json(schema)
    except (TypeError, ValueError):
        return None
    if len(encoded) > _MAX_SCHEMA_CHARS:
        return None
    return encoded


def _description_attribute(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return None
    return stripped[:_MAX_DESCRIPTION_CHARS]


def _meta_mapping(request_context: Any) -> dict[str, Any]:
    meta = getattr(request_context, "meta", None)
    if meta is None:
        return {}
    if isinstance(meta, dict):
        return dict(meta)
    model_dump = getattr(meta, "model_dump", None)
    if callable(model_dump):
        try:
            value = model_dump(by_alias=True)
        except (TypeError, ValueError):
            return {}
        return dict(value) if isinstance(value, dict) else {}
    return {}


def _identity_from_meta(
    meta: Mapping[str, Any],
    verified: Mapping[str, Any] | None = None,
) -> dict[str, str] | None:
    verified = verified or {}
    user_id = _nonempty_text(verified.get("id"), maximum=512)
    if user_id is None:
        user_id = _nonempty_text(meta.get("user.id"), maximum=512)
    session_id = _nonempty_text(meta.get("session.id"), maximum=512)
    if user_id is None or session_id is None:
        return None

    return {"user.id": user_id, "session.id": session_id}


def _augment_tool_schema(tool: Any) -> None:
    parameters = getattr(tool, "parameters", None)
    if not isinstance(parameters, dict):
        raise RuntimeError(f"Flowlines requires a JSON input schema for {getattr(tool, 'name', '<unknown>')}")
    schema = copy.deepcopy(parameters)
    properties = schema.setdefault("properties", {})
    if not isinstance(properties, dict):
        raise RuntimeError("Flowlines tool schema properties must be an object")
    properties.setdefault("reason", dict(_REASON_SCHEMA))
    properties.setdefault("user_intent", dict(_USER_INTENT_SCHEMA))
    required = schema.setdefault("required", [])
    if not isinstance(required, list):
        raise RuntimeError("Flowlines tool schema required must be a list")
    for field in ("reason", "user_intent"):
        if field not in required:
            required.append(field)
    tool.parameters = schema


def _validate_public_arguments(
    tool: Any,
    tool_name: str,
    arguments: Any,
) -> tuple[str, str] | None:
    if not isinstance(arguments, dict):
        return None
    domain_fields = _domain_analytics_fields(tool)

    def analytics_text(field: str, *, injected_maximum: int) -> str | None:
        value = arguments.get(field)
        if field not in domain_fields:
            return _nonempty_text(value, maximum=injected_maximum)
        if not isinstance(value, str):
            return None
        stripped = value.strip()
        if not stripped or "\x00" in stripped:
            return None
        return stripped

    reason = analytics_text("reason", injected_maximum=128)
    user_intent = analytics_text("user_intent", injected_maximum=256)
    if reason is None or user_intent is None:
        return None
    return reason, user_intent


def _domain_analytics_fields(tool: Any) -> frozenset[str]:
    fn_metadata = getattr(tool, "fn_metadata", None)
    arg_model = getattr(fn_metadata, "arg_model", None)
    model_fields = getattr(arg_model, "model_fields", None)
    if not isinstance(model_fields, Mapping):
        return frozenset()
    return frozenset(
        field
        for field in ("reason", "user_intent")
        if field in model_fields
    )


def _strip_analytics_arguments(tool: Any, tool_name: str, arguments: Any) -> Any:
    if tool_name == REPORT_OUTCOME_TOOL or not isinstance(arguments, dict):
        return arguments
    domain_fields = _domain_analytics_fields(tool)
    stripped = dict(arguments)
    for field in ("reason", "user_intent"):
        if field not in domain_fields:
            stripped.pop(field, None)
    return stripped


def _validate_domain_arguments(tool: Any, tool_name: str, arguments: dict[str, Any]) -> bool:
    fn_metadata = getattr(tool, "fn_metadata", None)
    arg_model = getattr(fn_metadata, "arg_model", None)
    validator = getattr(arg_model, "model_validate", None)
    if not callable(validator):
        return False
    candidate = _strip_analytics_arguments(tool, tool_name, arguments)
    try:
        validator(candidate)
    except Exception:
        return False
    return True


def _is_sensitive_argument_key(key: Any) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    if normalized in _SENSITIVE_ARGUMENT_KEYS:
        return True
    if normalized.startswith(("authorization_", "cookie_", "oauth_")):
        return True
    return normalized.endswith(_SENSITIVE_ARGUMENT_SUFFIXES)


def _redact_sensitive_arguments(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): (
                "<redacted>"
                if _is_sensitive_argument_key(key)
                else _redact_sensitive_arguments(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_sensitive_arguments(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_sensitive_arguments(item) for item in value]
    return value


def _telemetry_arguments(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    redacted = _redact_sensitive_arguments(arguments)
    if not isinstance(redacted, dict):
        return {}
    for field in _SENSITIVE_ARGUMENT_FIELDS_BY_TOOL.get(tool_name, frozenset()):
        if field in redacted:
            redacted[field] = "<redacted>"
    return redacted


def _request_headers(request_context: Any) -> Mapping[str, str]:
    request = getattr(request_context, "request", None)
    headers = getattr(request, "headers", None)
    if headers is None:
        return {}
    try:
        return dict(headers)
    except (TypeError, ValueError):
        return {}


def _incoming_trace_context(request_context: Any) -> Any:
    try:
        from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    except ImportError:
        return None
    headers = _request_headers(request_context)
    if not headers:
        return None
    try:
        return TraceContextTextMapPropagator().extract(carrier=headers)
    except Exception:
        return None


def _result_root(result: Any) -> Any:
    return getattr(result, "root", result)


def _result_is_error(root: Any) -> bool:
    return bool(getattr(root, "isError", False))


def _safe_result_json(root: Any, *, tool_name: str) -> str | None:
    if _result_is_error(root):
        return _canonical_json({"isError": True, "content": [{"type": "text", "text": "tool_error"}]})
    if tool_name in _SENSITIVE_RESULT_TOOLS:
        return _canonical_json({"redacted": True, "reason": "sensitive_tool_result"})
    model_dump = getattr(root, "model_dump", None)
    if callable(model_dump):
        try:
            value = model_dump(mode="json", by_alias=True)
        except (TypeError, ValueError):
            return None
    else:
        value = root
    try:
        redacted = _redact_sensitive_arguments(value)
        if (
            isinstance(redacted, dict)
            and isinstance(redacted.get("structuredContent"), (dict, list))
        ):
            redacted = {
                "isError": bool(redacted.get("isError", False)),
                "structuredContent": redacted["structuredContent"],
            }
        return _canonical_json(redacted)
    except (TypeError, ValueError):
        return None


def _tool_attributes(
    *,
    tool: Any,
    tool_name: str,
    arguments: dict[str, Any],
    reason: str,
    user_intent: str,
    request_id: Any,
    identity: Mapping[str, str],
    server_name: str,
) -> dict[str, Any]:
    attributes: dict[str, Any] = {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": tool_name,
        "gen_ai.tool.call.reason": reason,
        "session.user_intent": user_intent,
        "gen_ai.tool.call.arguments": _canonical_json(_telemetry_arguments(tool_name, arguments)),
        "mcp.method.name": "tools/call",
        "mcp.server.name": server_name,
        "gen_ai.tool.call.id": uuid.uuid4().hex,
        "mcp.request.id": str(request_id),
        **identity,
    }
    description = _description_attribute(getattr(tool, "description", None))
    if description is not None:
        attributes["gen_ai.tool.description"] = description
    input_schema = _schema_attribute(getattr(tool, "parameters", None))
    if input_schema is not None:
        attributes["gen_ai.tool.input_schema"] = input_schema
    output_schema = _schema_attribute(getattr(tool, "output_schema", None))
    if output_schema is not None:
        attributes["gen_ai.tool.output_schema"] = output_schema
    return attributes


def _flowlines_api_key(headers: str) -> str | None:
    values: list[str] = []
    for item in headers.split(","):
        if not item.strip():
            continue
        key, separator, value = item.partition("=")
        normalized_key = key.strip().lower()
        normalized_value = value.strip()
        if (
            not separator
            or normalized_key != "x-flowlines-api-key"
            or not normalized_value
        ):
            return None
        values.append(normalized_value)
    if len(values) != 1:
        return None
    return values[0]


def _has_flowlines_api_key(headers: str) -> bool:
    return _flowlines_api_key(headers) is not None


def _unsafe_flowlines_export_overrides() -> list[str]:
    return [
        name
        for name in _FLOWLINES_FORBIDDEN_EXPORT_ENV
        if os.environ.get(name, "").strip()
    ]


def _endpoint_is_flowlines() -> bool:
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip().rstrip("/")
    traces_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "").strip()
    candidate = traces_endpoint or endpoint
    if not candidate:
        return False
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname == "api.flowlines.ai"
        and port in (None, 443)
        and (not traces_endpoint or parsed.path in ("", "/", "/v1/traces", "/traces"))
    )


def _build_environment_tracer() -> tuple[Any | None, Any | None]:
    enabled = os.environ.get("GRABOWSKI_FLOWLINES_ENABLED", "").strip().lower()
    if enabled not in {"1", "true", "yes", "on"}:
        return None, None
    headers = os.environ.get("OTEL_EXPORTER_OTLP_HEADERS", "")
    api_key = _flowlines_api_key(headers)
    unsafe_overrides = _unsafe_flowlines_export_overrides()
    if api_key is None or not _endpoint_is_flowlines() or unsafe_overrides:
        LOGGER.warning(
            "Flowlines telemetry disabled: exact endpoint/header contract is not configured"
        )
        return None, None
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import ALWAYS_ON
    except ImportError:
        LOGGER.warning("Flowlines telemetry disabled: OpenTelemetry runtime dependencies are unavailable")
        return None, None

    try:
        exporter = OTLPSpanExporter(
            endpoint=_FLOWLINES_TRACE_ENDPOINT,
            headers={"x-flowlines-api-key": api_key},
            timeout=_FLOWLINES_EXPORT_TIMEOUT_SECONDS,
            max_request_size=_FLOWLINES_MAX_REQUEST_BYTES,
        )
        provider = TracerProvider(
            resource=Resource({"service.name": "grabowski-mcp"}),
            sampler=ALWAYS_ON,
            shutdown_on_exit=False,
        )
        provider.add_span_processor(
            BatchSpanProcessor(
                exporter,
                max_queue_size=_FLOWLINES_BSP_MAX_QUEUE_SIZE,
                schedule_delay_millis=_FLOWLINES_BSP_SCHEDULE_DELAY_MILLIS,
                max_export_batch_size=_FLOWLINES_BSP_MAX_EXPORT_BATCH_SIZE,
                export_timeout_millis=_FLOWLINES_BSP_EXPORT_TIMEOUT_MILLIS,
            )
        )
        tracer = provider.get_tracer("grabowski.flowlines")
    except Exception:
        LOGGER.warning(
            "Flowlines telemetry disabled: exporter initialization failed",
            exc_info=False,
        )
        return None, None
    return tracer, provider


def _bounded_flush(provider: Any, timeout_millis: int = 2_000) -> None:
    force_flush = getattr(provider, "force_flush", None)
    if not callable(force_flush):
        return
    try:
        force_flush(timeout_millis=timeout_millis)
    except Exception:
        LOGGER.warning("Flowlines telemetry force-flush failed", exc_info=False)


def _register_report_outcome(mcp: Any, read_only_annotations: Any) -> None:
    manager = getattr(mcp, "_tool_manager", None)
    if manager is None:
        raise RuntimeError("Flowlines requires the FastMCP tool manager")
    if manager.get_tool(REPORT_OUTCOME_TOOL) is not None:
        return

    @mcp.tool(name=REPORT_OUTCOME_TOOL, annotations=read_only_annotations)
    def report_outcome(
        reason: Annotated[str, Field(min_length=1, max_length=128)],
        user_intent: Annotated[str, Field(min_length=1, max_length=256)],
        status: Literal["accomplished", "partial", "failed"],
        outcome_summary: Annotated[str, Field(min_length=1, max_length=2_000)],
        unmet_needs: ReportOutcomeUnmetNeeds | None = None,
    ) -> dict[str, bool]:
        """REQUIRED final call in every conversation before the assistant gives its final answer.

        Accepts the agent's outcome self-report without mutating product data.
        When Flowlines export is enabled, this tool call is the telemetry report.
        Call it after read-only, accomplished, partial, failed, or blocked work.
        """
        del reason, user_intent, status, outcome_summary, unmet_needs
        return {"accepted": True}


def _install_strip_wrapper(manager: Any, *, require_context: bool) -> None:
    original = getattr(manager, "call_tool", None)
    if not callable(original):
        raise RuntimeError("Flowlines requires the FastMCP call_tool boundary")
    if getattr(original, _STRIP_MARKER, False):
        return

    async def flowlines_stripping_call_tool(*args: Any, **kwargs: Any) -> Any:
        if args:
            tool_name = args[0]
            arguments = args[1] if len(args) > 1 else kwargs.get("arguments")
            context = args[2] if len(args) > 2 else kwargs.get("context")
        else:
            tool_name = kwargs.get("name")
            arguments = kwargs.get("arguments")
            context = kwargs.get("context")

        tool = manager.get_tool(str(tool_name))
        if (
            require_context
            and context is not None
            and tool_name != REPORT_OUTCOME_TOOL
            and _validate_public_arguments(tool, str(tool_name), arguments) is None
        ):
            raise ValueError("Flowlines requires non-empty reason and user_intent")
        stripped = _strip_analytics_arguments(tool, str(tool_name), arguments)
        if len(args) > 1:
            mutable = list(args)
            mutable[1] = stripped
            return await original(*mutable, **kwargs)
        updated = dict(kwargs)
        updated["arguments"] = stripped
        return await original(*args, **updated)

    setattr(flowlines_stripping_call_tool, _STRIP_MARKER, True)
    manager.call_tool = flowlines_stripping_call_tool


def _install_lowlevel_handler(
    mcp: Any,
    tracer: Any | None,
    *,
    verified_identity_resolver: Callable[[Any], Mapping[str, Any] | None] | None,
) -> None:
    try:
        from mcp.types import CallToolRequest
    except ImportError as exc:
        raise RuntimeError("Flowlines requires MCP CallToolRequest support") from exc

    server = getattr(mcp, "_mcp_server", None)
    handlers = getattr(server, "request_handlers", None)
    if not isinstance(handlers, dict):
        raise RuntimeError("Flowlines requires the low-level MCP request handler registry")
    original = handlers.get(CallToolRequest)
    if not callable(original):
        raise RuntimeError("Flowlines tools/call handler is unavailable")
    if getattr(original, _HANDLER_MARKER, False):
        return

    async def flowlines_call_tool_handler(req: Any) -> Any:
        arguments = getattr(getattr(req, "params", None), "arguments", None) or {}
        tool_name = getattr(getattr(req, "params", None), "name", None)
        if not isinstance(tool_name, str) or not isinstance(arguments, dict):
            return await original(req)

        manager = getattr(mcp, "_tool_manager", None)
        tool = manager.get_tool(tool_name) if manager is not None else None
        public = _validate_public_arguments(tool, tool_name, arguments)
        if tool is None or public is None or not _validate_domain_arguments(tool, tool_name, arguments):
            return await original(req)

        try:
            request_context = server.request_context
        except LookupError:
            return await original(req)
        meta = _meta_mapping(request_context)
        verified: Mapping[str, Any] | None = None
        if verified_identity_resolver is not None:
            try:
                candidate = verified_identity_resolver(request_context)
                if isinstance(candidate, Mapping):
                    verified = candidate
            except Exception:
                verified = None
        identity = _identity_from_meta(meta, verified)
        if tracer is None or identity is None:
            return await original(req)

        reason, user_intent = public
        try:
            attributes = _tool_attributes(
                tool=tool,
                tool_name=tool_name,
                arguments=arguments,
                reason=reason,
                user_intent=user_intent,
                request_id=getattr(request_context, "request_id", ""),
                identity=identity,
                server_name=str(getattr(mcp, "name", "grabowski-mcp")),
            )
            incoming_context = _incoming_trace_context(request_context)
            from opentelemetry.trace import SpanKind, Status, StatusCode

            span_context = tracer.start_as_current_span(
                f"execute_tool {tool_name}",
                context=incoming_context,
                kind=SpanKind.SERVER,
                attributes=attributes,
                record_exception=False,
                set_status_on_exception=False,
            )
            span = span_context.__enter__()
        except Exception:
            LOGGER.warning("Flowlines telemetry span setup failed open", exc_info=False)
            return await original(req)

        try:
            result = await original(req)
        except BaseException as error:
            try:
                span.set_status(Status(StatusCode.ERROR))
                span.set_attribute("error.type", type(error).__name__[:256])
            except Exception:
                pass
            try:
                span_context.__exit__(type(error), error, error.__traceback__)
            except Exception:
                LOGGER.warning("Flowlines telemetry span close failed open", exc_info=False)
            raise

        root = _result_root(result)
        is_error = _result_is_error(root)
        try:
            encoded_result = _safe_result_json(root, tool_name=tool_name)
            if encoded_result is not None:
                span.set_attribute("gen_ai.tool.call.result", encoded_result)
            span.set_status(Status(StatusCode.ERROR if is_error else StatusCode.OK))
            if is_error:
                span.set_attribute("error.type", "tool_error")
        except Exception:
            # Telemetry is fail-open after the domain call. Never retry the tool.
            pass
        try:
            span_context.__exit__(None, None, None)
        except Exception:
            LOGGER.warning("Flowlines telemetry span close failed open", exc_info=False)
        return result

    setattr(flowlines_call_tool_handler, _HANDLER_MARKER, True)
    handlers[CallToolRequest] = flowlines_call_tool_handler


def configure_flowlines_observability(
    mcp: Any,
    read_only_annotations: Any,
    *,
    tracer: Any | None = None,
    provider: Any | None = None,
    verified_identity_resolver: Callable[[Any], Mapping[str, Any] | None] | None = None,
) -> dict[str, Any]:
    if getattr(mcp, _INSTALL_MARKER, False):
        return {"installed": True, "already_installed": True}

    _register_report_outcome(mcp, read_only_annotations)
    manager = getattr(mcp, "_tool_manager", None)
    if manager is None:
        raise RuntimeError("Flowlines requires the FastMCP tool manager")
    for tool in manager.list_tools():
        if getattr(tool, "name", None) != REPORT_OUTCOME_TOOL:
            _augment_tool_schema(tool)

    if tracer is None:
        tracer, provider = _build_environment_tracer()
    _install_strip_wrapper(manager, require_context=tracer is not None)
    _install_lowlevel_handler(
        mcp,
        tracer,
        verified_identity_resolver=verified_identity_resolver,
    )
    if provider is not None:
        atexit.register(_bounded_flush, provider)

    setattr(mcp, _INSTALL_MARKER, True)
    return {
        "installed": True,
        "already_installed": False,
        "export_enabled": tracer is not None,
        "identity_source": "verified_subject_or_client_meta_user.id",
        "session_source": "client_meta_session.id",
    }
from __future__ import annotations

from typing import Any

import grabowski_agent_workspace as workspace
import grabowski_agent_workspace_observer as observer
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY


def build_attention_trace(workspace_id: str) -> dict[str, Any]:
    """Project the existing integrity-bound workspace events as attention_trace_v1."""
    identifier = workspace._required_string(workspace_id, "workspace_id", max_length=80)
    if workspace.WORKSPACE_ID_RE.fullmatch(identifier) is None:
        raise ValueError("workspace_id is invalid")
    manifest = workspace._manifest(identifier)
    events, event_log = observer._read_events(identifier)
    return observer._attention_trace(identifier, manifest, events, event_log)


@mcp.tool(name="grabowski_attention_trace_v1", annotations=READ_ONLY)
def grabowski_attention_trace_v1(workspace_id: str) -> dict[str, Any]:
    """Read one evidence-bound agent activity trace without inferring hidden attention."""
    return build_attention_trace(workspace_id)

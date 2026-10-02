# PostHog MCP Analytics

## Purpose

Grabowski can optionally emit metadata-only MCP tool-call telemetry to PostHog.
The integration is an observation seam, not an authority source and not a
replacement for Grabowski audit, runtime, lease, Git, CI, or deployment truth.

The integration is disabled when no valid project token is configured. It
fails open: PostHog import, configuration, initialization, transmission, or
shutdown failures must not make an operator tool fail.

## Privacy boundary

Only the PostHog event $mcp_tool_call is allowed to leave Grabowski. The final
before_send projection keeps only:

- tool name;
- wall-clock duration;
- boolean error state;
- PostHog library/source metadata;
- Grabowski server/protocol metadata;
- opaque session ID when the SDK already has one.

It always disables GeoIP enrichment and person-profile processing and replaces
the event distinct_id with the constant grabowski-mcp-anonymous.

The following are deliberately not exported:

- tool arguments or parameters;
- tool results or response bodies;
- agent intent or user goal text;
- model identity;
- error messages or exception payloads;
- custom event properties;
- sibling $exception events;
- PostHog conversation or feedback fields.

Accordingly the SDK is configured with context=False,
enable_conversation_id=False, capture_model=False,
enable_exception_autocapture=False, report_missing=False, and
collect_feedback=False. These settings also prevent PostHog from adding
analytics arguments or conversation blocks to Grabowski's public MCP surface.

## Activation

Production activation is explicit. Configure a PostHog project token by either:

1. placing only the token in
   ~/.config/grabowski/posthog-project-token, owned by the operator user and
   mode 0600 or stricter; or
2. setting GRABOWSKI_POSTHOG_PROJECT_TOKEN.

The fixed token file is the preferred durable path because it does not put the
token in repository state. The file is opened without symlink following, must have exactly one hard
link, is validated as a small private regular file owned by the operator user,
and is rejected if its identity or size changes while being read. The token
must contain no whitespace, including a trailing newline. Its contents are never
logged.

The default ingestion origin is https://eu.i.posthog.com. The optional
GRABOWSKI_POSTHOG_HOST override accepts only the EU or US PostHog HTTPS
ingestion origins.

GRABOWSKI_POSTHOG_MCP_ANALYTICS=0 explicitly disables the integration even
when a token exists. A truthy value explicitly requests activation and logs a
warning if no token is available. When the switch is unset, presence of a
valid token is the opt-in signal.

## Runtime ordering

PostHog instrumentation is installed before Grabowski builds the Streamable HTTP
application. The HTTP runtime setup then installs Grabowski's deployment and
authority gate around the instrumented tool-call boundary. Reversing this order
would leave an already-built HTTP application without PostHog's stateless MCP
middleware and would let the SDK replace the previously installed outer
Grabowski call boundary.

## Verification

A production claim requires both sides of the path:

1. fresh Grabowski runtime identity and audit health;
2. one real read-only MCP call through the deployed process;
3. a fresh PostHog readback showing $mcp_tool_call with the expected tool
   name, duration and error state;
4. verification that no forbidden content properties are present.

PostHog data is observational evidence only. It never proves repository,
deployment, authorization, or audit state.
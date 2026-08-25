# Juno OpenAI-compatible Gateway

## Purpose

This gateway gives Juno on the iPad one controlled OpenAI-compatible endpoint without turning Juno into a second Grabowski operator or storing provider credentials in Juno.

Target path:

`Juno -> Tailscale HTTPS -> heim-pc -> loopback gateway -> Grabowski coding-agent router -> non-paid Codex advisory route`

The gateway is intentionally advisory-only. It does not expose repository mutation, Bureau mutation, shell access, MCP tools, browser tools, or direct provider selection.

## API contract

The service listens on `127.0.0.1:18195` by default and exposes:

- `GET /healthz` — minimal unauthenticated liveness response; no secret or route detail.
- `GET /v1/models` — Bearer-authenticated; exposes exactly `grabowski-juno`.
- `POST /v1/chat/completions` — Bearer-authenticated text chat.

`stream=false` returns a normal OpenAI-style chat completion. `stream=true` returns a buffered SSE response containing one content chunk, one stop chunk, and `[DONE]`. This is compatibility streaming, not token-by-token backend streaming.

The v1 contract is deliberately narrow. Text and text content parts are supported. Tool/function calling, images, audio, arbitrary model names, multiple choices, and unknown request fields are rejected. Request size, message count, per-message size, total content, output size, timeout, and concurrency are bounded.

Sampling and token-budget fields that compatible clients commonly send may be accepted for wire compatibility, but they are not used to weaken the selected Grabowski route or its safety policy.

## Routing and cost boundary

Every chat request performs fresh route selection through Grabowski's coding-agent router with:

- `allow_paid=false`;
- Codex as the only allowed harness;
- `private-context` and `user_data` risk flags;
- advisory/contrast authority only.

The selected route is then revalidated with `advisory_route_execution_contract(..., paid_execution_authorized=False)` immediately before execution. A paid route, OpenRouter route, non-Codex harness, non-advisory authority, invalid route contract, stale/unavailable quota state, or missing safe route fails closed with HTTP 503.

There is no PAYG fallback, no OpenRouter direct path, and no Ollama fallback.

## Execution boundary

The Codex subprocess runs:

- in a fresh temporary directory;
- with `--sandbox read-only`;
- with `--ephemeral`;
- with repository checks skipped because no repository is supplied;
- with user config and repository rules ignored;
- with shell/unified exec, hooks, apps, browser/computer and in-app surfaces, plugins, multi-agent, image/view tools, skill/tool discovery, elicitation, workspace dependency handling, remote plugins, and dependency-install tooling disabled;
- with a strict inherited-environment allowlist limited to runtime basics such as HOME, PATH, locale, TLS certificate paths, TMPDIR, and XDG_RUNTIME_DIR; arbitrary inherited credentials and private environment values are not forwarded;
- with the conversation prompt supplied over stdin rather than process argv, so chat content is not exposed through the Codex command line;
- with only the final response file used as the user-visible model answer.

The gateway prompt also tells the advisory model not to use tools or external/local resources. The command-line and systemd boundaries, rather than that prompt, are the primary controls.

The service's systemd sandbox hides the normal home tree. It binds the deployed Grabowski runtime, the coding-agent router state, the gateway state, and the Codex installation/state explicitly. Codex needs its own `.codex` state writable for authenticated operation; that is the main residual local-write boundary. The service is intended for a single trusted owner, not multi-tenant use.

## Secret contract

The gateway Bearer token lives at:

`~/.local/state/grabowski/juno-openai-gateway/token`

The installer creates it once with owner-only permissions and never prints its contents. The gateway rejects a symlink, non-regular file, wrong owner, extra hard link, broad permissions, or invalid token size/content. Logs must never contain the token, request body, or response body.

Provider API keys are neither accepted by the gateway nor inherited by the Codex subprocess. The subprocess environment is allowlisted rather than secret-name blacklisted, so unrelated credential variables are excluded by default.

## Installation

After the gateway code has been merged and the exact merge revision deployed into the Grabowski runtime:

`tools/install_juno_openai_gateway.py`

The installer:

1. creates or validates the private token;
2. atomically copies the reviewed gateway source to `~/.local/libexec/grabowski/grabowski_juno_openai_gateway.py` and records its SHA-256;
3. installs the user systemd unit;
4. reloads user systemd;
5. enables and starts the service;
6. checks `/healthz` and the authenticated `/v1/models` endpoint locally.

The service imports the current deployed Grabowski routing modules through the release symlink at `~/.local/share/grabowski-mcp/inputs/src`, while the gateway executable itself remains the exact hash copied by the installer. A later gateway code change therefore requires rerunning the installer after the new revision is merged; an unrelated Grabowski runtime refresh does not silently replace the gateway executable.

It intentionally does **not** modify Tailscale Serve.

## Tailnet publication

Publication is a separate operator action after local service readback. Use Tailscale **Serve**, never Funnel, and preserve existing Serve handlers.

If port `9450` is still unclaimed at mutation time, the intended mapping is:

`https://heim-pc.<tailnet>.ts.net:9450/v1/... -> http://127.0.0.1:18195/v1/...`

The exact current tailnet hostname, occupied ports, and existing handlers must be read immediately before mutation. A post-change readback must prove that the existing handlers are unchanged and the new handler is tailnet-only.

## Juno configuration

In Juno Connect, configure the OpenAI-compatible provider with:

- Base URL: the current Tailscale Serve HTTPS URL for this gateway;
- Model: `grabowski-juno`;
- API key: the gateway Bearer token.

Do not put an OpenRouter or other provider API key into this gateway profile. The current Grabowski Juno worker surface does not provide a documented authority to mutate Juno's provider UI, so that UI binding must remain an explicit user/UI step unless a safe supported automation surface is added later.

## Non-goals

This gateway is not:

- a new Grabowski control plane;
- a repository or Bureau execution endpoint;
- a general-purpose proxy to arbitrary OpenAI-compatible providers;
- a paid-route escape hatch;
- a public internet service;
- a replacement for the existing Juno session-bound worker integration.

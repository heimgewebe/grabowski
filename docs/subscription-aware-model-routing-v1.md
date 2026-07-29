# Subscription-aware model routing v1

## Decision

Grabowski routes external model work by task fit and expected review quality **inside already-paid subscription baselines**. It does not balance traffic merely to distribute consumption across providers.

A subscription establishes a zero-additional-cost routing baseline only for the provider surface covered by that subscription. It never establishes permission to consume API pay-as-you-go, purchased credits, or provider overage.

## Authority boundary

ChatGPT remains the controller and Grabowski remains the authoritative local execution layer. External model harnesses are advisory only:

- they may provide independent review or explicit contrast;
- they may not become the authoritative writer;
- they may not apply patches, commit, push, merge, deploy, or alter lifecycle truth;
- their availability does not authorize parallel work by itself.

Codex is an explicit contrast surface only. Because ChatGPT and Codex are in the same OpenAI lineage, Codex is never counted as an independent external review of the controller.

## Verified subscription baselines

Observed on 2026-07-29:

| Provider | Canonical local plan label | Live evidence | Included routing surface | Excluded cost surfaces |
| --- | --- | --- | --- | --- |
| OpenAI | ChatGPT Pro | owner assertion; `codex login status` reports ChatGPT login; `gpt-5.6-sol` xhigh smoke passed | Codex CLI contrast | OpenAI API, purchased Codex credits |
| Anthropic | Claude Pro | `claude auth status` reports `subscriptionType: pro`; Sonnet 5 and Opus 5 smokes passed | Claude Code review and contrast | Anthropic API, usage credits |
| Google | Google AI subscription | owner assertion; Antigravity `gemini-3.1-pro-high` smoke passed | Antigravity and Jules baseline | Vertex AI API, Google AI Studio API, purchased AI credits |
| xAI | SuperGrok | Grok authentication reports `subscription_tier: SuperGrok`; `grok-4.5-build` smoke passed | Grok Build review and contrast | xAI API, extra usage credits, pay-as-you-go overage |

The exact Google AI tier is not exposed by the local harness. The catalog therefore records the subscription family and the verified Antigravity entitlement without inventing a narrower tier.

The user-facing phrase “Claude Plus” is normalized to the server-reported product label **Claude Pro**.

## Model evidence

The live harness probes supersede stale catalog generations:

- Claude alias `opus` resolves to Claude Opus 5.
- Claude alias `sonnet` resolves to Claude Sonnet 5.
- Fable 5 returns `usage-credits-required`; it is not part of the Claude Pro baseline.
- Antigravity exposes Gemini 3.1 Pro and Gemini 3.6 Flash.
- Codex resolves its current high-end subscription route to GPT-5.6 Sol.
- Grok Build resolves the SuperGrok route to Grok 4.5 Build.

Old model identifiers may remain as disabled compatibility records. They are not preferred routes.

## Routing policy

The router evaluates candidates in this order:

1. authoritative direct-operator boundary;
2. task class and required review role;
3. model quality prior and effort level;
4. harness reliability and measured outcomes;
5. remaining subscription quota and provider health;
6. delegation overhead.

Provider diversity is used only when it improves independence or technical coverage. It is not a traffic-balancing target.

### Review routes

- `claude-opus-5-high`: judgment-heavy, security, architecture, and critical review through the Claude Pro baseline.
- `antigravity-gemini-pro-review-high`: independent Google-family review through the Google AI baseline.
- `grok-4.5-review-high`: independent xAI review through SuperGrok; one turn, no web search, no subagents, no memory, plain structured output.

All direct Claude Pro routes use the same `anthropic-claude-pro` independence group. Two Claude models therefore never satisfy a two-provider independence requirement.

### Contrast routes

Codex routes are contrast-only. Legacy Gemini Pro and Grok high routes remain contrast-only; dedicated review routes carry review semantics separately.

### Paid-only routes

Fable 5 remains disabled or explicit-paid-only. Its live probe required usage credits. It may run only after separate paid authorization and a positive hard budget. It is never selected from the Claude Pro baseline.

## Quota exhaustion

When a subscription baseline is exhausted or entitlement evidence is unavailable:

1. mark the route unavailable for automatic selection;
2. surface the quota or entitlement blocker;
3. route to another subscription baseline only when task fit remains acceptable;
4. otherwise keep the work with the direct operator or stop the external review;
5. never fall through to API pay-as-you-go, purchased credits, or provider overage.

The default action is `block_and_surface`.

## Runtime contract

The Grok candidate runner uses a route-bound schema-3 packet and resolves the owner-controlled native binary behind `~/.grok/bin/grok`. The npm/Node trampoline is not executed and no user-session DBus access is exposed. The resolved target must remain inside `~/.grok/bin`, be owner-controlled, executable, and not group- or world-writable.

The logical receipt remains bound to this constrained command shape:

```text
grok --model grok-4.5 --prompt-file <isolated-prompt.txt> \
  --max-turns 1 --disable-web-search --no-subagents --no-memory \
  --permission-mode plan --tools= --json-schema <candidate-schema>
```

`--prompt-file` removes the need for a file-reading tool. The empty tool set prevents terminal and filesystem tool execution. Grok must return one completed-turn envelope whose parsed `text` exactly matches `structuredOutput`; receipt validation rechecks the command, schema, envelope and repository snapshots.

## Nonclaims

This contract does not establish:

- unlimited subscription capacity;
- exact remaining quota;
- permission to consume credits or API spend;
- independence between models from the same provider lineage;
- correctness of an external review;
- authority for an external model to implement or merge changes.

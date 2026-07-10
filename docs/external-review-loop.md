# External review loop

Grabowski separates three independent merge controls:

1. Grabowski self-review of the current PR diff.
2. External LLM review evidence where policy requires it.
3. CI, mergeability, current-head binding, current-diff binding, and terminal finding triage.

No control substitutes for another. A GitHub comment, review body, or model summary is not self-review evidence.

## Policy matrix

| Lane | External review | Claude CLI packet review |
| --- | --- | --- |
| Ordinary documentation-only PR | Exempt | No |
| Very small uncomplicated PR in a standard repository | Exempt | No |
| Normal non-trivial PR in a standard repository | Required; any structured current-diff LLM review may qualify | No |
| High-critical PR | Required | Yes |
| Any non-documentation-only PR in `heimgewebe/weltgewebe` | Required | Yes |
| Ordinary documentation-only PR in `heimgewebe/weltgewebe` | Exempt | No |

Policy-critical documentation is not ordinary documentation. `GRABOWSKI.md`, `AGENTS.md`, `docs/external-review-loop.md`, operator/recovery/deploy doctrine, generated structured data, build/config/CI/packaging files, lock files, and binary-like zero-line diffs do not receive the ordinary documentation or tiny-change exemption.

Repository identity is canonicalized only from a valid GitHub owner/repository slug or the equivalent GitHub URL/SSH form. Invalid repository identity blocks the gate; it cannot silently remove Weltgewebe from the special lane.

## Create head- and diff-bound scaffolds

Create the self-review template and external review packet once per PR head and diff:

```bash
python3 tools/pr_review_gate.py \
  --pr <PR_NUMBER> \
  --write-self-review-template evidence/pr-<PR_NUMBER>-self-review-template.json \
  --write-external-review-packet evidence/pr-<PR_NUMBER>-external \
  --json
```

The packet contains:

- repository and PR identity;
- current PR head SHA;
- SHA-256 of the exact `gh pr diff` bytes;
- reviewer instructions and their SHA-256;
- the complete PR diff as a downloadable file;
- an external-evidence template and packet manifest.

Any head or diff change invalidates the packet, self-review, external review, and triage. Regenerate all artifacts after every such change.

Run the repeatable gate only with completed evidence:

```bash
python3 tools/pr_review_gate.py \
  --pr <PR_NUMBER> \
  --self-review evidence/self-review.json \
  --external-review-evidence evidence/external-review.json \
  --json
```

External-review-exempt PRs still require completed self-review evidence; omit only external evidence.

## Grabowski self-review

Self-review must inspect the actual current diff and record:

- `kind: grabowski_self_review` and `review_mode: critical_diff_review`;
- exact repository, PR, head SHA, and current diff SHA-256;
- `PASS|NEEDS_CHANGE|BLOCK` verdict;
- every current PR file in `reviewed_files`;
- focus axes `correctness`, `regression_risk`, `tests`, `security`, and `integration`;
- review iterations and material findings;
- terminal triage for every finding;
- zero remaining material findings for a passing gate.

The generated template is only a scaffold. It does not pass until an actual critical diff review has replaced all placeholders.

## Required Claude CLI packet review

`tools/external_review_claude.py` is the mandatory provider for high-critical PRs and every non-documentation-only PR in `heimgewebe/weltgewebe`.

The adapter:

1. verifies packet paths and packet hashes;
2. verifies repository identity, PR head, and live `gh pr diff` hash;
3. builds one prompt from the packet instructions plus the exact packet diff;
4. hashes the exact UTF-8 bytes that will be sent;
5. sends those bytes only through stdin;
6. runs Claude non-interactively with no tools, Plan permission mode, no persistent session, Safe Mode, model `opus`, effort `high`, and a finite budget;
7. accepts only the CLI `structured_output` object validated against the required JSON schema;
8. verifies repository identity, PR head, and live diff again after the review;
9. stores raw output and structured evidence only after all post-checks pass.

Run it with the packet manifest:

```bash
python3 tools/external_review_claude.py \
  --manifest evidence/pr-<PR_NUMBER>-external/pr-<PR_NUMBER>-<head>-external-review-manifest.json \
  --repo /path/to/repository \
  --output evidence/pr-<PR_NUMBER>-external/claude-external-review-evidence.json \
  --timeout-minutes 30 \
  --max-budget-usd 2
```

The accepted command shape is exact apart from the positive finite budget value:

```text
claude -p \
  --output-format json \
  --json-schema <required-schema> \
  --tools= \
  --permission-mode plan \
  --no-session-persistence \
  --safe-mode \
  --model opus \
  --effort high \
  --max-budget-usd <positive-finite-number>
```

Unknown flags, alternative ordering, `--print` in place of `-p`, enabled tools, mutation-oriented permission modes, another model, another effort level, a different schema, and non-finite or non-positive budgets are rejected by the gate.

The default budget is `2.0` USD. This is a controlled initial ceiling, not a guarantee that every large review will finish. A budget failure produces no passing evidence. Increase the ceiling only deliberately and keep it finite. When Claude reports them, evidence records actual cost, usage/model usage, CLI durations, turn count, and measured runtime.

Claude failure, timeout, empty output, invalid JSON, missing `structured_output`, API/auth/budget failure, packet mismatch, repository mismatch, head drift, diff drift, prompt-hash mismatch, stdin-hash mismatch, or an unknown command shape fails closed. There is no silent Gemini, ChatGPT, or Ultrareview fallback on a Claude-required lane.

Claude findings are never auto-triaged. `PASS` is valid only with zero findings. `NEEDS_CHANGE` and `BLOCK` require at least one concrete finding and keep the gate closed until every finding is checked against the diff and terminally recorded.

### Packet-review evidence binding

A required Claude entry uses:

```json
{
  "schema_version": 1,
  "kind": "external_review",
  "repo": "heimgewebe/grabowski",
  "pr": 141,
  "head_sha": "<current-head>",
  "diff_sha256": "<current-diff-sha256>",
  "prompt_sha256": "<sha256-of-actual-stdin-bytes>",
  "prompt_includes_diff": true,
  "prompt_transmitted": true,
  "review_input": {
    "mode": "claude_packet_prompt",
    "repo": "heimgewebe/grabowski",
    "pr": 141,
    "head_sha": "<current-head>",
    "diff_sha256": "<current-diff-sha256>",
    "packet_prompt_sha256": "<packet-instructions-sha256>",
    "prompt_sha256": "<sha256-of-actual-stdin-bytes>",
    "transport": "stdin"
  },
  "reviews": [
    {
      "source": "claude-cli:packet-review",
      "tool": "claude-code",
      "tool_version": "<non-empty-version>",
      "command": ["claude", "-p", "... exact allowed flags ..."],
      "model": "opus",
      "effort": "high",
      "stdin_sha256": "<same-prompt-sha256>",
      "exit_code": 0,
      "json_ok": true,
      "review_sha256": "<raw-cli-result-sha256>",
      "verdict": "PASS",
      "finding_count": 0
    }
  ],
  "external_reviews_triaged": true,
  "findings": []
}
```

The top-level prompt hash, `review_input.prompt_sha256`, and review `stdin_sha256` must match. The gate independently rebuilds the deterministic packet instructions from the current repository, PR, head, diff filename, diff hash, and PR metadata, then compares that SHA-256 with `review_input.packet_prompt_sha256`. This makes the packet-instruction hash load-bearing instead of a descriptive audit field and prevents combining another packet prompt with the current diff.

## Optional providers and optional Ultrareview

`tools/external_review_agy.py` remains available for ordinary non-exempt PRs. It may produce structured, head- and diff-bound Gemini/agy evidence. It does not satisfy a Claude-required lane merely because it is an external model.

Claude CLI `ultrareview` may be run as an additional independent review when quota is available. It is never the mandatory provider and never a single point of failure for this gate. Legacy `--claude-evidence` remains accepted only as diagnostic input; it cannot satisfy `claude-cli:packet-review`.

## Explicit Claude policy waiver

There is no silent fallback. A Claude-required lane may omit `claude-cli:packet-review` only when `pr_review_gate.py` receives an explicit waiver with `--policy-waiver <path>`. The waiver is narrow: it removes only the Claude-provider requirement. A structured, current-diff external review from another provider remains required, as do Grabowski self-review, terminal finding triage, CI, mergeability, and current head/diff binding.

The waiver JSON must contain exactly these fields:

```json
{
  "schema_version": 1,
  "kind": "claude_packet_review_policy_waiver",
  "scope": "claude_packet_review_only",
  "repo": "heimgewebe/grabowski",
  "pr": 141,
  "head_sha": "<current-40-hex-head>",
  "diff_sha256": "<current-diff-sha256>",
  "authority": "trusted-owner",
  "approver": "<named trusted-owner decision maker>",
  "reason": "<specific bounded exception reason>",
  "issued_at": "2026-07-10T10:00:00+00:00",
  "expires_at": "2026-07-10T18:00:00+00:00",
  "audit_reference": "<durable decision or incident receipt>"
}
```

The gate rejects missing or unknown fields, invalid authority or scope, repo/PR/head/diff mismatch, timestamps without timezone, future-dated issuance beyond five minutes of clock skew, expiry, and lifetimes longer than 24 hours. The complete waiver and its validation outcome are echoed in gate JSON. This is an auditable emergency path, not a normal alternate provider and not permission to claim Claude reviewed the PR.

A successful adapter invocation is the capability proof for the installed Claude CLI and records its actual version. If an upstream CLI flag or result-envelope contract changes, the run fails closed with the CLI error; repair can proceed only through the explicit waiver plus a qualifying independent external review.

## External finding triage

For all external evidence:

- `head_sha` and `diff_sha256` must match the current gate state;
- every review needs a source, review hash, verdict, and non-negative integer finding count;
- `external_reviews_triaged` must be true for a passing gate;
- every reported finding must have terminal top-level triage;
- a non-PASS review without terminal finding coverage blocks;
- count coverage prevents obvious under-recording but does not identify findings cryptographically.

Terminal statuses remain `fixed`, `accepted`, `false_positive`, `deferred_with_reason`, and `not_applicable`, subject to severity/materiality restrictions. Strong or blocking findings cannot be accepted or deferred as a passing shortcut.

## Threat model

Hashes are integrity and reproducibility handles, not external identity signatures. The adapter proves what the local trusted operator process sent and received, and the gate checks the resulting structure and bindings. A party that can arbitrarily rewrite all local artifacts can still fabricate unsigned evidence and matching hashes.

Stronger identity guarantees would require a signature or attestation rooted outside the operator's write path, stable finding IDs, protected artifact storage, or branch-protection enforcement. Those are not introduced here.

The relevant safety gain in this version is narrower and concrete: the genuine adapter cannot silently review another head, another diff, another packet, another command shape, or model text outside `structured_output`; and the gate does not treat Claude as a replacement for self-review, CI, mergeability, or finding triage.

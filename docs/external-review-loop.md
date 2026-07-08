# External review loop

`tools/pr_review_gate.py` requires separate external LLM review evidence for every pull request except documentation-only changes and very small uncomplicated changes. High-critical pull requests also require a platform review from Codex or Claude. High-critical classification is derived from large file/line counts, generic runtime/deploy/security/migration/privilege/recovery/policy path markers, Grabowski operator-critical paths, self-review uncertainty, and material findings after the first review.

The external loop is separate from Grabowski self-review. Self-review remains internal evidence; external review evidence is passed with its own CLI argument. Use the packet writer whenever an external LLM review is needed so the diff is available as a downloadable artifact:

## Evidence, not comments

A GitHub PR comment that says the operator checked the PR is not review evidence and must not be treated as a merge gate.

Before merge, Grabowski must run its own critical review against the current PR head and current PR diff. That review has to inspect the diff itself, challenge the approach, record review iterations, record material findings, and terminally triage every finding in structured self-review evidence. Do not write the self-review text into the pull request as a review comment; the PR may at most reference the evidence artifact path/hash/status.

For every non-exempt PR, Grabowski must start an external LLM review loop before merge by handing the user a portable review packet. The packet must contain repo, PR number, current head SHA, diff hash, exact reviewer instructions, an evidence template, and the full PR diff as a downloadable file suitable for another model. Required external review remains blocking until returned findings are triaged and supplied as external review evidence, unless the user consciously overrides that gate outside this automated policy.

```bash
python3 tools/pr_review_gate.py \
  --pr <PR_NUMBER> \
  --write-external-review-packet evidence/pr-<PR_NUMBER>-external \
  --self-review evidence/self-review.json \
  --external-review-evidence evidence/external-review.json
```

For high-critical PRs, include `--claude-evidence evidence/claude.json` when Claude CLI evidence is used instead of a current-head trusted Claude review object.

Minimal external evidence object:

```json
{
  "schema_version": 1,
  "kind": "external_review",
  "repo": "heimgewebe/grabowski",
  "pr": 70,
  "head_sha": "<current PR head SHA>",
  "diff_sha256": "<sha256 of current PR diff>",
  "prompt_sha256": "<sha256 of exact prompt sent externally>",
  "prompt_includes_diff": true,
  "reviews": [
    {
      "source": "chatgpt|claude|gemini|other",
      "review_sha256": "<sha256 of returned review text>",
      "verdict": "PASS|NEEDS_CHANGE|BLOCK",
      "finding_count": 0
    }
  ],
  "external_reviews_triaged": true,
  "findings": []
}
```

Rules:

- `head_sha` must match the current PR head.
- `diff_sha256` must match the current PR diff hash computed by the gate from `gh pr diff`.
- `prompt_sha256` and each `review_sha256` must be valid SHA-256 hex strings.
- `prompt_includes_diff` must be true, but this is only the operator's assertion that the external prompt contained the diff.
- `reviews` must be a list and must be non-empty when the external loop is required.
- Each review entry must include `source`, `review_sha256`, `verdict`, and integer `finding_count >= 0`.
- `source` is a human-readable label for traceability. It is not a trust anchor and does not prove reviewer identity.
- `external_review.required`, when present, must be a boolean. A required external review cannot be disabled by setting `required=false` in evidence.
- `external_reviews_triaged` must be true.
- `findings` must be a list, and every finding must be terminally triaged with the same terminal status rules as Grabowski self-review findings.
- A review with `verdict != "PASS"` or `finding_count > 0` must be covered by terminal top-level `findings[]`; `findings: []` cannot hide a documented external blocker.
- `external_reviews_triaged=true` states that triage happened; it does not replace finding records.
- V1 uses count coverage rather than finding IDs: reported external findings must be no greater than terminal top-level findings, and a non-PASS review with `finding_count: 0` counts as one reported finding.
- Count coverage is not identity-binding. It only prevents obvious under-recording; it does not bind a specific reported finding to a specific terminal finding.
- Deprecated `self_review.external_review` is ignored. Use `--external-review-evidence` for external evidence.
- Documentation-only PRs and very small uncomplicated PRs with no external evidence do not block. If voluntary external evidence is passed, its findings are still validated.
- Policy-critical documentation such as `GRABOWSKI.md`, `AGENTS.md`, `docs/external-review-loop.md`, and operator/recovery/deploy doctrine is not documentation-exempt.
- Very small changes are not exempt when they touch build, config, CI, packaging, controlled tool paths, structured data, lock files, or zero-line/binary-like diffs.
- Non-trivial non-documentation PRs require external LLM evidence even when Codex or Claude is not required.
- High-critical PRs require both external LLM evidence and at least one platform review from Codex or Claude.

Threat model:

The hashes are audit and integrity handles, not identity guarantees. They help detect accidental drift and make review artifacts reproducible against the current diff. They do not prove that an external reviewer really produced the review if the same operator can freely write prompt, review text, hashes, `source`, and triage records.

`prompt_includes_diff=true` is an assertion by the evidence author, not a cryptographic proof. The gate validates shape, head binding, diff-hash binding, and count coverage; it does not validate prompt contents directly. It also cannot prove that the external model saw the same prompt whose hash is recorded.

A stronger model would use stable finding IDs, signed prompt/review artifacts, branch protection, externally stored attestations, or reviewer identity backed by a system outside the operator's write path. Those are outside this PR.

This is not a substitute for Grabowski self-review, high-critical platform review, or CI. It is a contrast loop: different reviewer failure modes, not ritual mass.

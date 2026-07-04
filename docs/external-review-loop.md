# External review loop

`tools/pr_review_gate.py` requires separate external review evidence when a pull request is classified as complex/risky or when the external evidence explicitly marks itself as required. Complexity is currently derived from file count, diff size, risk paths, self-review uncertainty, and material findings after the first review.

The external loop is separate from Grabowski self-review. Self-review remains internal evidence; external review evidence is passed with its own CLI argument:

```bash
python3 tools/pr_review_gate.py \
  --pr <PR_NUMBER> \
  --self-review evidence/self-review.json \
  --claude-evidence evidence/claude.json \
  --external-review-evidence evidence/external-review.json
```

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
- `external_review.required`, when present, must be a boolean. A complex/risky PR cannot be unblocked by setting `required=false` in evidence.
- `external_reviews_triaged` must be true.
- `findings` must be a list, and every finding must be terminally triaged with the same terminal status rules as Grabowski self-review findings.
- A review with `verdict != "PASS"` or `finding_count > 0` must be covered by terminal top-level `findings[]`; `findings: []` cannot hide a documented external blocker.
- `external_reviews_triaged=true` states that triage happened; it does not replace finding records.
- V1 uses count coverage rather than finding IDs: reported external findings must be no greater than terminal top-level findings, and a non-PASS review with `finding_count: 0` counts as one reported finding.
- Count coverage is not identity-binding. It only prevents obvious under-recording; it does not bind a specific reported finding to a specific terminal finding.
- Deprecated `self_review.external_review` is ignored. Use `--external-review-evidence` for external evidence.
- A trivial PR with no external evidence does not block. If voluntary external evidence is passed, its findings are still validated.

Threat model:

The hashes are audit and integrity handles, not identity guarantees. They help detect accidental drift and make review artifacts reproducible against the current diff. They do not prove that an external reviewer really produced the review if the same operator can freely write prompt, review text, hashes, `source`, and triage records.

`prompt_includes_diff=true` is an assertion by the evidence author, not a cryptographic proof. The gate validates shape, head binding, diff-hash binding, and count coverage; it does not validate prompt contents directly. It also cannot prove that the external model saw the same prompt whose hash is recorded.

A stronger model would use stable finding IDs, signed prompt/review artifacts, branch protection, externally stored attestations, or reviewer identity backed by a system outside the operator's write path. Those are outside this PR.

This is not a substitute for Grabowski self-review, Codex, Claude, or CI. It is a contrast loop: different reviewer failure modes, not ritual mass.

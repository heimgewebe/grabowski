# External review loop

`tools/pr_review_gate.py` requires external review evidence when a pull request is classified as complex. Complexity is currently derived from file count, diff size, risk paths, self-review uncertainty, and material findings after the first review.

Required self-review field for complex or explicitly required external review:

```json
{
  "external_review": {
    "required": true,
    "diff_prompt_provided": true,
    "prompt_head_sha": "<current PR head SHA>",
    "prompt_includes_diff": true,
    "external_reviews_triaged": true,
    "reviews_received": 1,
    "findings": []
  }
}
```

Rules:

- `prompt_head_sha` must match the current PR head.
- The prompt must assert that it included either a diff or a patch.
- At least one external review must be received when the external loop is required.
- All recorded external findings, including optional external-review evidence on small changes, must be terminally triaged with the same terminal status rules as Grabowski self-review findings.
- Small non-risk changes may record a non-requirement reason:

```json
{
  "external_review": {
    "required": false,
    "reason": "small non-risk documentation change"
  }
}
```

This is not a substitute for Grabowski self-review, Codex, Claude, or CI. It is a contrast loop: different reviewer failure modes, not ritual mass.

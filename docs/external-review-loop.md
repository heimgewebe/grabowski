# External review loop

`tools/pr_review_gate.py` requires separate diff-bound external review evidence for every pull request except documentation-only changes and very small uncomplicated changes. High-critical pull requests require that evidence to contain a valid Claude CLI `ultrareview` entry. This is an independent-review requirement, not a privileged GitHub platform-review requirement. Weltgewebe is an important repository: every non-documentation-only Weltgewebe PR requires external review evidence with Claude CLI `ultrareview`, including very small code changes. High-critical classification is derived from large file/line counts, generic runtime/deploy/security/migration/privilege/recovery/policy path markers, Grabowski operator-critical paths, self-review uncertainty, and material findings after the first review.

The external loop is separate from Grabowski self-review. Self-review remains internal evidence; external review evidence is passed with its own CLI argument. Use the packet writer whenever an external LLM review is needed so the diff is available as a downloadable artifact:

## Evidence, not comments

A GitHub PR comment that says the operator checked the PR is not review evidence and must not be treated as a merge gate.

Before merge, Grabowski must run its own critical review against the current PR head and current PR diff. That review has to inspect the diff itself, challenge the approach, record a `PASS|NEEDS_CHANGE|BLOCK` verdict, list every reviewed PR file, cover the focus axes `correctness`, `regression_risk`, `tests`, `security`, and `integration`, record review iterations, record material findings, and terminally triage every finding in structured self-review evidence. Do not write the self-review text into the pull request as a review comment; the PR may at most reference the evidence artifact path/hash/status.

The self-review gate validates structure, exact PR file coverage, and current head/diff binding. This is necessary evidence hygiene, not proof that the review was high quality. External review evidence remains the collision-reduction layer for every non-exempt PR. The required focus axes have no local exemption: if `security` or `integration` yields no issue for a given change, the axis still stays in `review_focus`; individual findings may use terminal `not_applicable` status when recording such a conclusion is useful.

Self-review is required for every PR. For every non-exempt PR, Grabowski must also start an external LLM review loop before merge by handing the user a portable review packet. The packet must contain repo, PR number, current head SHA, diff hash, exact reviewer instructions, an evidence template, and the full PR diff as a downloadable file suitable for another model. Required external review remains blocking until returned findings are triaged and supplied as external review evidence, unless the user consciously overrides that gate outside this automated policy.

Create the self-review template and external review packet once per PR head/diff:

```bash
python3 tools/pr_review_gate.py \
  --pr <PR_NUMBER> \
  --write-self-review-template evidence/pr-<PR_NUMBER>-self-review-template.json \
  --write-external-review-packet evidence/pr-<PR_NUMBER>-external \
  --json
```

Then run the repeatable gate check against completed evidence:

```bash
python3 tools/pr_review_gate.py \
  --pr <PR_NUMBER> \
  --self-review evidence/self-review.json \
  --external-review-evidence evidence/external-review.json \
  --json
```

## Claude CLI provider for critical PRs

For high-critical PRs and every non-documentation-only PR in `heimgewebe/weltgewebe`, run Claude CLI through the packet-bound adapter. The adapter verifies the repository identity, current PR head, live `gh pr diff` hash, packet paths, and packet hashes before review and rechecks head and diff after review. It invokes the exact command shape required by the gate and writes a structured `claude-cli:ultrareview` review entry. Because `ultrareview` receives a PR target rather than the packet prompt, the evidence records `prompt_transmitted: false`, `prompt_includes_diff: false`, and a separate `review_input` object bound to repo, PR, head SHA, and diff SHA-256. The gate requires that explicit tool-input binding on Claude-required lanes.

```bash
python3 tools/external_review_claude.py \
  --manifest evidence/pr-<PR_NUMBER>-external/pr-<PR_NUMBER>-<head>-external-review-manifest.json \
  --repo /path/to/repository \
  --output evidence/pr-<PR_NUMBER>-external/claude-external-review-evidence.json \
  --timeout-minutes 30
```

Claude is the mandatory independent first reviewer on these lanes, but not the sole truth source. A clean Claude result does not replace Grabowski self-review, CI, mergeability, current-head binding, current-diff binding, or terminal triage. Claude findings are stored but are not auto-triaged; `NEEDS_CHANGE`, `BLOCK`, or any positive finding count keeps the gate closed until the findings are resolved and terminally recorded. CLI failure, timeout, invalid JSON, repository mismatch, head drift, or diff drift fails closed and produces no passing evidence.

## Optional agy/Gemini provider

`tools/external_review_agy.py` can produce `--external-review-evidence` from a packet written by `tools/pr_review_gate.py`. It is a convenience provider, not a privileged trust anchor. The tool reads the packet manifest, verifies that the prompt and diff files are inside the packet directory, checks their SHA-256 values against the manifest, builds one inline prompt containing the full diff, invokes `gemini`/`agy` in print mode, stores the raw model response, and writes evidence shaped for the review gate.

```bash
python3 tools/external_review_agy.py \
  --manifest evidence/pr-<PR_NUMBER>-external/pr-<PR_NUMBER>-<head>-external-review-manifest.json \
  --output evidence/pr-<PR_NUMBER>-external/agy-external-review-evidence.json \
  --model 'Gemini 3.1 Pro (Low)'
```

The provider intentionally uses the known-good `agy` invocation shape:

```bash
gemini --print-timeout=<seconds>s --model '<model>' --print '<prompt with full diff>'
```

Do not pipe the prompt through stdin for this provider; `agy --print` requires the prompt as an argument. Put `--print-timeout` before `--print`, otherwise `agy` can treat timeout flags as prompt text. Because argv transport can expose the prompt briefly to local process observers, use this provider only for review packets that are already acceptable to send to an external model. If the prompt would exceed the configured argv-size budget, the provider fails closed instead of silently dropping or truncating the diff.

Passing provider evidence is created only for `PASS` reviews with `finding_count: 0`. Any `NEEDS_CHANGE`, `BLOCK`, or positive finding count is stored as raw review output and raw findings, but `external_reviews_triaged` remains false so the normal gate blocks until Grabowski records terminal triage in top-level `findings[]`. Upstream failures, timeouts, empty output, invalid JSON, missing packet files, or manifest hash drift also fail closed and must not be treated as evidence.

For external-review-exempt PRs, still pass completed `--self-review` evidence and omit only `--external-review-evidence`. `--claude-evidence` remains accepted as legacy diagnostic input, but it does not satisfy the critical-PR Claude CLI rule and does not replace `--external-review-evidence`.

Minimal self-review evidence object:

```json
{
  "schema_version": 1,
  "kind": "grabowski_self_review",
  "reviewer": "grabowski-self",
  "review_mode": "critical_diff_review",
  "repo": "heimgewebe/grabowski",
  "pr": 70,
  "head_sha": "<current PR head SHA>",
  "diff_sha256": "<sha256 of current PR diff>",
  "diff_reviewed": true,
  "reviewed_files": ["<every current PR file>"],
  "review_focus": ["correctness", "regression_risk", "tests", "security", "integration"],
  "verdict": "PASS",
  "review_iterations": [
    {"n": 1, "summary": "critical diff review completed", "material_findings": 0}
  ],
  "all_findings_triaged": true,
  "findings": [],
  "material_findings_remaining": 0,
  "material_findings_after_first_review": 0,
  "stop_reason": "clean_pass"
}
```

Self-review rules:

- `schema_version` must be integer `1`, `kind` must be `grabowski_self_review`, and `review_mode` must be `critical_diff_review`.
- `repo`, `pr`, `head_sha`, and `diff_sha256` must match the current gate state.
- `verdict` must be `PASS`; `NEEDS_CHANGE` or `BLOCK` blocks merge.
- `reviewed_files` must cover every file in the current PR file list using exact, case-sensitive repository paths. A single leading `./` is tolerated; absolute paths and `..` path segments are invalid.
- `review_focus` must include `correctness`, `regression_risk`, `tests`, `security`, and `integration`; these axes are mandatory considerations, not optional per-PR switches.
- `--write-self-review-template` writes a scaffold bound to the current head and diff hash; it does not satisfy the gate until completed after an actual critical review and all placeholders such as `PASS|NEEDS_CHANGE|BLOCK` are replaced. Existing template files are not overwritten.

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
      "source": "claude-cli:ultrareview|chatgpt|gemini|other|user_pasted_review",
      "tool": "claude-code when source is claude-cli:ultrareview",
      "tool_version": "<non-empty Claude CLI version when required>",
      "command": ["claude", "ultrareview", "<PR_NUMBER>", "--json", "--timeout", "30"],
      "exit_code": 0,
      "json_ok": true,
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
- Generic external-review evidence requires `prompt_includes_diff: true`; this is only the operator's assertion that the external prompt contained the diff. Claude CLI `ultrareview` evidence instead requires `prompt_includes_diff: false`, `prompt_transmitted: false`, and `review_input.mode: claude_ultrareview_pr` bound to the exact repo, PR, head SHA, and diff SHA-256.
- `reviews` must be a list and must be non-empty when the external loop is required.
- Each review entry must include `source`, `review_sha256`, `verdict`, and integer `finding_count >= 0`.
- `source` is normally a human-readable trace label. For a required Claude CLI review it must be exactly `claude-cli:ultrareview`, accompanied by `tool: claude-code`, a non-empty `tool_version`, the exact PR-bound `claude ultrareview ... --json --timeout ...` command, `exit_code: 0`, and `json_ok: true`.
- `external_review.required`, when present, must be a boolean. A required external review cannot be disabled by setting `required=false` in evidence.
- `external_reviews_triaged` must be true.
- `findings` must be a list, and every finding must be terminally triaged with the same terminal status rules as Grabowski self-review findings.
- A review with `verdict != "PASS"` or `finding_count > 0` must be covered by terminal top-level `findings[]`; `findings: []` cannot hide a documented external blocker.
- `external_reviews_triaged=true` states that triage happened; it does not replace finding records.
- V1 uses count coverage rather than finding IDs: reported external findings must be no greater than terminal top-level findings, and a non-PASS review with `finding_count: 0` counts as one reported finding.
- Count coverage is not identity-binding. It only prevents obvious under-recording; it does not bind a specific reported finding to a specific terminal finding.
- Deprecated `self_review.external_review` is ignored. Use `--external-review-evidence` for external evidence.
- Documentation-only PRs and very small uncomplicated PRs with no external evidence do not block under the standard repository policy. Weltgewebe overrides the tiny-change exemption for every non-documentation-only PR. If voluntary external evidence is passed, its findings are still validated.
- Policy-critical documentation such as `GRABOWSKI.md`, `AGENTS.md`, `docs/external-review-loop.md`, and operator/recovery/deploy doctrine is not documentation-exempt.
- Very small changes are not exempt when they touch build, config, CI, packaging, controlled tool paths, structured data, lock files, or zero-line/binary-like diffs.
- Non-trivial non-documentation PRs require diff-bound external review evidence. The reviewer may be ChatGPT in the current conversation or another external LLM, as long as the review was based on the current PR diff and is recorded in structured evidence.
- High-critical PRs require diff-bound external review evidence containing a valid Claude CLI `ultrareview` entry. All non-documentation-only Weltgewebe PRs inherit the same Claude CLI requirement even when otherwise tiny. This does not make Claude a sole or privileged truth anchor: GitHub platform signals remain diagnostics, while self-review, CI, mergeability, head/diff binding, and finding triage remain independent blockers.
- Required Python matrix checks are derived from the target repository's regular `.github/workflows/validate.yml` or `.yaml`. Grabowski's own fallback remains `validate (3.10)` plus `validate (3.12)`. A foreign repository with a missing, unreadable, duplicate, or non-literal Python matrix fails closed instead of inheriting Grabowski's versions.

Threat model:

The hashes are audit and integrity handles, not identity guarantees. They help detect accidental drift and make review artifacts reproducible against the current diff. They do not prove that an external reviewer really produced the review if the same operator can freely write prompt, review text, hashes, `source`, and triage records.

`prompt_includes_diff=true` is an assertion by the evidence author, not a cryptographic proof. The gate validates shape, head binding, diff-hash binding, and count coverage; it does not validate prompt contents directly. It also cannot prove that the external model saw the same prompt whose hash is recorded.

A stronger model would use stable finding IDs, signed prompt/review artifacts, branch protection, externally stored attestations, or reviewer identity backed by a system outside the operator's write path. Those are outside this PR.

This is not a substitute for Grabowski self-review or CI. It is a contrast loop: different reviewer failure modes, not ritual mass. The policy deliberately selects Claude CLI as the required independent reviewer only for high-critical and important-repository lanes; ordinary non-exempt PRs may still use another diff-bound external LLM review.

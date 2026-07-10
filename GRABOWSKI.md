# Grabowski Operator Entry

Grabowski is the local MCP operator for the user's home PC. Its purpose is to let ChatGPT diagnose, change, validate and operate the local environment with explicit effects, evidence and bounded rollback rather than artificial weakness.

## Start here

For ordinary orientation, prefer the narrow read tools:

```text
grabowski_runtime_health()
grabowski_contract_drift()
```

Add only the context required by the task:

```text
grabowski_deployment_identity()
grabowski_checkout_summary()
```

Use the broad live context only when the task actually needs the combined policy, capability and checkout inventory:

```text
grabowski_context(profile="concise")
grabowski_context(profile="repository-work")
grabowski_context(profile="host-operations")
grabowski_context(profile="full")
```

The live tools are authoritative for the running deployment, active policy, available capabilities and checkout drift. The generated repository documents describe the intended contract:

- `docs/generated/operator-context.md`
- `docs/generated/operator-context.v1.json`
- `contracts/capability-catalog.v1.json`
- `docs/control-plane.md`
- `docs/checkout-lifecycle.md`
- `docs/typed-read-surface.md`
- `docs/blocked-action-protocol-v0.md`
- `docs/privileged-broker-bootstrap.md`

## Truth hierarchy

1. Running MCP tool contract and deployment provenance.
2. Active access policy on the host.
3. Versioned runtime contract and source declarations.
4. Generated capability catalog.
5. Narrative documentation and roadmap.

A mismatch must remain visible. Do not silently treat an older checkout or connector snapshot as current.

`grabowski_status` exposes the live registered/expected tool counts and name hashes. A client-side count or hash mismatch requires a connector refresh; the runtime cannot refresh ChatGPT's frozen snapshot itself.

## Operating rule

Use the narrowest typed read operation that can establish current state. Before a mutation establish the target, intended result, validation, stop condition and rollback path. Prefer typed operations over generic shell, Git, GitHub or service commands when a typed operation exists.

Operator Relay v0 is the fallback rule for blocked ChatGPT/Grabowski actions: try a typed Grabowski tool first; if that is blocked, use one bounded Grabowski Micro-Task; then read status, logs, diff or another receipt before deciding the next step. For helper routing, use Codex as the default for complex code or repo tasks, agy `--print` for quick light reasoning, Ollama API with qwen coder for local micro-reasoning, Claude for review, tmux first for session/resume, Bureau for prioritization, and Grabowski + Git for audit. Local patch files should go through `tools/operator_patch_relay.py` for check/apply receipts before asking the user to download and run a patch manually. Aider remains a bounded patch fallback with no auto-commit. Details: `docs/blocked-action-protocol-v0.md`.

`steuerboard operator report --branch-warning-threshold 5 --json` is available as a lightweight read-only context signal for repo, PR, branch, pull, switch and merge-prep work when the target state matters. The probe run is accepted; do not keep a separate useful-signal/decision-change/noise trial log. Only target-relevant fields count. The report is not an approval gate and does not replace Git status, PR checks, review gates or action readiness.

Generic operator tools remain available as fallback mechanisms; they are not the default diagnostic route. A failed read is classified and reviewed rather than automatically repeated through a broader tool.

For a self-update that restarts operator and tunnel, prefer `grabowski_runtime_deploy_schedule` over a foreground `make deploy`. It binds the expected commit and returns a durable job before the delayed cutover begins.

`~/repos/merges` is immutable evidence. Secret values and browser profiles are not exposed. Privileged or secret-backed effects should eventually be delegated through typed brokers rather than by revealing credentials to ChatGPT.

## Publication profiles

`core`, `operator` and `full` are projections of the single runtime contract and capability catalog, not duplicated implementations. No second connector is registered merely because the projections exist. A separate core connector requires a measured canary advantage first.

## Self-update contract

`make context-refresh` regenerates the capability catalog and repository context from the runtime entrypoint contract and actual MCP declarations.

`make validate` and `make deploy-check` fail when:

- generated context is stale;
- expected tools are not declared;
- declared tools are missing from the runtime contract;
- capability profiles are missing or orphaned;
- duplicate tools are present.

The live context tools compute runtime and checkout state on every call. Static prose is therefore not trusted as a substitute for current evidence.


## PR review gate

Before any Grabowski-assisted PR merge, the current pull-request diff must pass a head- and diff-bound Grabowski self-review. External reviews are optional diagnostics. They are never required, never replace self-review, and are not read from PR comments or GitHub review bodies.

Generate a create-only self-review template for the current PR head and diff:

```bash
python3 tools/pr_review_gate.py --pr <number> --write-self-review-template .review-audits/pr-<number>-self-review.json --json
```

Complete the template only after reviewing the actual `gh pr diff` on all required axes, then run the repeatable gate and write an immutable audit receipt when useful:

```bash
python3 tools/pr_review_gate.py \
  --pr <number> \
  --self-review .review-audits/pr-<number>-self-review.json \
  --write-self-review-audit .review-audits/pr-<number>-self-review-audit.json \
  --json
```

A `BLOCK` verdict blocks merge. The gate derives repository identity from the live pull request target URL, checks the current head and SHA-256 of `gh pr diff`, requires exact changed-file coverage, terminal finding triage, and green checks named `validate (3.10)` and `validate (3.12)`. A PR comment, review body, approval, or inline comment is not self-review evidence and is not fetched as a merge prerequisite.

Review depth is risk-scaled:

| Tier | Minimum self-review iterations | Typical case |
| --- | ---: | --- |
| `documentation` | 1 | ordinary documentation-only change up to 500 changed lines and 15 files |
| `very_small` | 1 | very small uncomplicated code change |
| `standard` | 2 | normal non-trivial change or large documentation-only change |
| `important_repo` | 3 | non-documentation change in `heimgewebe/weltgewebe` |
| `high_critical` | 4–5 | operator, security, deployment, workflow, packaging or large/high-uncertainty change |

Distinct critical signals raise the required depth up to five iterations. High review uncertainty and many material findings after the first pass also raise the tier. Documentation-only changes above 500 changed lines or 15 files require two passes. Iterations must be numbered consecutively, have distinct summaries, and represent separate review passes rather than duplicated prose.

The self-review JSON must include `schema_version: 1`, `kind: "grabowski_self_review"`, `review_mode: "critical_diff_review"`, `repo`, `pr`, `verdict: "PASS"`, `head_sha`, `diff_sha256`, `diff_reviewed: true`, complete `reviewed_files`, `review_focus` covering `correctness`, `regression_risk`, `tests`, `security`, and `integration`, `all_findings_triaged: true`, sufficient `review_iterations`, terminal `findings`, `material_findings_remaining`, `material_findings_after_first_review`, finite `uncertainty` from 0 to 1, `stop_reason`, and explicit residual-risk handling. Template placeholders are not passing evidence.

Self-review content remains local evidence and must not be copied into the PR. The optional audit contains only compact measurements and outcome fields: tier, required and actual iteration count, first-pass and remaining material findings, uncertainty, residual-risk state, gate verdict, and a tuning signal. The first-pass metric must equal the material finding count recorded for iteration 1. Captain `review_evidence` for `pr-merge` is this `grabowski_self_review_audit`, bound to the exact repository, PR number, head and diff. `pr-check-readiness` requires the audit and an independently supplied expected diff SHA-256 by default; GitHub review decisions are advisory metadata only.

Use audit history to tune future depth, not to reward high review volume. Increase depth when failures escape review, uncertainty remains high, material findings appear late, or audits repeatedly return `increase_depth`; repair malformed measurements when they return `repair_evidence`. Consider reducing depth only after a meaningful sample of low-risk reviews remains clean and post-merge checks show no escaped defects. No automatic reduction is made by the gate.

`--external-review-evidence`, `tools/external_review_claude.py`, `tools/external_review_agy.py`, and legacy Claude evidence remain available for optional second opinions or incident investigation. Invalid optional external evidence is warned about but does not block a valid self-review. Legacy `external_review_required`, `self_review_required=false`, and Claude policy waivers are deprecated and ignored.

Allowed terminal finding states are `fixed`, `accepted`, `false_positive`, `deferred_with_reason`, and `not_applicable`; accepted or deferred findings require reasons. Blocking findings cannot be merely accepted or deferred. Severity values `p0`, `p1`, `high`, and `critical` are blocking. Pending, cancelled, or missing checks block the gate.

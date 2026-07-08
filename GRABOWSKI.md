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

Before any Grabowski-assisted PR merge, review evidence must be evaluated rather than assumed. Every PR requires current self-review evidence; non-exempt PRs also require external review evidence. Generate self-review templates and external review packets in a separate create-only step; then run the gate against completed evidence in a repeatable check step. Treat a BLOCK verdict as merge-blocking. The self-review template is only a scaffold; it is not passing evidence until Grabowski has actually reviewed the diff, recorded a PASS verdict, review iterations, reviewed files, focus axes, and terminal finding triage.

For a non-exempt PR, first generate review scaffolds:

```bash
python3 tools/pr_review_gate.py --pr <number> --write-self-review-template <path> --write-external-review-packet <dir> --json
```

Then run the repeatable gate check after evidence is completed:

```bash
python3 tools/pr_review_gate.py --pr <number> --self-review <path> --external-review-evidence <path> --json
```

For an external-review-exempt PR, still provide completed self-review evidence and omit only the external packet/evidence arguments from the relevant command.

The gate requires a head-SHA- and `gh pr diff` SHA-256-bound Grabowski self-review, iterative review evidence, terminal triage for every finding at every severity, and expected green checks named `validate (3.10)` and `validate (3.12)`. External LLM review evidence is required for every PR except documentation-only changes and very small uncomplicated changes. Policy-critical documentation and build/config/CI/packaging/tooling changes are not exempt merely because they are text or small. High-critical changes additionally require at least one platform review from Codex or Claude, provided either by a current-head trusted review object or, for Claude CLI, by a valid `--claude-evidence` receipt. Codex and Claude are therefore not the default review path for ordinary PRs; external LLM review packets are.

Self-review evidence must use the same diff source as the gate:

```bash
gh pr diff <number> --repo <owner>/<repo> > evidence/pr-<number>.diff
sha256sum evidence/pr-<number>.diff
# macOS: shasum -a 256 evidence/pr-<number>.diff
```

The self-review JSON must include `schema_version: 1`, `kind: "grabowski_self_review"`, `review_mode: "critical_diff_review"`, `repo`, `pr`, `verdict: "PASS"`, `head_sha`, `diff_sha256`, `diff_reviewed: true`, complete `reviewed_files` coverage for the current PR files, `review_focus` covering `correctness`, `regression_risk`, `tests`, `security`, and `integration`, `all_findings_triaged: true`, non-empty `review_iterations`, terminal `findings`, `material_findings_remaining`, and a `stop_reason`. The self-review must be a critical review performed by Grabowski against the actual diff; do not post the self-review text into the PR. A PR comment, review body, or inline comment is not self-review evidence. Existing self-review evidence without the required workflow fields or without `diff_sha256` must be regenerated against the current head and current `gh pr diff` output before merge.

The self-review gate checks structural compliance, exact PR file coverage, and current head/diff binding. That reduces self-deception but does not prove review quality by itself; external review evidence remains the collision-reduction layer for every non-exempt PR. `review_focus` records that every required axis was consciously considered. There is no per-axis exemption: if an axis yields no issue for a specific PR, keep the axis in `review_focus` and record concrete non-applicable findings only when useful. Template placeholders such as `PASS|NEEDS_CHANGE|BLOCK` must be replaced before the object can be passing evidence.

Allowed terminal finding states are `fixed`, `accepted`, `false_positive`, `deferred_with_reason`, and `not_applicable`; accepted or deferred findings require reasons. Blocking findings cannot be merely accepted or deferred. Severity values `p0`, `p1`, `high`, and `critical` are treated as blocking for this purpose. Pending, cancelled, or missing checks block the gate.

# Self-review-first PR review loop

Status: active

## Decision

Grabowski self-review remains the universal required review control. For `high_critical` pull requests, and whenever `codex_review_required=true` is supplied, Captain additionally requires one current-head GitHub Codex settlement or one explicit short-lived exception. Other external LLM reviews, GitHub approvals, PR comments, and provider-specific packet reviews remain optional diagnostics. No review prose is treated as authoritative by itself.

The required controls remain independent:

1. current head and `gh pr diff` binding;
2. risk-scaled Grabowski self-review;
3. terminal finding triage;
4. green CI;
5. mergeability and target identity;
6. current-head Codex settlement for high-critical or explicitly selected PRs;
7. Captain authority and recovery controls where Captain executes the merge.

## Depth policy

| Review tier | Minimum iterations | Trigger |
| --- | ---: | --- |
| `documentation` | 1 | ordinary documentation-only diff up to 500 changed lines and 15 files |
| `very_small` | 1 | small uncomplicated code diff |
| `standard` | 2 | other non-trivial diff or large documentation-only diff |
| `important_repo` | 3 | non-documentation diff in `heimgewebe/weltgewebe` |
| `high_critical` | 4–5 | high-critical path, large diff, high uncertainty, or many first-pass findings |

The high-critical minimum starts at four and rises to five when multiple independent critical signals are present. The cap prevents review ritual from growing without bound; unresolved risk still blocks regardless of loop count.

Each iteration must re-read the current diff from a distinct angle. Recommended order:

1. correctness and contract changes;
2. regression paths and compatibility;
3. tests, negative cases, and failure handling;
4. security, authority, data integrity, and integration boundaries;
5. final adversarial pass for high-critical work with multiple risk signals.

A repeated summary without new inspection is not an iteration; normalized duplicate summaries are rejected. `uncertainty` must be a finite value from 0 to 1, and `material_findings_after_first_review` must equal iteration 1. Any change to repository, PR number, head or diff invalidates the evidence and restarts the loop.

## Workflow

Create the self-review scaffold once for the current head and diff:

```bash
python3 tools/pr_review_gate.py \
  --pr <PR_NUMBER> \
  --write-self-review-template .review-audits/pr-<PR_NUMBER>-self-review.json \
  --json
```

Review the actual diff, fill the scaffold, then evaluate it:

```bash
python3 tools/pr_review_gate.py \
  --pr <PR_NUMBER> \
  --self-review .review-audits/pr-<PR_NUMBER>-self-review.json \
  --write-self-review-audit .review-audits/pr-<PR_NUMBER>-self-review-audit.json \
  --json
```

Both template and audit are create-only. Existing paths are never overwritten. The audit is compact evidence, not review prose. It records the exact head and diff hash, tier, required and actual iterations, finding counts, uncertainty, residual-risk state, gate verdict, and tuning signal.

## Required-check contract

A target repository may declare universal merge checks in
`.github/grabowski-required-checks.json`:

```json
{
  "schema_version": 1,
  "required_checks": ["Detect docs updates", "Core Guard Tests"]
}
```

The policy that authorizes the current merge is read from the exact PR base, not
from the proposed head. A head-side catalog is validated immediately but only
becomes authoritative after merge. A PR therefore cannot weaken its own missing-
check detection. Bootstrap mappings cover named repositories until their first
catalog reaches the default branch.

Catalogs are strict and bounded: schema version 1, no unknown fields, 1–64 unique
check names, and at most 200 characters per normalized name. Expected checks must report `pass`; missing or skipped expected checks block.
Any other failed, cancelled, pending, or errored check also blocks, while an
explicitly skipped non-expected on-demand job is neutral. The catalog therefore
detects universal checks that failed to run or disappeared. Repositories without a base
catalog or bootstrap mapping may use the legacy base-side
`.github/workflows/validate.yml` matrix contract.

## Captain contract

For `pr-merge`, Captain `review_evidence` must be a valid `grabowski_self_review_audit` with:

- matching `repo`, `pr`, `head_sha` and `diff_sha256`;
- `gate_verdict: PASS`;
- `self_review_gate_valid: true`;
- `all_findings_triaged: true`;
- `actual_review_iterations >= minimum_review_iterations`;
- no unaccepted material findings;
- `tuning_signal: observe`.

The audit may additionally carry action and target digests. Captain rejects mismatched bindings. The readiness grip also requires an independently supplied expected diff hash by default; a GitHub approval or changes-requested state neither satisfies nor blocks the self-review contract.

For `high_critical` or explicitly required PRs, `codex_review_evidence` is a separate Captain gate. `tools/codex_review_settlement.py` creates an idempotent `@codex review` request whose hidden marker binds repository, PR, current head and current diff SHA-256. If identical trusted markers are duplicated, the earliest canonical request is authoritative; later duplicates cannot move the review or finding cutoff. Settlement requires one of three trusted completion forms after the canonical request: a Codex pull-request review bound to the full head, a deterministic clean-result issue comment whose reviewed-commit token is a 10–40 character prefix of that head, or a thumbs-up reaction on the exact request. Every bounded trusted Codex inline thread bound to the current head must be resolved, including threads created before a duplicate marker. A new head or diff invalidates the request and all prior settlement evidence.

The settlement evidence records the tool's static diff classification for diagnostics, but that value is not required to equal the later self-review tier: uncertainty and discovered findings can escalate Captain's requirement after the request was created. Captain derives authority from its own current self-review and explicit parameters, not from the settlement's diagnostic tier.

Captain validates the evidence structurally and binds its digest into the short-lived execution intent. A `COMMENTED` review never clears an outstanding current-head `CHANGES_REQUESTED` or `PENDING` review. GitHub represents an unsubmitted `PENDING` review with no submission timestamp; it still blocks conservatively regardless of when the canonical request was created. A later trusted `APPROVED` review may supersede `CHANGES_REQUESTED`, while a `PENDING` review must disappear from the live set through submission or deletion before settlement can pass. The atomic merge guard then reads the exact request, the bounded canonical issue-comment set, the bounded current-head review set, the selected review, clean-result comment or reaction completion, and the current thread set from GitHub twice: once before acquiring merge resources and once immediately before `gh pr merge`. Any missing object, body or actor drift, non-earliest request, stale head, changed diff, outstanding blocking review, changed thread set, unresolved thread, truncated result window, failed GitHub read or evidence mismatch blocks fail-closed. Request, issue-comment, review and reaction revalidation uses 100 items per page with pagination enabled and accepts exactly one page; any second page is an explicit boundedness failure. A clean-result comment is accepted only from a trusted Codex actor, after the request, when the entire normalized body matches the deterministic `Didn't find any major issues` prefix, one bounded single-line connector closing of at most 80 characters ending in punctuation or a bounded emoji shortcode, the reviewed-commit prefix matching the current head, and the known GitHub-Codex footer through end of body. Its exact body digest remains bound into the evidence. Multiline or unbounded success prose is rejected; the closing text itself has no authority.

The workflow requests one idempotent Codex review for every current PR head, so dynamic high-critical classifications and later explicit Captain requirements cannot lack a request merely because the workflow did not have the self-review evidence yet. Captain still decides risk-based whether settlement is mandatory; lower-tier PRs are not blocked by missing Codex evidence unless explicitly required.

The workflow status `Codex review settled` is a diagnostic projection. GitHub Actions supports review, review-comment and issue-comment triggers, but neither review-thread resolution nor reaction changes as direct workflow triggers. A separate default-branch dispatcher refreshes the projection every 15 minutes and on manual dispatch by invoking the trusted settlement workflow for at most 100 open pull requests. It lists 101 candidates and fails closed instead of silently truncating a larger inventory. The dispatcher has only `actions: write`, `contents: read` and `pull-requests: read`, checks out no code and never evaluates a pull-request head. During the one-time bootstrap before the evaluator itself reaches the default branch, the settlement workflow reports `trusted_evaluator_missing_on_default_branch` and blocks explicitly rather than executing the pull-request copy of the evaluator. The introducing pull request therefore needs an authorized out-of-band current-head settlement; after merge, ordinary refreshes use only the trusted default-branch evaluator. Reaction and thread-resolution projections may be delayed by one refresh interval, and scheduled workflows can be delayed by the platform. Captain does not trust this projection and always performs the authoritative live revalidation. The diagnostic status must not be configured as a required repository check.

A `grabowski_codex_review_exception` is allowed only as an explicit, repo/PR/head/diff-bound record with approver, reason and at most two hours of validity. The published Captain evidence schema exposes it together with `codex_review_evidence` as the mutually exclusive `codex_review_release` alternative group and lists every runtime-required exception field. When Codex settlement is required, exactly one alternative must be present. The exception bypasses only the Codex settlement gate; it does not weaken self-review, CI, delivery, mergeability, authorization or live target checks.

## Audit tuning

Audits support policy calibration. Useful aggregate signals are:

- escaped defects found after merge;
- findings first discovered in later review iterations;
- blocked reviews caused by insufficient depth;
- uncertainty distribution by tier and repository;
- review cost versus defect interception.

Increase depth when late findings or escaped defects cluster in a tier. Reduce depth only after a meaningful, reproducible sample shows low interception value and no corresponding rise in escaped defects. The current implementation emits `increase_depth`, `repair_evidence`, or `observe`; it never automatically weakens policy.

## Review evidence schema boundary

`tools/review_evidence_schemas.py` defines dependency-free schema models for the three JSON evidence inputs consumed by the gate: Grabowski self-review, optional external review evidence, and legacy Claude ultrareview evidence. Each model can emit a Draft 2020-12 JSON Schema document through `json_schema_for(...)`; the runtime loader uses the same model directly, so documentation and machine validation share one field definition.

The schema layer validates `schema_version: 1`, required fields, primitive JSON types, bounded numeric primitives, array item primitives, fixed discriminator values, and unknown top-level fields. Structural self-review failures are fatal because self-review is the required gate evidence. Structural failures in optional external or legacy Claude evidence remain advisory warnings and cannot turn optional diagnostics into a merge requirement. Existing schema-version-1 payloads remain the compatibility boundary; the deprecated `codex_review`, `claude_review`, and `external_review` self-review fields remain structurally accepted but do not regain policy authority. No migration is required for valid v1 evidence.

Schema validation is intentionally structural. Current PR identity, `head_sha`, `diff_sha256`, complete file coverage, review depth, terminal triage, and merge policy remain checks of `evaluate_review_gate`. A structurally valid stale evidence file therefore still fails the existing head/diff binding instead of acquiring authority from the schema layer.

## Optional external diagnostics

External review tools other than the conditional GitHub Codex settlement remain available for unusual uncertainty, incident analysis, or a deliberate second opinion. Their evidence may be supplied with `--external-review-evidence`; invalid evidence produces warnings, not a merge block. Legacy Claude packet requirements, policy waivers, and `self_review_required=false` are deprecated. No external review satisfies or shortens the required self-review loop.

## Cost policy

External providers default to a `0 USD` request and a `0 USD` runtime policy cap, so they are blocked before process launch. A positive request remains blocked unless an administrator explicitly raises `GRABOWSKI_EXTERNAL_PROVIDER_BUDGET_CAP_USD`; the requested amount must not exceed that cap. Agent competition additionally requires a provider-enforced hard USD limit by default. Providers without a hard limit remain blocked unless the caller explicitly weakens that gate. Prior budget authorizations do not carry forward.

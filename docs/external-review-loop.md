# Self-review-first PR review loop

Status: active

## Decision

Grabowski self-review is the required review control. External LLM reviews, GitHub approvals, PR comments, and provider-specific packet reviews are optional diagnostics only. No review prose is posted to the PR as authoritative evidence.

The required controls remain independent:

1. current head and `gh pr diff` binding;
2. risk-scaled Grabowski self-review;
3. terminal finding triage;
4. green CI;
5. mergeability and target identity;
6. Captain authority and recovery controls where Captain executes the merge.

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

The audit may additionally carry action and target digests. Captain rejects mismatched bindings. The readiness grip also requires an independently supplied expected diff hash by default; a GitHub approval or changes-requested state is advisory and neither satisfies nor blocks the self-review contract.

## Audit tuning

Audits support policy calibration. Useful aggregate signals are:

- escaped defects found after merge;
- findings first discovered in later review iterations;
- blocked reviews caused by insufficient depth;
- uncertainty distribution by tier and repository;
- review cost versus defect interception.

Increase depth when late findings or escaped defects cluster in a tier. Reduce depth only after a meaningful, reproducible sample shows low interception value and no corresponding rise in escaped defects. The current implementation emits `increase_depth`, `repair_evidence`, or `observe`; it never automatically weakens policy.

## Optional external diagnostics

External review tools remain available for unusual uncertainty, incident analysis, or a deliberate second opinion. Their evidence may be supplied with `--external-review-evidence`; invalid evidence produces warnings, not a merge block. Legacy Claude packet requirements, policy waivers, and `self_review_required=false` are deprecated. External review output does not satisfy or shorten the required self-review loop.

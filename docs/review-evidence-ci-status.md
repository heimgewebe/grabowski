# Review evidence CI status

Status: rollout-ready, not yet required

## Purpose

The `Review evidence status` workflow projects an already completed, head/diff-bound Grabowski self-review audit into the GitHub commit-status context `Review evidence gate`.

The projection is deliberately smaller than the underlying review evidence. CI does not receive review prose, findings, residual-risk text, local paths, provider output, or private evidence files. The detailed self-review and immutable audit remain operator-side evidence; the public status projection carries only machine fields needed to decide whether that audit still belongs to the current pull-request head and diff.

The CI status is a projection of review evidence, not a replacement for the local review gate, ordinary CI, branch protection, GitHub review requirements, or any independent high-critical review control.

## Trusted execution boundary

The workflow is triggered by `issue_comment`, so GitHub loads the workflow from the repository default branch rather than executing workflow code proposed by the pull request.

Only comments beginning with `/grabowski-review-evidence` enter the job. Before any status mutation, `tools/pr_review_gate_ci.py` asks GitHub for the triggering actor's repository permission. Only `admin`, `maintain`, `write`, or legacy `push` permission may publish the status. Unauthorized comments do not mutate PR status. Before publishing, the evaluator re-reads the bounded last-100 PR comment window, requires the event comment to still have the exact same body, and requires it to be the newest authorized review-evidence command. A missing, edited, out-of-window, or superseded event fails closed without status mutation.

The job needs only the ephemeral repository `GITHUB_TOKEN` with:

- `contents: read`;
- `pull-requests: read`;
- `statuses: write`.

No mutable operator token, provider credential, private review artifact, or long-lived secret is required.

## Evidence boundary

`python3 tools/pr_review_gate_ci.py prepare --audit <audit> --comment` converts one immutable `grabowski_self_review_audit` into a sanitized `grabowski_review_gate_status` projection.

The projection contains only:

- repository and PR number;
- exact PR head SHA;
- exact PR diff SHA-256;
- SHA-256 of the full local audit;
- gate verdict and self-review-gate validity;
- triage and remaining-material-finding state;
- required and actual review iteration counts;
- review tier and tuning signal.

The projection intentionally excludes review prose, finding bodies, residual-risk reasons, uncertainty notes, generated timestamps, local paths, external-review content, and secrets.

### What may be committed

The workflow and projection schema implementation may be committed. A head-bound status projection should **not** be committed into the PR it describes: that commit would change the head and diff and make the projection stale immediately.

### What may be uploaded

Only the sanitized status projection may be posted in the PR command comment:

`/grabowski-review-evidence v1 <base64-status-projection>`

The full self-review and audit are not uploaded by this workflow.

### What may be referenced

The public projection references the detailed local audit only by `audit_sha256`. That digest is traceability evidence, not proof that CI has read private audit contents. The authority boundary is the repository's write-capable operator set: a write-authorized actor can assert a projection, so the status is not a cryptographic attestation of private audit possession and must remain paired with independent CI and platform-review controls.

## Stale-evidence detection

For every authorized command the default-branch evaluator reads the live PR and recomputes the current PR diff hash with the same `gh pr diff` surface used by the local gate.

The status is blocked when any of these bindings or controls fail:

- repository mismatch;
- PR-number mismatch;
- current head SHA mismatch;
- current diff SHA-256 mismatch;
- non-PASS gate verdict;
- invalid self-review gate;
- incomplete finding triage;
- material findings remaining;
- actual review depth below the audited minimum;
- audited minimum depth below the complexity currently derived from the PR;
- audited review tier weaker than the current PR tier;
- tuning signal other than `observe`.

A new PR head has no inherited status. Reusing evidence from an older head therefore cannot make the new head green.

## Self-reference boundary

`Review evidence gate` is the output of the local review gate. Feeding its own red or pending state back into `tools/pr_review_gate.py` would create a recovery deadlock: the local gate could not produce the new evidence needed to repair its derived status.

The local gate therefore ignores only the check/status name `Review evidence gate` when evaluating its input checks. Branch protection remains independent and can still require that context. All other failed, cancelled, pending, or errored checks retain their existing blocking behavior.

The derived status must not be added to the local gate's required-check catalog. It is made required, when appropriate, at GitHub branch-protection level instead.

## High-critical and platform-review controls

The status projection cannot lower review depth. CI recomputes current PR complexity from the trusted default-branch evaluator and rejects an audit whose minimum iteration count or review tier is weaker than the current PR requires. A stronger audited tier remains valid.

Any GitHub branch-protection review requirement or other platform review requirement remains independent. `Review evidence gate` neither creates an approval nor satisfies a required approval. Likewise, optional external-review diagnostics do not become authoritative through this status path.

## Rollout

1. **Advisory phase**: merge the workflow and evaluator, exercise missing, stale, red, and green evidence paths, and verify that status updates bind to the current PR head.
2. **Observation phase**: use `Review evidence gate` on normal PRs while keeping existing required checks and review requirements unchanged. Confirm that default-branch execution, actor authorization, and stale-evidence handling remain reliable.
3. **Required phase**: after stable observation, configure GitHub branch protection to require the `Review evidence gate` status context in addition to existing CI and review requirements. Do not add the derived context to the local required-check catalog.
4. **Rollback**: remove the branch-protection requirement first. The workflow can then remain advisory or be disabled without weakening the pre-existing local review gate or CI checks.

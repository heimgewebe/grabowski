# Review evidence CI status

Status: advisory rollout only; not yet eligible to become a sole required merge gate

## Purpose

The `Review evidence status` workflow projects an already completed, head/base/diff-bound Grabowski self-review audit into the GitHub commit-status context `Review evidence gate`.

The projection is deliberately smaller than the underlying review evidence. CI does not receive review prose, findings, residual-risk text, local paths, provider output, or private evidence files. The detailed self-review and immutable audit remain operator-side evidence; the public status projection carries only machine fields needed to decide whether that audit still belongs to the current pull-request head, base, diff, and review-policy version.

The CI status is a projection of review evidence, not a replacement for the local review gate, ordinary CI, branch protection, GitHub review requirements, or any independent high-critical review control.

## Trusted execution boundary

The workflow is triggered by immutable `issue_comment.created` events, so GitHub loads the workflow from the repository default branch rather than executing workflow code proposed by the pull request. Corrections are made by posting a new command; editing an old command is not a supported way to create a new review-evidence generation.

Only exact v1 commands enter the job: either `/grabowski-review-evidence v1` or that prefix followed by one space and the encoded payload. Before any status mutation, `tools/pr_review_gate_ci.py` asks GitHub for the triggering actor's repository permission. Only `admin`, `maintain`, `write`, or legacy `push` permission may publish the status. In publish mode, the supplied actor must match `GITHUB_ACTOR`, and a concrete comment ID is mandatory.

The workflow intentionally has no concurrency queue. Every eligible command may run; stale runs independently re-read authorization state immediately before publication. This avoids losing a valid pending command because another `issue_comment` run replaced it in a shared concurrency group.

Before publication, the evaluator re-reads the bounded last-100 PR comment window, requires the triggering comment to still have the exact event body, and requires it to be the newest authorized v1 review-evidence command. It repeats that freshness check immediately before the final status write. A genuinely superseded command is the only safe no-op. An edited, missing, or out-of-window triggering command is blocking and, once the actor has been authorized and the current head is known, publishes a failure rather than silently preserving an older green status.

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
- exact PR base SHA observed by the audit;
- exact PR diff SHA-256;
- SHA-256 of the full local audit;
- canonical review-policy version;
- gate verdict and self-review-gate validity;
- triage and remaining-material-finding state;
- required and actual review iteration counts;
- review tier and tuning signal.

The projection intentionally excludes review prose, finding bodies, residual-risk reasons, uncertainty notes, generated timestamps, local paths, external-review content, and secrets.

The self-review audit and public status projection use the canonical structural schemas in `tools/review_evidence_schemas.py`. The private audit schema permits additional private fields, while the public projection schema rejects unknown fields. `REVIEW_POLICY_VERSION` must be incremented when review-gate policy semantics change in a way that makes prior audits stale; old policy-bound audits then cannot be projected as current evidence.

### What may be committed

The workflow and projection schema implementation may be committed. A head-bound status projection should **not** be committed into the PR it describes: that commit would change the head and diff and make the projection stale immediately.

### What may be uploaded

Only the sanitized status projection may be posted in the PR command comment:

`/grabowski-review-evidence v1 <base64-status-projection>`

The full self-review and audit are not uploaded by this workflow.

### What may be referenced

The public projection references the detailed local audit only by `audit_sha256`. That digest is traceability evidence, not proof that CI has read or possessed the private audit contents. The authority boundary remains the repository's write-capable operator set: a write-authorized actor can assert a syntactically valid projection.

Therefore the current status is an **authorized operator assertion**, not a cryptographic attestation of review provenance. It must not become the sole hard merge gate until a trusted evidence-store or cryptographic attestation path lets the default-branch evaluator verify that the referenced audit actually exists and was produced by an authorized review-gate execution.

## Stale-evidence detection

For every authorized command the default-branch evaluator reads the live PR and recomputes the current PR diff hash with the same `gh pr diff` surface used by the local gate.

The status is blocked when any of these bindings or controls fail:

- repository mismatch;
- PR-number mismatch;
- current head SHA mismatch;
- current base SHA mismatch;
- current diff SHA-256 mismatch;
- stale review-policy version;
- non-PASS gate verdict;
- invalid self-review gate;
- incomplete finding triage;
- material findings remaining;
- actual review depth below the audited minimum;
- audited minimum depth below the complexity currently derived from the PR;
- audited review tier weaker than the current PR tier;
- tuning signal other than `observe`.

The evaluator also re-reads head and base immediately before publication. A head or base change during evaluation blocks the result rather than allowing a status computed from a mixed snapshot.

A new PR head has no inherited status. Reusing evidence from an older head therefore cannot make the new head green.

A later base-branch advance can still change the effective merge diff after a green commit status has already been written to an unchanged PR head. GitHub commit statuses do not retroactively re-run merely because the base moved. Consequently, **required rollout must not rely on this status with loose/out-of-date branch protection**. Before this status is ever required, the protected branch must enforce an up-to-date/strict merge basis or an equivalent merge-queue mechanism, so base drift forces a fresh merge candidate and fresh review evidence. Base SHA binding detects drift during evaluation; strict merge-basis enforcement is what prevents a previously green unchanged head from remaining merge-eligible after later base drift.

## Comment freshness and races

The comment window is deliberately bounded. This prevents an unbounded PR-history read from turning one status command into uncontrolled API work.

The evaluator distinguishes:

- `current`: exact triggering body and newest authorized v1 command;
- `superseded`: a newer authorized v1 command exists; the older run performs no status mutation;
- `stale_or_edited`: the triggering comment still exists in the window but its body no longer matches the event;
- `outside_bounded_window`: the triggering comment cannot be proven current within the bounded window.
- `authorization_unknown`: authorization of a newer command could not be determined safely.

Failures to read the current comment window after the triggering actor and PR head are known likewise attempt to replace any older green status with a blocking status rather than silently preserving it. Only `superseded` is a safe no-op. The other non-current states are blocking once the triggering actor has been authorized. Permission lookups are cached per evaluation, and subprocess calls have bounded timeouts.

There remains an unavoidable small distributed-systems race between the final freshness read and the commit-status API write. The second freshness read and final head/base read materially narrow that window; a newer authorized command will subsequently re-evaluate the same head. A future attested status service could make generation ordering atomic, but this workflow does not claim that stronger property.

## Self-reference boundary

`Review evidence gate` is the output of the local review gate. Feeding its own red or pending state back into `tools/pr_review_gate.py` would create a recovery deadlock: the local gate could not produce the new evidence needed to repair its derived status.

The local gate therefore ignores only the check/status name `Review evidence gate` when evaluating its input checks. The local required-check catalog explicitly rejects that derived status name. Branch protection remains independent and may eventually require that context after the rollout blockers in this document are resolved. All other failed, cancelled, pending, or errored checks retain their existing blocking behavior.

## High-critical and platform-review controls

The status projection cannot lower review depth. CI recomputes current PR complexity from the trusted default-branch evaluator and rejects an audit whose minimum iteration count or review tier is weaker than the current PR requires. A stronger audited tier remains valid.

Any GitHub branch-protection review requirement or other platform review requirement remains independent. `Review evidence gate` neither creates an approval nor satisfies a required approval. Likewise, optional external-review diagnostics do not become authoritative through this status path.

## Rollout

1. **Advisory phase**: exercise missing, stale, red, green, base-drift, policy-drift, edited/out-of-window, and superseded evidence paths. Verify that status writes bind to the current head/base/diff and that unrelated comments cannot suppress a pending valid command.
2. **Observation phase**: use `Review evidence gate` on normal PRs while keeping existing required checks and review requirements unchanged. Confirm default-branch execution, actor authorization, bounded-command handling, final freshness revalidation, and command timeouts remain reliable.
3. **Provenance prerequisite**: add a trusted audit-attestation or evidence-store verification path. Until then, treat the status as an authorized operator assertion rather than proof that CI possessed the referenced audit.
4. **Merge-basis prerequisite**: ensure required branch protection uses a strict/up-to-date merge basis or equivalent merge queue so later base drift cannot leave an unchanged head merge-eligible on an older green status.
5. **Required phase**: only after both prerequisites and stable observation, configure GitHub branch protection to require `Review evidence gate` in addition to existing CI and independent review requirements. Never add the derived context to the local required-check catalog.
6. **Rollback**: remove the branch-protection requirement first. The workflow can then remain advisory or be disabled without weakening the pre-existing local review gate or CI checks.

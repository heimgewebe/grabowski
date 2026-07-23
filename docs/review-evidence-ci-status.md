# Review evidence CI status

Status: signed v2 provenance implemented; required rollout remains blocked on live proof, publisher identity, supersession semantics, and signer-recovery readiness

## Purpose

The `Review evidence status` workflow projects an already completed, head/base/diff-bound Grabowski self-review audit into GitHub commit statuses. Unsigned v1 commands publish only `Review evidence gate (advisory)`. Cryptographically verified v2 commands publish `Review evidence gate (attested)`, the only context eligible for a future required rollout. The historical `Review evidence gate` context is legacy and must never be reused as the v2 required context.

The projection is deliberately smaller than the underlying review evidence. CI does not receive review prose, findings, residual-risk text, local paths, provider output, or private evidence files. The detailed self-review and immutable audit remain operator-side evidence; the public status projection carries only machine fields needed to decide whether that audit still belongs to the current pull-request head, base, diff, and review-policy version.

The CI status is a projection of review evidence, not a replacement for the local review gate, ordinary CI, branch protection, GitHub review requirements, or any independent high-critical review control.

## Trusted execution boundary

The workflow is triggered by immutable `issue_comment.created` events, so GitHub loads the workflow definition from the repository default branch rather than executing workflow code proposed by the pull request. Corrections are made by posting a new command; editing an old command is not a supported way to create a new review-evidence generation.

Only exact v1 or v2 commands enter the job. v1 carries an unsigned sanitized projection and can mutate only the advisory context. v2 carries a signed attestation envelope; before the required-eligible context can be written, the default-branch evaluator verifies the OpenSSH signature against `config/review-evidence-allowed-signers`, the fixed signer principal, and the fixed review-evidence signature namespace. Before any status mutation, `tools/pr_review_gate_ci.py` also asks GitHub for the triggering actor's repository permission. Only `admin`, `maintain`, `write`, or legacy `push` permission may publish a status. In publish mode, the supplied actor must match `GITHUB_ACTOR`, and a concrete comment ID is mandatory.

The workflow intentionally has no concurrency queue. Every eligible command may run; stale runs independently re-read authorization state immediately before publication. This avoids losing a valid pending command because another `issue_comment` run replaced it in a shared concurrency group.

Before publication, the evaluator re-reads the bounded last-100 PR comment window, requires the triggering comment to still have the exact event body, and requires it to be the newest authorized command in the same protocol generation. v1 and v2 freshness generations are independent, so an unsigned advisory command cannot supersede an attested v2 command. The evaluator repeats that freshness check immediately before the final status write. A genuinely superseded same-version command is a no-op for that older run. An edited, missing, or out-of-window triggering command is blocking and, once the actor has been authorized and the current head is known, attempts to publish a failure to that command generation's own status context rather than silently preserving an older green status.

This freshness contract is sufficient for observation but is not yet a complete hard-gate generation protocol. A newer v2 comment can supersede an older run before the newer run itself reaches status publication. If that newer run is queued, cancelled, runner-starved, fails checkout, or otherwise terminates before replacing an already-published green status, the older green commit status can remain visible. Required rollout therefore needs an explicit, tested supersession contract that prevents a status from remaining merge-authoritative after it has become semantically stale.

The job needs only the ephemeral repository `GITHUB_TOKEN` with:

- `contents: read`;
- `pull-requests: read`;
- `statuses: write`.

CI requires no mutable operator token, provider credential, private review artifact, private signing key, or long-lived CI secret. v2 signing happens locally with a dedicated private key; CI receives only the signed sanitized envelope and the repository-stored public allowlist.

## Evidence boundary

`python3 tools/pr_review_gate_ci.py prepare --audit <audit> --comment` converts one immutable `grabowski_self_review_audit` into an unsigned sanitized v1 projection. `prepare-attested --audit <audit> --signing-key <key> --comment` signs the exact canonical projection and emits a v2 attestation envelope.

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

The self-review audit, public status projection and signed v2 envelope use canonical structural schemas in `tools/review_evidence_schemas.py`. The private audit schema permits additional private fields, while the public projection and attestation envelope reject unknown top-level fields. `REVIEW_POLICY_VERSION` must be incremented when review-gate policy semantics change in a way that makes prior audits stale; old policy-bound audits then cannot be projected as current evidence.

### What may be committed

The workflow and projection schema implementation may be committed. A head-bound status projection should **not** be committed into the PR it describes: that commit would change the head and diff and make the projection stale immediately.

### What may be uploaded

Only sanitized evidence may be posted in a PR command comment:

`/grabowski-review-evidence v1 <base64-status-projection>`

`/grabowski-review-evidence v2 <base64-signed-attestation>`

v1 is advisory-only. v2 contains the same sanitized projection plus a detached OpenSSH signature encoded inside a strict envelope. The full self-review, private audit and private signing key are never uploaded by this workflow.

### What may be referenced

The public projection references the detailed local audit only by `audit_sha256`. That digest remains traceability evidence rather than proof that CI possesses the private audit contents.

v1 therefore remains an **authorized operator assertion**. v2 adds cryptographic provenance for the exact canonical projection: a write-authorized actor who lacks an allowlisted private signing key cannot fabricate a v2 PASS. The signature still does not prove durable existence of the private audit or review quality; it attests that a trusted local signing key signed the exact public projection and its audit digest. The detailed threat model, option comparison, required-gate blockers and key lifecycle are defined in `docs/review-evidence-provenance.md`.

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

- `current`: exact triggering body and newest authorized command in the same protocol generation;
- `superseded`: a newer authorized command of the same protocol generation exists; the older run performs no status mutation;
- `stale_or_edited`: the triggering comment still exists in the window but its body no longer matches the event;
- `outside_bounded_window`: the triggering comment cannot be proven current within the bounded window;
- `authorization_unknown`: authorization of a newer command could not be determined safely.

Failures to read the current comment window after the triggering actor and PR head are known likewise attempt to replace any older green status with a blocking status rather than silently preserving it. Only `superseded` is currently a no-op. The other non-current states are blocking once the triggering actor has been authorized. Permission lookups are cached per evaluation, and subprocess calls have bounded timeouts.

For v2, "authorized" freshness currently means repository write permission plus the v2 command prefix; cryptographic validity is established later during evidence parsing. Therefore a write-authorized malformed or unsigned v2-prefixed comment can supersede an older in-flight v2 run. Whether hard-gate supersession authority should itself require a valid signature remains an explicit rollout decision.

There remains an unavoidable small distributed-systems race between the final freshness read and the commit-status API write. The second freshness read and final head/base read materially narrow that window. A future attested status service or another atomic generation mechanism could provide stronger ordering; this workflow does not claim that property.

## Self-reference boundary

`Review evidence gate`, `Review evidence gate (advisory)`, and `Review evidence gate (attested)` are outputs derived from the local review gate. Feeding either red or pending state back into `tools/pr_review_gate.py` would create a recovery deadlock: the local gate could not produce the new evidence needed to repair its derived status.

The local gate therefore ignores all three derived status names when evaluating its input checks, and the local required-check catalog explicitly rejects all three. Branch protection remains independent and may eventually require only the `Review evidence gate (attested)` context after the rollout blockers in this document are resolved. All other failed, cancelled, pending, or errored checks retain their existing blocking behavior.

## High-critical and platform-review controls

The status projection cannot lower review depth. CI recomputes current PR complexity from the trusted default-branch evaluator and rejects an audit whose minimum iteration count or review tier is weaker than the current PR requires. A stronger audited tier remains valid.

Any GitHub branch-protection review requirement or other platform review requirement remains independent. `Review evidence gate` neither creates an approval nor satisfies a required approval. Likewise, optional external-review diagnostics do not become authoritative through this status path.

## Rollout

1. **v1 advisory phase**: keep unsigned evidence on `Review evidence gate (advisory)` and exercise missing, stale, red, green, base-drift, policy-drift, edited/out-of-window, and superseded paths.
2. **v2 attestation observation**: exercise real signed v2 commands through the trusted default-branch workflow. Confirm valid signatures pass and tampered, unsigned, wrong-key and missing-allowlist paths fail closed.
3. **Merge-basis prerequisite**: ensure required branch protection uses a strict/up-to-date merge basis or equivalent merge queue so later base drift cannot leave an unchanged head merge-eligible on an older green status.
4. **Publisher-identity prerequisite**: give the future required `Review evidence gate (attested)` context a publisher identity exclusive to, or cryptographically equivalent to, the intended review-evidence evaluator. Binding only to the general GitHub Actions integration is not sufficient workflow-specific provenance.
5. **Supersession prerequisite**: select and live-test the authoritative generation model, including queued, cancelled, runner-unavailable and failure-before-publication cases, so an older green status cannot remain merge-authoritative contrary to that model.
6. **Recovery prerequisite**: prove signer rotation and key-loss recovery as described in `docs/review-evidence-provenance.md`. A single lost key must not create an unrecoverable repository lockout.
7. **Required phase**: only after stable v2 observation and all prerequisites, configure branch protection to require `Review evidence gate (attested)` in addition to existing CI and independent review requirements. Never add any derived review-evidence context to the local required-check catalog.
8. **Rollback**: remove the branch-protection requirement first. The signed workflow can then remain non-required or be disabled without weakening the pre-existing local review gate or CI checks.

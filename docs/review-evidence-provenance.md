# Review evidence provenance

Status: OpenSSH-signed v2 projection implemented; required-check activation remains gated on live proof, publisher identity, supersession semantics, and recovery readiness

## Decision

Use a dedicated local Ed25519/OpenSSH signing key to attest the canonical public review-status projection. The default-branch evaluator verifies the signature against a repository allowlist before it can publish the future required status context `Review evidence gate (attested)`.

Keep unsigned `/grabowski-review-evidence v1` evidence as a backward-compatible advisory assertion, but publish it only to `Review evidence gate (advisory)`. Signed `/grabowski-review-evidence v2` is the only command generation eligible to publish `Review evidence gate (attested)`.

The historical context `Review evidence gate` is permanently treated as legacy. It is never reused as the attested required context, because pre-v2 unsigned success statuses may already exist on commits and cannot be distinguished retrospectively from cryptographically verified results.

This design is intentionally narrower than a claim that CI possesses the private audit. The signature proves that an allowlisted signing key attested the exact canonical public projection, including the private audit digest and all head/base/diff/policy bindings. It does not prove that the underlying private audit is still durably stored.

## Threat model

### Mitigated

- A repository user with ordinary write permission cannot fabricate a v2 PASS projection unless they also possess an allowlisted private signing key.
- A posted v2 projection cannot be modified after signing without invalidating the signature.
- A valid signature cannot be replayed onto another repository, PR, head, base, diff or review-policy generation because those values are inside the signed canonical status object and are revalidated live.
- Signature-domain confusion is reduced by the fixed OpenSSH signature namespace `review-evidence@grabowski.heimgewebe`.
- An unsigned v1 projection cannot satisfy the future required context because v1 publishes only `Review evidence gate (advisory)`.
- CI does not need the private signing key, a mutable operator token or the private review artifact.

### Not mitigated

- Compromise of the local signing private key or the local user account that can read it.
- A malicious or mistaken trusted signer intentionally signing a false but structurally valid projection.
- Poor review quality, missed findings or a compromised local review-gate implementation before signing.
- Deletion or loss of the private audit after its digest was signed.
- The small distributed race between the final GitHub freshness read and the commit-status write.
- A compromise of the protected default-branch evaluator or its signer allowlist.
- GitHub required-status source binding identifies an integration/App, not a unique workflow file. Binding the future required context to the general GitHub Actions integration therefore does not by itself prove that this specific review-evidence workflow produced the status. A dedicated publisher identity or an equivalently strong workflow-specific control is still required before hard-gate rollout.
- A newer v2 comment can make an older run semantically superseded before the newer run has successfully replaced an already-published green status. If the newer run never reaches status publication, an older green commit status can remain visible. Required rollout therefore needs an explicit, tested stale-PASS invalidation or last-completed-attestation contract.
- Freshness currently treats a write-authorized v2-prefixed comment as a newer generation before cryptographic validity is established. This permits a write-authorized actor without the signing key to supersede an older in-flight v2 run and intentionally drive the attested context toward failure. This is primarily an availability risk, but it interacts with the stale-green window above.

## Options considered

### 1. Dedicated local OpenSSH signing key — implement

Mechanism:

1. The local gate produces the private `grabowski_self_review_audit`.
2. `tools/pr_review_gate_ci.py prepare-attested` derives the existing sanitized status projection.
3. `ssh-keygen -Y sign` signs the canonical projection bytes with a dedicated Ed25519 key and the fixed review-evidence namespace.
4. The PR comment carries only the signed public envelope.
5. The trusted default-branch workflow verifies the signature with `ssh-keygen -Y verify` and `config/review-evidence-allowed-signers`.
6. Only verified v2 evidence may publish `Review evidence gate (attested)`.

Benefits:

- no private review contents cross the CI boundary;
- no private key or mutable operator secret is stored in GitHub Actions;
- no new Python cryptography dependency;
- uses an already available OpenSSH signing primitive with explicit namespace separation and allowlisted principals;
- small implementation and operational surface.

Costs and burden:

- protect and back up a dedicated private key;
- document rotation and loss recovery;
- ensure hosted runners continue to provide a compatible `ssh-keygen`;
- bootstrap the required-check policy carefully so the repository trust root cannot be changed by the same unsigned path it is meant to replace.

Decision: implement now.

### 2. Sigstore/keyless or GitHub artifact attestations — defer

Sigstore can sign blobs with ephemeral identity-backed keys and avoid a long-lived local signing key. GitHub artifact attestations use Sigstore and bind artifacts to GitHub Actions workflow identity.

For this use case, however, the authoritative audit is generated locally and intentionally remains private. Moving attestation generation into GitHub Actions would either require uploading more private material or would merely attest a user-supplied digest, recreating the original assertion problem. A local keyless Sigstore path would add external CLI, OIDC identity and availability dependencies without removing the need to define which local review execution is authoritative.

Decision: defer unless the review gate itself later moves into a trusted remote execution environment or an organization-wide identity-backed attestation service becomes available.

### 3. Repository-bound hash manifest — reject as authenticity control

A committed or posted manifest containing `audit_sha256`, head, base and diff can improve traceability and stale-data detection, but it adds no authenticity when the same repository write-capable principals can create both the manifest and the status assertion.

Decision: retain hashes as signed binding fields, but do not treat an unsigned repository manifest as provenance.

## Key and trust-root layout

Local private key:

`~/.config/grabowski/review-evidence-signing-ed25519`

Repository public allowlist:

`config/review-evidence-allowed-signers`

Signer principal:

`grabowski-review-gate@heimgewebe`

Signature namespace:

`review-evidence@grabowski.heimgewebe`

Initial key fingerprint:

`SHA256:HgacCWPT8Z9urRow2+ha1ejQpAigRCIGskCCAEBHULs`

The private key is local-only and must never be committed, pasted into a PR comment or exposed to GitHub Actions. The public key is not secret.

## Rotation

Normal rotation should preserve continuous trust:

1. Generate a new dedicated key locally.
2. Add the new public key to the allowlist while the old key still works.
3. Merge that trust-root change using evidence signed by an already trusted key.
4. Produce and verify at least one v2 status with the new key.
5. Remove the old public key in a second reviewed change.
6. Destroy or archive the retired private key according to the local secret-retention policy.

## Loss recovery

A required gate with only one signing key can cause repository lockout if that key is lost. Required-check activation therefore needs one of these proven recovery paths before rollout:

- a separately protected recovery signing key whose public key is already allowlisted; or
- a tested break-glass procedure that can temporarily change the repository ruleset, rotate the trust root, and restore the required check with an auditable receipt.

Do not add a placeholder or commented recovery public key. Recovery is proven only when a real separately protected private key exists and its public key is already trusted, or when the break-glass path has been exercised and recorded.

Until one recovery path is proven, v2 may be exercised live but `Review evidence gate (attested)` should remain non-required.

## Required-gate blockers

The following are explicit blockers, not deferred implementation details that may be assumed away:

1. **Publisher identity:** prove that only the intended review-evidence publisher can satisfy the required context. A source restriction to the general GitHub Actions integration is insufficient if unrelated workflows under the same integration can publish the same context.
2. **Supersession contract:** decide whether authority follows the latest submitted v2 command or the latest successfully completed attestation. Whichever model is selected must prevent an older green status from remaining merge-authoritative after it has become semantically stale.
3. **Cryptographic supersession authority:** decide whether malformed or unsigned v2-prefixed comments may supersede valid attested generations. For a hard gate, requiring a valid signature before a v2 comment gains supersession authority is the safer default unless an explicit fail-red policy is preferred.
4. **Recovery:** prove key rotation and key-loss recovery without relying on the single active private key.
5. **Merge basis:** require an up-to-date/strict merge basis or equivalent merge queue.

## Required-rollout conditions

The status may become required only when all of the following are true:

1. A real PR has produced a successful v2 status from the trusted default-branch workflow.
2. Invalid, tampered, unsigned and wrong-key v2 inputs have been observed to fail closed.
3. The protected branch enforces an up-to-date/strict merge basis or equivalent merge queue.
4. The required `Review evidence gate (attested)` status has a publisher identity that is exclusive to, or cryptographically equivalent to, the intended review-evidence evaluator; binding only to the general GitHub Actions integration is not sufficient proof of workflow identity.
5. The selected supersession contract has been tested across queued, cancelled, failed-before-publication, superseded and runner-unavailable executions, with no stale green status remaining merge-authoritative contrary to that contract.
6. The signer allowlist and default-branch evaluator are protected by the resulting gate.
7. Key rotation and key-loss recovery have a tested, auditable path.
8. Independent high-critical/platform review requirements remain separate.

## Operational commands

Unsigned advisory projection:

`python3 tools/pr_review_gate_ci.py prepare --audit <audit.json> --comment`

Signed v2 projection:

`python3 tools/pr_review_gate_ci.py prepare-attested --audit <audit.json> --signing-key ~/.config/grabowski/review-evidence-signing-ed25519 --comment`

The v2 output is a PR comment command. It contains the sanitized status projection and an OpenSSH signature, not the private audit contents.

## References

- GitHub Docs: Artifact attestations — GitHub Actions/Sigstore provenance model.
- Sigstore Docs: Signing blobs — keyless and key-backed blob signing.
- OpenSSH `ssh-keygen(1)`: `-Y sign`, `-Y verify`, allowed signers and signature namespaces.

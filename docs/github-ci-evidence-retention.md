# Durable GitHub CI evidence under Actions retention

GitHub Actions checks, workflow runs and commit statuses are external source data with finite retention. A stored run URL or run ID is therefore not a durable evidence address.

## Contract

Preparing `github` operator-obligation evidence remains strictly read-only. At the mutating completed-close boundary, Grabowski freshly revalidates the supplied GitHub v2 evidence and only then writes the canonical observation material to a private, create-only, content-addressed archive under the Grabowski state root. The evidence SHA-256 is the archive key and still hashes the canonical observation material. A completed close is blocked if new GitHub v2 evidence cannot be durably bound.

Later verification remains **live-first**:

1. If GitHub still exposes the bound PR/check history, Grabowski recomputes the observation from GitHub and requires the exact stored digest.
2. If the GitHub check/run history is unavailable, Grabowski may use only a server-created archive whose reference, canonical material, evidence digest and archive-envelope digest all verify.
   Only an explicit GitHub source-history unavailability condition opens this fallback. Generic adapter failures such as local command errors, budget exhaustion or oversized responses stay `stale` and never become verified from the archive.
3. If live GitHub data is present but contradicts the stored identity or result, the archive never overrides the contradiction; verification fails closed. Even when retained check history is gone, any still-visible PR head/base/merge identity must match before archive fallback is allowed.
4. Historical evidence created before this archive existed does not become trustworthy retroactively. If GitHub has already removed its source and no server archive exists, it remains `stale`/unverified.

The archive preserves the normalized fields used by the GitHub evidence adapter, including commit identities, check/status identities, conclusions, check-suite/application identity and workflow run/workflow identity. It is a durable server-derived receipt of the authoritative observation, not a byte-for-byte archive of GitHub logs or artifacts.

## Operational consequence

Long-lived `PROVEN` contracts must not treat `actions/runs/<id>` as an archival location. Proofs that require original logs or arbitrary GitHub API payloads need an additional export path before provider retention removes them. Existing old run links therefore still require a one-time inventory and rescue decision; this change hardens newly prepared Grabowski evidence and prevents the same failure mode from recurring there.

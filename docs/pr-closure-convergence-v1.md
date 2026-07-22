# PR Closure Convergence Optimization v1

## Overview

The PR closure convergence optimization provides a deterministic, hash-bound request builder for the existing `convergence-assess` protocol and integrates a read-only `next_convergence_action` recommendation into the operator current-work projection.

## Truth Boundaries & Non-Claims

- Source records (PR, deployment, Bureau/obligation, checkout/worktree) remain authoritative in their existing stores.
- The request builder consumes explicitly supplied evidence records or authoritative projection inputs. It never invents missing evidence, never claims unread live truth, and never creates a second lifecycle database.
- Recommendations do not grant mutation authority (no automatic merge, deployment, obligation closeout, or worktree deletion).
- All governor boundaries (review, CI, lease safety, dirty checkout protection) remain fail-closed.

## Evidence Categories & Profile

The `pr-closure-v1` profile binds four mandatory evidence categories:

1. **`pr_merge`**: PR merge receipt (`github-pr:<repo>#<pr>@<commit>`).
2. **`deployment_live`**: Deployment live receipt (`grabowski-release:<release_id>`).
3. **`obligation`**: Operator obligation / Bureau task completion receipt (`obligation:<id>` / `bureau:task:...`).
4. **`checkout`**: Checkout / worktree cleanup or archival evidence (`grabowski:checkout:<key>`).

Missing, conflicting, or stale evidence is explicitly bound into `blocked_by`, `conflicts`, and `missing_evidence` rather than smoothed.

## Convergence Recommendation Ordering

The read-only `next_convergence_action` recommendation prioritizes finishable chains in the following order:

1. `merge-ready`: PR review and CI pass, ready for merge evaluation.
2. `merged-not-live`: PR merged, awaiting deployment verification.
3. `live-not-closed`: Deployment verified live, awaiting terminal obligation closure.
4. `closed-not-cleaned`: Obligation closed, awaiting worktree hygiene / lease release.

When no finishable chain is active, standard blocking, resumable, or converged workspace recommendations apply.

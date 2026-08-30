# D2 post-S3 coupling stop decision — 2026-08-30

## Binding

- repository: `heimgewebe/grabowski`
- measured current-main revision: `30ccbe9b49f794fc4ffe1cbb2062e5d9fbf0dfca`
- proof branch was rebased onto that revision before the final measurement; its only added path is this note
- preceding S3: PR #976, `refactor: inject merge guard resource authority`

This note is a revision-bound architecture decision. It does not claim that future revisions retain the same graph or that the remaining cycle is intrinsically desirable.

## Fresh structural measurement

Reproduction:

```sh
python3 tools/coupling_baseline.py --repo . --output /tmp/grabowski-coupling-d2.json
```

Observed on the bound revision:

- modules: **131**
- import edges: **385**
- cyclic SCCs: **1**
- largest cyclic SCC: **34 modules**
- internal edges in that SCC: **120**
- direct mutual-import pairs inside the SCC: **11**

The older post-S2 snapshot used in the rest-plan discussion had a largest SCC of 37 modules. The exact S3 boundary is narrower and was remeasured directly from Git objects with the same static-import/SCC calculation:

- S3 parent `a3c9c81d2c2a53c4626a86e6d8bf8d2bd7e005e8`: **130 modules / 381 edges / largest SCC 36**
- S3 commit `8bf15e8ec07bd2a4eddfb4b2bf29ce2fd99bfb7e`: **130 modules / 380 edges / largest SCC 34**
- current bound main `30ccbe9b49f794fc4ffe1cbb2062e5d9fbf0dfca`: **131 modules / 385 edges / largest SCC 34**

Thus the broader post-S2-to-current progression is **37 → 34**, while S3 itself produced the directly attributable **36 → 34** reduction and that reduction remained stable as the repository grew afterward.

## D2 sensitivity ranking

A read-only edge-removal sensitivity check was run against the exact 34-module SCC. No single internal import edge reduced the largest SCC by more than one module: the best hypothetical single-edge result was **34 → 33**.

The highest-coupling nodes inside the SCC were:

| module | internal degree | outgoing | incoming |
| --- | ---: | ---: | ---: |
| `grabowski_tasks` | 22 | 14 | 8 |
| `grabowski_mcp` | 19 | 4 | 15 |
| `grabowski_grips` | 18 | 16 | 2 |
| `grabowski_resources` | 17 | 5 | 12 |
| `grabowski_checkouts` | 16 | 6 | 10 |
| `grabowski_operator` | 16 | 4 | 12 |
| `grabowski_agent_workspace` | 14 | 9 | 5 |

These are composition hubs, not automatic extraction targets. Removing all SCC-facing imports from a hub is only an upper bound and would imply large interface/migration changes.

## Strongest remaining local candidate

The most concrete small cluster was checkout terminalization:

- `grabowski_checkouts` ↔ `grabowski_checkout_terminal_reconciliation`
- `grabowski_checkouts` ↔ `grabowski_checkout_terminal_sources`

Hypothetically removing both outgoing mutual edges from `grabowski_checkouts` can reduce the largest SCC to **32**.

However, the cost is not local:

- `grabowski_checkout_terminal_reconciliation` currently uses **32 distinct** `grabowski_checkouts` attributes across **58** attribute uses;
- those dependencies include lifecycle/retention projections, SQLite access, Git/worktree observation, resource/task/process coordination, operation locking and hashing;
- removing the reverse imports without duplicating truth would require a substantial checkout authority/interface extraction or composition rewrite.

That is materially more migration surface than S3's focused resource-authority injection.

## Operational evidence

Fresh seven-day operator optimization evidence did not identify checkout terminalization or the remaining SCC as a leading failure path.

The leading current findings were instead:

1. repeated Bureau contract failures;
2. unresolved friction-decision backlog;
3. resource reclamation requiring provenance-specific analysis;
4. repeated guarded-path blockades.

The verified audit signal had `uncertain_outcome = 0`. Therefore there is no current operational-error signal strong enough to justify the checkout extraction cost merely to reduce the SCC by at most two additional modules.

Operator optimization report binding:

- report SHA-256: `d443c9f7ec0a3dccbeeb46bddbca2feadc2a355cef43cca48afda479ba91b2db`
- audit projection SHA-256: `19211c1512dcd5c59fdabc39e4b7d97536455510e9cfb74a96b5953e08cf03cd`

## Decision

**STOP additional architecture seams after S3 on this revision.**

Rationale against the Restplan threshold:

- S3 achieved a directly measured **36 → 34** SCC reduction; the broader post-S2-to-current progression is **37 → 34**.
- No remaining single edge has comparable leverage; the best is 34 → 33.
- The strongest two-edge local candidate has an upper-bound 34 → 32 effect but requires a broad checkout authority extraction.
- No current production/friction evidence ties that candidate to a leading operational failure.
- Further ports/interfaces would therefore cost more than the presently demonstrated structural and operational benefit.

This is the intended stop-rule outcome, not an assertion that SCC size must reach zero.

## Reopen conditions

Reopen architectural coupling work only if fresh evidence shows at least one of:

- a remaining cycle becomes a repeated operational failure path;
- a concrete seam removes multiple cycle edges while materially reducing authority duplication or fan-out with a small interface;
- a required feature exposes an existing multi-authority path that can be simplified rather than merely wrapped;
- the SCC grows materially or a new cyclic SCC appears;
- a future refactor makes one of today's expensive seams cheap as a side effect.

Absent such evidence, prioritize external publication convergence, evidence-based public tool-surface reduction and lifecycle hygiene over further SCC minimization.

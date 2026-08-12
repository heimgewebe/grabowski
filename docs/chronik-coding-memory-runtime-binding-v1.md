# Chronik coding-memory runtime binding v1

Grabowski consumes Chronik's producer-owned coding-memory runtime contract as a revision-bound vendored artifact.

The authoritative producer is `heimgewebe/chronik`. The exact producer commit, Git blob SHA and content SHA-256 are recorded in `contracts/chronik-coding-memory-runtime.binding.v1.json`; the vendored contract is `contracts/chronik-coding-memory-runtime.v1.json`.

`tools/validate_chronik_coding_memory_runtime.py` fails closed when:

- the vendored contract no longer matches the bound producer blob/content digest;
- Chronik declares a coding-memory dependency that is not an explicit direct Grabowski runtime pin;
- Grabowski's direct runtime pin and lock disagree;
- a Grabowski pin does not satisfy the producer constraint;
- the supported producer contract shape changes without an explicit consumer update.

The gate runs as part of `make validate` and before `deploy-check`, `deploy-preflight`, `deploy-apply` and scheduled `deploy`.

This binding does not claim that the currently deployed Chronik release equals the bound producer commit, that dynamic imports are absent, or that contract compatibility alone proves runtime success. Runtime execution remains fail-soft at the existing Chronik adapter boundary.

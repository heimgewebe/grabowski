# Chronik coding-memory runtime binding v1

Grabowski consumes Chronik's producer-owned coding-memory runtime contract as a revision-bound vendored artifact.

The authoritative producer is `heimgewebe/chronik`. The exact producer commit, Git blob SHA and content SHA-256 are recorded in `contracts/chronik-coding-memory-runtime.binding.v1.json`; the vendored contract is `contracts/chronik-coding-memory-runtime.v1.json`.

`tools/validate_chronik_coding_memory_runtime.py` fails closed when:

- the vendored contract no longer matches the bound producer blob/content digest;
- a producer-declared coding-memory distribution is absent from Grabowski's hashed runtime lock;
- the locked version does not satisfy the producer constraint;
- Chronik raises its Python floor beyond the interpreter executing Grabowski's validation/deployment gate;
- the supported producer contract shape or semantic `does_not_establish` boundaries change without an explicit consumer update.

The producer contract is checked against the resolved runtime lock rather than copied into a second set of Grabowski direct requirements. Packages already provided transitively remain transitive; if a future lock regeneration removes one, this gate fails before deployment. Grabowski's ordinary direct-requirement/lock consistency remains owned by the existing runtime-lock contract.

The gate runs as part of `make validate` and before `deploy-check`, `deploy-preflight`, `deploy-apply` and scheduled `deploy`.

This binding does not claim that the currently deployed Chronik release equals the bound producer commit, that dynamic imports are absent, or that contract compatibility alone proves runtime success. Runtime execution remains fail-soft at the existing Chronik adapter boundary.

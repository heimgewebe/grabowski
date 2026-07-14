# Scoped operator blockades

Grabowski blockades use two independent axes: **scope** describes where a
restriction applies, and **posture** describes how strongly that scope is
restricted. This avoids turning every local failure into a host-wide outage
without weakening fail-closed behavior for genuine trust failures.

The pure decision core is implemented in `src/grabowski_blockades.py`. It does
not read or write the filesystem. Persistence, audit append, quarantine, fsync
and runtime dispatch belong to typed adapters and remain a separate,
lease-bound integration phase.

## Scope axis

From narrowest operational target to broadest:

| Scope | Match rule | Typical use |
| --- | --- | --- |
| `path` | exact absolute path or descendant | corrupt or contested artifact |
| `capability` | exact capability name | unsafe write or deploy surface |
| `task` | exact task identity | failed or inconsistent execution |
| `owner` | exact lease/worker owner | compromised or stale worker |
| `repo` | exact absolute repository path or descendant | repository-wide drift |
| `service` | exact service identity | unhealthy deployment target |
| `host` | exact host identity | host-local trust failure |
| `global` | all actions | system-wide trust failure |

Path and repository matching is component-aware. `/srv/data` matches
`/srv/data/item`, but not `/srv/database`. A missing action attribute never
matches a specific scope.

## Posture axis

Postures are strictly ordered and compose monotonically:

```text
observe < preflight_required < mutation_freeze < hard_stop
```

| Posture | Mutation behavior | Read and recovery behavior |
| --- | --- | --- |
| `observe` | allowed | warning/evidence only |
| `preflight_required` | allowed only with a fresh explicit preflight | immutable reads remain open |
| `mutation_freeze` | mutation denied in the matching scope | read, status, audit and exact recovery remain open |
| `hard_stop` | normal mutation denied in the matching scope | immutable reads and exact recovery remain open |

All active matching records are evaluated. The strongest posture wins. A later
or narrower weak record cannot reduce a stronger record. Severe blockades do
not expire automatically; `mutation_freeze` and `hard_stop` require an explicit
evidence-bound resolution.

## Global hard-stop boundary

A global `hard_stop` is reserved for failures that invalidate global trust,
including:

- invalid or provenance-unknown audit history;
- invalid deployed-runtime provenance;
- compromised broker, recovery or root identity;
- an externally engaged environment stop;
- damage with credible host-wide or cross-scope reach.

The following are not sufficient on their own:

- one failed CI test;
- one stale or overlapping lease;
- one task failure;
- one invalid file;
- one unhealthy service;
- connector friction without integrity loss.

Those cases must use the smallest scope that safely contains the observed
risk. The core enforces an explicit allowlist of global-trust trigger classes for
a global `hard_stop`; a local trigger cannot merely claim global scope.
Escalation may be automatic when stronger evidence arrives. De-escalation must
remain explicit and evidence-bound.

## Decision matrix

| Action | No match / observe | Preflight required | Mutation freeze | Hard stop |
| --- | --- | --- | --- | --- |
| immutable read | allow | allow | allow | allow |
| status | allow | allow | allow | allow |
| audit read | allow | allow | allow | allow |
| mutation | allow | require fresh preflight | deny | deny |
| recovery disarm | no target | exact evidence only | exact evidence only | exact evidence only |

An active external environment record blocks all in-band disarm. It must be
cleared through the external control plane that engaged it.

## Record requirements

A persisted v1 record contains:

- schema version and unique blockade identity;
- posture and scope;
- bounded reason and trigger class;
- timezone-aware engagement time;
- one or more concrete evidence references;
- complete tool, request, session, task and owner provenance;
- source and disarm policy;
- optional expiry only for `observe` and `preflight_required`.

Canonical JSON uses sorted keys and compact UTF-8 encoding. Evidence
references are validated, duplicate entries are rejected and the remaining
references are sorted before hashing, so equivalent
records cannot acquire different identities from caller ordering. Its SHA-256 is
the record identity used by recovery validation.

## Evidence-bound disarm

The pure validator requires all of the following before a typed runtime adapter
may mutate state:

- exact blockade ID;
- exact canonical record SHA-256;
- exact scope;
- observed marker path equal to an expected canonical path supplied separately
  by the trusted runtime adapter, not by the evidence payload;
- marker present, regular and single-link;
- mode `0600` and expected owner;
- external environment stop absent;
- valid audit history;
- valid deployed provenance;
- fresh canonical recovery evidence;
- ready root broker.

The core returns a decision only. The runtime adapter must still perform a
create-only or quarantine transaction, directory fsync, absence readback and
audit receipt. No generic write, terminal or indirect execution surface may
create or clear the canonical record.

## Legacy compatibility

A legacy canonical marker is adapted to a global `hard_stop` record with an
in-band recovery policy. An external environment stop is adapted to a global
`hard_stop` with `external_only` recovery. These adapters are deterministic and
do not mutate state.

## Test isolation

Blockade and denial proofs must run against a transient process with temporary
`HOME` and state roots while using the deployed artifact under test. Tests must
reject the canonical production path. Success, exceptions and signal cleanup
must leave production state byte-for-byte unchanged.

The initial core intentionally does not modify `src/grabowski_mcp.py`,
`src/grabowski_capabilities.py`, generated contracts or runtime entrypoints.
Those files were held by an independent workspace lease when this phase began.
Runtime integration follows only after authoritative release of those exact
resources.

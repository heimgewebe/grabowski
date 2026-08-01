# Reposkop context tool v2

## Purpose

`grabowski_reposkop_context` runs exactly one target-bound Reposkop-2.0 coherence report, validates its canonical local checkout identity and records deduplicated semantic usage evidence.

## Accepted artifact contract

The adapter accepts only:

- `reposkop_coherence_report` schema 2;
- `reposkop_checkout_observation` schema 2 with `observation_complete: true`;
- `reposkop_coherence_projection` schema 1;
- the exact scoped authority boundary declaring Reposkop authoritative for checkout identity and transition truth;
- `effect_authorized: false` on report and projection;
- exact target path and purpose;
- canonical, independently reproducible observation, projection and report digests;
- valid repository and checkout identity digests.

Reposkop identity does not replace Grabowski's task, lease, process, GitHub, recovery or effect checks.

## Live result versus persistent receipt

The tool result returns the complete current Reposkop report, including its observation, projection and report digests. These digests bind one exact capture and therefore change when `observed_at` or `generated_at` changes.

The persistent create-only usage receipt deliberately excludes those volatile capture digests. Its semantic identity binds:

- canonical target path and purpose;
- exact Reposkop executable digest;
- repository identity digest;
- checkout identity digest;
- a stable semantic observation digest computed after removing `observed_at` and `observation_sha256`;
- a stable semantic projection digest computed after removing capture-bound observation validation and projection digests.

Repeating an unchanged semantic checkout observation therefore replays one receipt and one audit binding even when capture timestamps and top-level artifact digests differ. A changed checkout identity, executable, Git state or coherence projection creates a new receipt key.

## Publication and recovery

Receipt publication remains private, create-only, exact-byte and audit-bound. Root, pending, final and lock paths are checked against Grabowski's write-root policy and bound to validated directory descriptors. Replays verify exact deterministic bytes and the matching audit record. Existing exact receipts without a current audit binding use the explicit recovery audit contract rather than claiming audit-before-create ordering.

## Non-goals

- no daemon or global scan;
- no effect authorization;
- no task, queue, PR or remote truth;
- no receipt per polling timestamp;
- no substitution for post-effect transition and continuity checks.

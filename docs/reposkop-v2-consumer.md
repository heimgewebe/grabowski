# Reposkop 2.0 consumer binding

Grabowski consumes Reposkop's canonical local checkout identity through `grabowski_reposkop_context`.

The adapter accepts only:

- coherence report schema v2;
- checkout observation schema v2 with `observation_complete: true`;
- coherence projection schema v1;
- the exact scoped authority boundary from Reposkop 2.0;
- `effect_authorized: false` on report and projection;
- canonically reproducible observation, projection and report digests.

The live tool result retains the exact capture digests. The private usage receipt deliberately excludes those volatile digests and binds:

- the Reposkop executable digest;
- canonical target path and purpose;
- repository and checkout identity digests;
- a semantic observation digest without `observed_at` and `observation_sha256`;
- a semantic projection digest without capture-bound observation validation and projection digests.

The matching audit record binds the receipt schema version, exact receipt bytes and the same stable identity fields. An unchanged semantic checkout therefore replays one receipt and one audit binding even when capture timestamps and exact artifact digests change.

## Rollout order

1. Install or update the Reposkop 2.0 executable.
2. Prove `reposkop report <target> --purpose grabowski-repo-state-context --json` emits a valid report v2.
3. Deploy the matching Grabowski runtime.
4. Invoke `grabowski_reposkop_context` for a clean explicit checkout.
5. Verify the private receipt and audit binding.
6. Only then add automatic transition hooks to risk-bearing Git and worktree effects.

An old Reposkop executable with the new Grabowski adapter fails closed. A new Reposkop executable with the old Grabowski adapter also fails closed because the report schema changed. The cutover therefore requires one coordinated maintenance operation and post-deploy readback.

Reposkop identity does not replace Grabowski's lease, process, GitHub, recovery or effect checks.

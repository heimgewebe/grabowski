# Reposkop 2.0 consumer binding

Grabowski consumes Reposkop's canonical local checkout identity through `grabowski_reposkop_context`.

The adapter accepts only:

- coherence report schema v2;
- checkout observation schema v2 with `observation_complete: true`;
- coherence projection schema v1;
- the exact scoped authority boundary from Reposkop 2.0;
- `effect_authorized: false` on report and projection;
- canonically reproducible observation, projection and report digests.

The private usage receipt binds:

- the Reposkop executable digest;
- report and observation digests;
- repository and checkout identity digests;
- projection digest;
- target path and purpose.

## Rollout order

1. Install or update the Reposkop 2.0 executable.
2. Prove `reposkop report <target> --purpose grabowski-repo-state-context --json` emits a valid report v2.
3. Deploy the matching Grabowski runtime.
4. Invoke `grabowski_reposkop_context` for a clean explicit checkout.
5. Verify the private receipt and audit binding.
6. Only then add automatic transition hooks to risk-bearing Git and worktree effects.

An old Reposkop executable with the new Grabowski adapter fails closed. A new Reposkop executable with the old Grabowski adapter also fails closed because the report schema changed. The cutover therefore requires one coordinated maintenance operation and post-deploy readback.

Reposkop identity does not replace Grabowski's lease, process, GitHub, recovery or effect checks.

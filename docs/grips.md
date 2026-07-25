# Grabowski Grip Surface

## Bureau Pickup Grips

The stable `grip_run` surface exposes three narrow wrappers around the existing typed Bureau pickup adapter:

- `bureau-pickup-execute` dispatches one complete request to `grabowski_bureau_pickup_execute`. It does not duplicate claim, lease, Registry-root, recovery or compensation logic.
- `bureau-pickup-status` reads one run through `grabowski_bureau_pickup_status` and remains read-only.
- `bureau-pickup-release` dispatches only to `grabowski_bureau_pickup_release`, which requires terminal Bureau readback and exact unchanged owner/resource binding.

This surface exists because long-lived clients may retain a frozen top-level MCP schema while `grip_run` remains available. A pickup grip is not a fallback to shell, Python module execution or generic resource release. The underlying typed adapter remains authoritative for operator gates, Registry-root binding, immutable journals, compensation, ambiguity handling and terminal release.

Receipt semantics are explicit:

- a successful commit, status read or release is `passed`;
- `claim-commit-recovery-required` is `blocked` and preserves the structured recovery result;
- `claim-commit-not-applied` is `failed` and preserves compensation evidence;
- an incomplete release is `failed`; other release refusals remain `blocked`.

The grips do not establish task verification, workspace cleanup authority, permission to release foreign leases, or safety of retrying an ambiguous commit without fresh authoritative readback.

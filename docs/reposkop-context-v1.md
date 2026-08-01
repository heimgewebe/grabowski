# Reposkop context tool v1 — historical contract

This document describes the retired Reposkop-1 consumer contract. It is retained only for hash-stable historical references.

The active Grabowski consumer accepts Reposkop 2.0 artifacts and is specified in [`reposkop-context-v2.md`](reposkop-context-v2.md).

## Historical boundary

Version 1 accepted:

- `reposkop_coherence_report` schema 1;
- `reposkop_checkout_observation` schema 1;
- `reposkop_coherence_projection` schema 1;
- `effect_authorized: false`;
- exact target and purpose binding.

Version 1 receipts intentionally excluded the encompassing report digest from their semantic deduplication identity. New consumers must not reconstruct current receipt semantics from this historical document.

The v1 contract is not accepted by the current adapter and must not be used for new integrations.

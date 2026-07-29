# Reposkop context tool v1

## Purpose

`grabowski_reposkop_context` runs exactly one target-bound Reposkop coherence report and records that the report was actually consumed through Grabowski. It closes the gap between documented Reposkop availability and observable operator use without adding a daemon, global scan or action gate.

## Call contract

Inputs:

- `repo`: one existing absolute, non-symlink directory;
- `purpose`: one bounded token, default `grabowski-repo-state-context`.

The tool invokes only the owner-held, regular, singly linked and executable `${HOME}/.local/bin/reposkop` path:

```text
reposkop report <absolute-target> --purpose <purpose> --json
```

The command has fixed runtime and output limits. The target checkout cannot replace the executable through `PATH`, Python import precedence or a same-named file. The executable identity is checked again after execution; drift invalidates the result.

## Validation boundary

The result is accepted only when:

- the report is exactly `reposkop_coherence_report` schema 1;
- its observation is exactly `reposkop_checkout_observation` schema 1;
- its projection is exactly `reposkop_coherence_projection` schema 1;
- report and projection both declare `effect_authorized: false`;
- reported target path and purpose exactly match the request;
- observation, projection and report SHA-256 fields are present and well formed.

Reposkop remains an observer. The output does not establish task, queue, pull-request or remote truth and never authorizes cleanup or another mutation.

## Usage receipt

A successful observation creates one private receipt under the Grabowski state root. Its identity binds:

- canonical target path;
- purpose;
- exact Reposkop executable SHA-256;
- observation SHA-256;
- projection SHA-256.

The receipt bytes are fully deterministic. Generated timestamps and the encompassing report digest are not stored in the receipt and are deliberately not part of the deduplication key. Repeating the same semantic observation therefore expects exactly the same bytes instead of manufacturing usage volume. A changed observation, projection or executable creates a new key and a new receipt.

Receipt, pending-file and lock paths are authorized before state creation. The receipt directory is owner-held mode `0700`; lock, pending and final files use mode `0600` and reject symlinks, foreign ownership, unexpected link counts, size drift, inode drift and any byte mismatch.

Publication is serialized by a per-key advisory file lock. The verified Grabowski audit binding is appended **before** any receipt bytes are published and binds the exact expected receipt SHA-256 and byte count. The receipt is then written to a deterministic pending file, fsynced, linked create-only to its final name and reduced to one final link. A crash after the audit append but before final publication is recoverable from the same exact audit binding. A crash after linking but before pending-file removal is recovered only when both paths resolve to the same exactly bound inode.

Every replay first validates the deterministic receipt bytes and then searches the verified audit chain for the exact byte and identity binding. If that exact binding is absent or older than the bounded search window, the fresh current Reposkop observation appends a new exact audit binding before the receipt is returned. A byte mismatch still fails closed. Concurrent identical calls wait on the same lock, yielding one publication and ordinary replay results rather than exposing a partial file.

## Why this is a separate tool

A generic terminal call can launch Reposkop, but cannot enforce the fixed executable, target binding, authority-boundary validation, audit-before-create contract or semantic receipt deduplication. Combining generic terminal and file-write surfaces would grant broader caller-controlled command and path authority while producing weaker evidence.

The dedicated tool has one narrow call shape: target in, validated coherence report and immutable, audit-bound usage evidence out.

## Non-goals

- no permanent process or scheduled scan;
- no global repository discovery;
- no decision-change or product-value claim from receipt presence;
- no replacement for Git, GitHub, Bureau, lease, process or deployment readbacks;
- no effect authorization.

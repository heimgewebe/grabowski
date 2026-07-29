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

- report and projection use the supported schema;
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

Generated timestamps and the encompassing report digest are deliberately not part of the deduplication key. Repeating the same semantic observation therefore reuses the existing receipt instead of manufacturing usage volume. A changed observation, projection or executable creates a new receipt.

Receipt creation is authorized before any directory or file is created. The directory is owner-held mode `0700`; receipts are create-only regular files with mode `0600`, single-link validation, file and directory `fsync`, and exact identity readback. Existing receipt drift fails closed.

The first creation is appended to the verified Grabowski audit chain and returns its exact audit-record digest. If the audit append fails, the new receipt is removed before the tool fails. Replaying an unchanged semantic observation creates neither another receipt nor another audit record.

## Why this is a separate tool

A generic terminal call can launch Reposkop, but cannot enforce the fixed executable, target binding, authority-boundary validation or semantic receipt deduplication. Combining generic terminal and file-write surfaces would grant broader caller-controlled command and path authority while producing weaker evidence.

The dedicated tool has one narrow call shape: target in, validated coherence report and immutable usage evidence out.

## Non-goals

- no permanent process or scheduled scan;
- no global repository discovery;
- no decision-change or product-value claim from receipt presence;
- no replacement for Git, GitHub, Bureau, lease, process or deployment readbacks;
- no effect authorization.

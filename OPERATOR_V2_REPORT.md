# Operator v2 Report

## Scope

This port integrates the Operator v2 foundation into the current-main
worktree without changing live configuration, services, deployed runtime,
commits, or remotes.

Implemented:

- v1 policy compatibility for existing policies without typed secret/browser
  fields.
- v2 policy validation for `secret_roots`, `browser_profile_roots` and
  `secret_export_roots`.
- Fail-closed runtime validation for unknown top-level fields, unknown profile
  fields, unknown capabilities, duplicate capabilities, invalid limits and v1
  policies carrying v2-only fields.
- Dedicated tools and capabilities:
  `secret_inspect`, `secret_reveal`, `secret_use`, `secret_export` and
  `browser_profile_read`.
- Generic read/list/stat/write blocking for secret and browser profile roots.
- Secret reads bound to no-symlink path walks, `O_NOFOLLOW` where available,
  regular-file snapshot checks, hardlink rejection and byte limits.
- `secret_reveal` as the only raw reveal path, with mandatory current SHA-256
  precondition.
- `secret_use` argv-only execution with `{SECRET_FD_PATH}`, memfd preference,
  restrictive temporary-file fallback, `pass_fds`, timeout cleanup and exact /
  base64 / URL-safe-base64 / URL-encoded output redaction.
- `secret_export` as local-only, create-only, source-hash-bound, atomic `0600`
  export under explicit export roots.
- `browser_profile_read` metadata/text access, with binary browser database
  content kept metadata-only.
- Quarantine-backed text replacement rollback and tamper-evident audit
  verification.
- Operator capability gates, mutation kill switch, safer command result
  redaction and the reference-only privileged-action contract.
- Runtime-entrypoint metadata for every existing current-main tool plus every
  new v2 MCP tool, preserving the current wrapper/supporting-source contract.
- Documentation, changelog, schemas, validator and policy examples aligned
  with the implemented contract.

Not activated:

- The live policy under `~/.config/grabowski/access.json` was not changed.
- The home-wide operator policy remains an example, not live metadata.
- No privileged local broker or fleet registration was added.
- No compatibility `private_*` tools were kept; the validator rejects retired
  `private_*` capability names in examples.

## Safety Notes

- Audit and evidence for sensitive mutating tools contain paths, hashes,
  transaction IDs, argv hashes, capability/profile metadata and postflight
  state only. They do not store secret values.
- `secret_reveal` returns raw text by design, but does not write that text to
  audit or evidence.
- `secret_use` never places the secret value in child argv or environment.
- Kill switch blocks mutating tools; read tools remain governed by their
  capabilities and hash policy.
- `~/repos/merges`, active policy, audit/quarantine state, broker policy and
  runtime-entrypoint paths remain protected from generic mutation.

## Validation

Passed in this port worktree:

```text
python3 -m unittest discover -s tests -v
git diff --check
make validate
```

`make validate` completed syntax checks, 198 unit tests, policy validation,
generated context validation, runtime/deploy-tooling lock validation,
deploy-tooling virtualenv verification and secret scanning.

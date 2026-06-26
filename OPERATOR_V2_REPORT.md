# Operator v2 Report

## Scope

Completed the Operator v2 secret/browser capability slice in this PR worktree
without changing live configuration, services, deployed runtime, or committing.

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
- Runtime-entrypoint metadata for every new MCP tool.
- Documentation, changelog and policy examples aligned with the implemented
  contract.

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
- Kill switch blocks `secret_use` and `secret_export`; `secret_inspect` and
  `secret_reveal` remain governed by their read capabilities and hash policy.
- `~/repos/merges`, active policy, audit/quarantine state, broker policy and
  runtime-entrypoint paths remain protected from generic mutation.

## Validation

Passed:

```text
python3 -m unittest tests.test_operator_v2_runtime -v
python3 -m unittest tests.test_repository_contract -v
python3 tools/validate_access_policy.py
make test
make validate
git diff --check
```

`make test` and `make validate` ran 135 tests successfully. `make validate`
also completed syntax checks, policy validation, runtime-lock validation,
deploy-tooling validation and secret scanning.

Blocked by environment:

```text
python3 tools/deploy_runtime.py --check
```

The check reached runtime dependency installation in a temporary check release,
then failed because the sandbox could not resolve PyPI for
`annotated-types==0.7.0` and pip cache access is disabled by ownership:

```text
Failed to establish a new connection: [Errno -5] Zu diesem Hostnamen gehört keine Adresse
ERROR: No matching distribution found for annotated-types==0.7.0
```

No live runtime, profile or service was changed by the failed check.

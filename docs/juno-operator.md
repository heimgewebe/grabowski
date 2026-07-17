# Juno Operator

Juno Operator is a local, read-only-first dashboard for the paired Juno iPad node.

## Contract

- Uses only the Python standard library.
- Discovers document roots without hard-coding app-container UUIDs in repository source.
- Supports an optional device-local `config/storage-roots.local.json` catalog for already consented roots whose parent directories iPadOS does not permit Juno to enumerate.
- Validates local catalog paths against bounded iPad document-provider domains and fails visibly on malformed or stale entries.
- Lists at most 100 immediate entries per storage root and never recursively reads private file contents.
- Network targets are fixed in `config/targets.json`, bounded to ten seconds, reject redirects, ignore proxy configuration and cap HTTP responses at 128 KiB.
- Writes only its own cache, dashboard and explicitly requested incident packages.
- Provides no free shell, repair button, service restart, task cancellation, deployment or deletion surface.
- A reachable HTTP service is not treated as proof of deployment identity.

## Device-local storage catalog

The deployed iPad project may contain a non-repository file at `config/storage-roots.local.json`:

```json
{
  "schema_version": 1,
  "roots": [
    {
      "label": "Auf meinem iPad",
      "path": "/private/var/mobile/Containers/Shared/AppGroup/.../File Provider Storage"
    }
  ]
}
```

This file contains paths, not bookmark bytes, tokens or credentials. App-container identifiers can change after reinstallations. Missing paths are ignored; malformed catalogs produce a visible warning instead of silently broadening access.

## iPad use

Open `Juno Operator.ipynb` and run the refresh cell. `run_juno_operator.py` provides the same operation from Juno's script runner. The generated `dashboard.html` is self-contained and uses no external assets.

## Incident package

`python run_juno_operator.py --incident` creates a new non-overwriting directory under `incidents/` with snapshot, dashboard, summary, checksums and manifest. It excludes secrets, environment dumps and document contents.

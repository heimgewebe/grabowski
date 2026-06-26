# Architektur

```text
ChatGPT
   |
   v
OpenAI Secure MCP Tunnel
   |
   v
Grabowski MCP
   |
   +-- Filesystem
   +-- Repositories
   +-- Patch / Transaction Engine
   +-- Shell / Jobs
   +-- Git
   +-- Lenskit / Atlas
   +-- User Services
   +-- Audit / Rollback
```

## Ebenen

### Control Surface
MCP-Tools und deren Schemas.

### Policy Layer
Explizite Lese-, Schreib- und Ausschlussregeln.
Optionale Operator-v2-Profile bündeln Roots, Limits und Capabilities.

### Execution Layer
Datei-, Prozess-, Git- und Serviceoperationen.

### Evidence Layer
Hashes, Diffs, Logs, Operation-IDs und Rollbackdaten.
Write-Audits sind hash-verkettet; Text-Ersetzungen bewahren eine quarantänierte
Vorversion für streng geprüfte Rollbacks.

## Grundsatz

Macht wird nicht durch Schwäche begrenzt, sondern durch Nachweisbarkeit,
Reversibilität und klare Wirkungsgrenzen.

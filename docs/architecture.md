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

### Execution Layer
Datei-, Prozess-, Git- und Serviceoperationen.

### Evidence Layer
Hashes, Diffs, Logs, Operation-IDs und Rollbackdaten.

## Grundsatz

Macht wird nicht durch Schwäche begrenzt, sondern durch Nachweisbarkeit,
Reversibilität und klare Wirkungsgrenzen.

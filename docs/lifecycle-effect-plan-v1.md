# Grabowski Lifecycle Effect Plan v1

## Zweck

Dieser Slice erweitert `GRABOWSKI-OPERATOR-SURFACE-V1-T071` um die fehlende Grenze zwischen read-only Lifecycle-Evidenz und späteren Effekten.

Ein Effektplan ist **keine Ausführungserlaubnis**. Er bindet lediglich:

- den gewünschten Effekt-Typ;
- die exakt klassifizierten Lifecycle-Objekte;
- deren `evidence_sha256`;
- die vollständigen gebundenen Source-Digests;
- den vorgesehenen Lease-Owner;
- die exakten Ressourcen, die unmittelbar vor einem Effekt als lebende Owner-Leases erneut belegt sein müssen.

Die unterstützten Planarten sind `task_archive`, `workspace_archive`, `retention_converge` und `current_projection_switch`.

## Eligibility

Archiv- und Retention-Pläne akzeptieren nur `terminal_archivable` mit explizitem `safe_to_archive=true` und leerer `normalization_errors`-Liste. Ein Wechsel der aktuellen Projektion akzeptiert nur bereits als `archived` klassifizierte Objekte.

Damit kann ein `ambiguous`, `active`, `blocking`, `recovery_required` oder `untouchable` klassifiziertes Objekt nicht durch die Planerstellung in einen effektfähigen Zustand umgedeutet werden.

## Stable create-only plan

`write_effect_plan()` persistiert einen validierten Plan unter einem deterministischen, SHA-256-gebundenen Dateinamen. Die Datei wird create-only und fsync-sicher geschrieben. Ein byteinhaltlich gleicher Plan kann idempotent wieder eingelesen werden; eine manipulierte oder widersprüchliche Datei schlägt fail-closed fehl.

Der Plan selbst trägt `mutation_performed=false` und begründet ausdrücklich keine:

- Effekt-Ausführung;
- physische Löschautorität;
- fortbestehende Quellidentität nach der Planung;
- fortbestehende Lease-Inhaberschaft;
- Erlaubnis zum Überschreiben fremder Ownership.

## Immediate revalidation

`revalidate_effect_plan()` muss unmittelbar vor einem späteren Executor aufgerufen werden. Die Revalidierung verlangt:

1. dieselben Lifecycle-Identitäten;
2. weiterhin dieselbe zulässige Klassifikation;
3. exakt denselben `evidence_sha256`;
4. exakt dieselben Source-Digests;
5. jede im Plan verlangte exakte Ressource als aktuelle Lease;
6. denselben Lease-Owner wie im Plan;
7. eine Lease-Laufzeit strikt über dem Revalidierungszeitpunkt.

Fehlende Objekte, geänderte Evidenz, geänderte Source-Digests, zwischenzeitlich aktive Zustände, fehlende Leases, fremde Owner, abgelaufene Leases und doppelte Lease-Beobachtungen blockieren fail-closed.

Auch `ready_for_effect=true` ist nur ein zeitpunktgebundener Revalidierungsbeleg. Es behauptet weder, dass der Effekt ausgeführt wurde, noch dass Evidenz oder Leases nach der Revalidierung unverändert bleiben.

## Noch nicht Teil dieses Slices

Dieser Slice führt absichtlich keine Archiv-, Retention-, Projektions- oder Löschoperation aus. Für den vollständigen T071-Abschluss fehlen weiterhin:

- konkrete Live-Collector-Adapter auf die typisierten Grabowski-Quellen;
- ein Executor, der nach Revalidierung die exakten Ressourcen selbst hält und vor jedem Effekt nochmals autoritativ prüft;
- create-only Effekt-Receipts nach belegter Mutation;
- atomare beziehungsweise recovery-sichere Task-Projektionsumschaltung;
- Workspace-Close-/Archive- und Retention-Konvergenz;
- typisierte paginierte Archiv-Read-Oberflächen;
- MCP-/Capability-Registrierung;
- Deployment und isolierter Livebeweis.

Physische Löschung bleibt außerhalb des T071-Vertrags.\n
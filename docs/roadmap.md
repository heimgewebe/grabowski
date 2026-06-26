# Roadmap

## GRABOWSKI-POWER-001

Status: v2 foundation implemented in repository; broader patch/search remains follow-up.

- vollständige Dateioperationen,
- Suche,
- Patch Engine,
- Papierkorb,
- Audit,
- Rollback.

## GRABOWSKI-SHELL-001

Status: v2 foundation implemented in repository; durable execution hardening in progress.

- allgemeiner Command Runner,
- persistente Hintergrundjobs,
- synchrone Hard-Timeouts,
- strukturierte Logs und Ergebnisartefakte,
- Prozesssteuerung ohne verwaiste Kindprozesse.

## GRABOWSKI-EVIDENCE-001

Status: Slice A implemented on `feat/grabowski-local-evidence`; pilot measurement pending.

- versionierte Job- und Result-Contracts,
- read-only Repo-State-, Diff- und Referenzbundles,
- Branch-/Head-Gates,
- sensible Pfadauslassung und Patch-Redaktion,
- Hashmanifest und Command-Provenance,
- deterministische Kernartefakte,
- noch keine MCP-Tool-Integration, Prüfprofile, Queue oder LLM-Schicht.

Der Ausbau beginnt erst nach einem realen Pilot mit messbarer Reduktion von
manuellen Evidenzschritten oder übertragenem Kontext.

## GRABOWSKI-OPERATOR-V2

Status: foundation implemented in repository; live cutover remains explicit.

- Access-Profile und Capabilities,
- Home-weites Operator-Beispiel ohne Live-Mutation,
- secret-safe argv-/Output-Redaction,
- Quarantäne und Rollback-Belege für Text-Ersetzungen,
- Kill-Switch für Mutationen,
- tamper-evidente Audit-Verifikation,
- unprivilegierter Referenzvertrag für spätere privilegierte Aktionen.

## GRABOWSKI-GIT-001

- Git-Lese- und Schreiboperationen,
- Worktrees,
- Commit und Push,
- Schutz fremder Änderungen.

## GRABOWSKI-KNOWLEDGE-001

- Lenskit- und Atlas-native Abfragen,
- Repo-Symbolsuche,
- Bundle-Freshness,
- strukturierte Codeanalyse.

## GRABOWSKI-OPS-001

- User-Services,
- Hoststeuerung,
- Downloads,
- Dokument- und Medienoperationen,
- GitHub-/PR-Orchestrierung.

## GRABOWSKI-DEPLOY-001

Status: implemented in repository; live cutover requires explicit deployment.

- reproduzierbares Deployment aus diesem Repo,
- atomarer Runtime-Wechsel,
- MCP-Handshake sowie Tool-List-Gate,
- Health- und Readiness-Gates,
- automatischer Rollback bei behandelbaren Deploymentfehlern,
- Deployment-Manifest mit Repo-HEAD, Source-Hash, Lockfile-Hash und Plattform-Provenienz,
- exklusiver Deployment-Lock,
- gestartete Runtime- und Prozessidentität,
- verhaltensbasierte Fehler- und Rollbacktests.


## GRABOWSKI-DEPLOY-002

- persistentes Deployment-Transaktionsjournal,
- atomare Phasenfortschreibung mit Datei- und Directory-`fsync`,
- Recovery von ursprünglichem Pointer und Legacy-Backup nach SIGKILL, Stromausfall oder Neustart,
- deterministische Startprüfung vor einem neuen Deployment,
- optionaler systemd-Recovery-Service nach eigenem Design-Gate.

## GRABOWSKI-FLEET-001

- Heimgewebe-Rolle bestimmen,
- Fleet-Registrierung im Metarepo,
- Produzenten und Konsumenten contractuell festlegen.

## GRABOWSKI-CONTROL-PLANE-001

Status: typed user-space control plane implemented; privileged execution remains fail-closed until an externally installed root-owned broker is approved.

- registrierte lokale und SSH-Ziele für `heim-pc`, `heimserver` und `heimberry`,
- argv-only Fleet-Ausführung mit Batch-SSH, deaktivierten Forwardings und Zeitgrenzen,
- Operationsrezepte mit Preflight, Action, Postflight und umgekehrtem Rollback,
- `secret_use` als Standard und begründungspflichtiges Break-Glass-`secret_reveal`,
- deterministische Connector-Snapshot-Probe,
- root-eigene Privileged-Action-Templates standardmäßig deaktiviert.

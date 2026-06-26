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

Status: v2 foundation implemented in repository.

- allgemeiner Command Runner,
- Hintergrundjobs,
- Timeouts,
- Logs,
- Prozesssteuerung.

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

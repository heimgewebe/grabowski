# Roadmap

## GRABOWSKI-OPTIMIZE-001

Status: registered plan; implementation slices must remain operator-reviewed and evidence-bound.

- canonical plan: `docs/operator-optimization-plan.md`,
- first priority: failed-task and friction signal classification,
- second priority: checkout/worktree hygiene through inventory, retention and archive-first cleanup,
- third priority: agent receipts, redaction tuning, function-preserving capability routing and fleet allowlist hardening,
- this roadmap entry authorizes no live policy change, cleanup, merge, push or deploy by itself.

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

Status: Slice A implemented on `main`; pilot measurement pending under GRABOWSKI-EVIDENCE-002.

- versionierte Job- und Result-Contracts,
- read-only Repo-State-, Diff- und Referenzbundles,
- Branch-/Head-Gates,
- sensible Pfadauslassung und Patch-Redaktion,
- Hashmanifest und Command-Provenance,
- deterministische Kernartefakte,
- noch keine MCP-Tool-Integration, Prüfprofile, Queue oder LLM-Schicht.

Der Ausbau beginnt erst nach einem realen Pilot mit messbarer Reduktion von
manuellen Evidenzschritten oder übertragenem Kontext.


## GRABOWSKI-EVIDENCE-002

Status: registered; real pilot records pending.

- Pilot-Record-Schema: `contracts/local-evidence-pilot-record.v1.schema.json`,
- Pilot-Record-Log: `docs/evidence-pilot.records.jsonl`,
- Pilot-Guide: `docs/local-evidence-pilot.md`,
- vorhandene `grabowski-local-evidence-*`-Bundles gelten als technische Fixtures,
- fünf historische Baseline-Fälle und fünf prospektive echte Aufgaben bleiben offen,
- keine MCP-Integration, Prüfprofile oder Knowledge-Selector-Erweiterung vor bestandenem Pilot-Gate.

## GRABOWSKI-OPERATOR-V2

Status: live in the deployed runtime; follow-up work is typed agent/fleet integration, not cutover.

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

Status: implemented and live in the deployed runtime; follow-up work is deployment transaction recovery hardening.

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

Status: typed user-space control plane implemented; root-owned privileged broker is installed and fail-closed, with broader privileged actions still gated by recovery evidence.

- registrierte lokale und SSH-Ziele für `heim-pc`, `heimserver` und `heimberry`,
- argv-only Fleet-Ausführung mit Batch-SSH, deaktivierten Forwardings und Zeitgrenzen,
- Operationsrezepte mit Preflight, Action, Postflight und umgekehrtem Rollback,
- `secret_use` als Standard und begründungspflichtiges Break-Glass-`secret_reveal`,
- deterministische Connector-Snapshot-Probe,
- root-eigene Privileged-Action-Templates standardmäßig deaktiviert.


## GRABOWSKI-OPERATOR-COMPLETION-001

Status: implemented and live; Reconcile now uses explicit check/refresh/resume semantics and legacy auto-resume is disabled as a compatibility path.

- atomare Ressourcenleases für Repo, Pfad, Port, Dienst, Browserprofil und Display,
- verlustfreie Task-DB-Migration und lease-gebundene persistente Tasks,
- Boot-/Perioden-Reconciliation mit explizitem Refresh ohne stillen Wiederanlauf,
- hashgebundener Artefakttransport mit Ziel-CAS und atomarer Publikation,
- agenteneigene Browserworker mit Loopback-CDP,
- isolierte Xvfb-GUI-Worker ohne Remote-Display-Listener,
- MCP-unabhängiger, inhaltsfreier Rootbroker-Status.

Hostseitig offen bleiben frische Server-Recovery-Evidence, Xvfb-Bereitstellung für breitere GUI-Workflows und der nächste Connector-Snapshot-Refresh nach neuen Toolverträgen.

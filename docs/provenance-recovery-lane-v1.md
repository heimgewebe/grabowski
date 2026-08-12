# Provenance-Recovery-Lane v1

## Problem

Das Integritätsgate ist richtig: eine Runtime mit ungültiger Deployment-Provenienz
darf keine normalen Wirkungen ausführen. Es schloss aber auch seinen eigenen
Reparaturpfad ein.

Konkret beobachtet am 2026-08-12 auf `ed4be785c6c89d6d3511fb9553d1e9f55ff5e503`:

* Deployment vollständig gebaut, Audit-Chain gültig, Kill-Switch frei.
* Trotzdem `manifest_schema_valid=false`, `entrypoint_contract_identity_valid=false`,
  `artifact_integrity_valid=false`, `provenance_valid=false`.
* Ursache: Build- und Runtime-Validator führten getrennte Feldlisten
  (siehe `grabowski_runtime_contract`), PR #738 fügte `browser_operator_default`
  hinzu, der Builder akzeptierte es, die Runtime verwarf es.

Die Folge war zirkulär:

* Self-Deploy braucht gültige Deployment-Provenienz.
* `grabowski_power_run` braucht gültige Deployment-Provenienz.
* Jede normale Mutation braucht einen Transport-Roundtrip, der
  `artifact_integrity_valid` verlangt.

Ein einziges fehlerhaftes Release sperrte damit genau die Aktion aus, die es
hätte reparieren können.

## Lösung

`grabowski_provenance_recovery` bricht die Zirkularität, ohne das Gate zu
schwächen. Zwei Tools:

| Tool | Autorität | Wirkung |
| --- | --- | --- |
| `grabowski_recovery_provenance_assess` | read | keine |
| `grabowski_recovery_provenance_repair` | mutation | genau ein revisionsgebundenes Runtime-Deployment |

### Autoritätsmodell

Die Lane leitet ihre Autorität **nicht** aus der als ungültig erkannten
Runtime-Provenienz ab. `provenance_valid` wird ausschließlich gelesen, um
festzustellen, dass eine Reparatur überhaupt gerechtfertigt ist.

Der zentrale Transport-Roundtrip verlangt für normale Mutationen eine
integritätsgültige Runtime. Genau für `grabowski_recovery_provenance_repair`
würde diese Vorbedingung den Reparaturpfad erneut zirkulär schließen. Deshalb
lässt der zentrale Dispatcher **nur dieses eine mutierende Tool** ohne normalen
Roundtrip bis zu seinem eigenen Recovery-Gate durch, und auch nur wenn alle
reparierbaren Integritätsflags explizite Boolesche Werte sind und mindestens
eines davon `false` ist. Fehlende/unklare Integrität, eine gesunde Runtime und
jede andere Mutation bleiben am normalen Transport-Gate. Diese enge Ausnahme
ist keine Reparaturautorität; Wirkung entsteht erst, wenn danach sämtliche
unabhängigen Recovery-Gates bestehen.

Alle Gate-Bedingungen (fail-closed, alle müssen erfüllt sein):

| Check | Bedeutung |
| --- | --- |
| `repair_warranted` | Runtime ist **nachweislich** integritätsungültig (unbekannt ≠ kaputt) |
| `audit_chain_valid` | Audit-Chain gültig |
| `audit_writable` | Audit-Chain beschreibbar |
| `kill_switch_clear` | Kill-Switch frei |
| `no_blocking_operator_blockade` | keine typisierte Operator-Blockade |
| `local_backup_marker_fresh` | frischer Backup-**Marker** (kein bewiesener Restore) |
| `privileged_broker_ready` | Privileged Broker vollständig gesund |
| `source_identity_bound` | Quelle sauber, `HEAD == origin/main == expected_head` |
| `target_contract_valid` | Ziel-Contract gültig unter dem vertrauten kanonischen Schema |
| `target_schema_judgeable` | Ziel führt byte-identisches Schema; sonst `indeterminate` |
| `target_deploys_canonical_validator` | Ziel deployt sein eigenes Validierungsschema |
| `no_competing_deployment` | Deploy-Lock frei, kein laufender Deploy-Job |

### Warum jedes Gate da ist — und was es kostet

Jedes Gate erkauft Sicherheit mit Verfügbarkeit. Bei einer Reparatur-Lane ist
das besonders heikel: ein Gate, das selbst ausfallen kann, erzeugt einen
Mehrfach-Fehler-Deadlock (Runtime kaputt **und** Gate kaputt = nicht
reparierbar). Deshalb hier explizit pro Gate.

| Gate | Verhindertes Risiko | Preis bei Ausfall |
| --- | --- | --- |
| `repair_warranted` | Lane als Umgehung geltender Gates | keiner (nur bei echtem Defekt offen) |
| `audit_chain_valid` / `audit_writable` | Reparatur ohne nachvollziehbaren Nachweis | kaputte Audit-Kette blockiert Reparatur |
| `kill_switch_clear` | Überstimmen eines expliziten Stopps | Kill-Switch blockiert (gewollt) |
| `no_blocking_operator_blockade` | Loch im Blockade-System | Blockade blockiert (gewollt) |
| `source_identity_bound` | Deploy eines nicht verifizierten Stands | dirty/divergenter Checkout blockiert |
| `target_contract_valid` | Reparatur in ein zweites kaputtes Release | – |
| `target_schema_judgeable` | Urteil über ein Schema, das dieser Prozess nicht implementiert | Schemawechsel braucht normalen Deploy-Pfad |
| `no_competing_deployment` | zwei gleichzeitige Deployments | laufender Deploy blockiert (gewollt) |

Zwei Gates sind **bewusst konservativ** und wurden hinterfragt:

* `privileged_broker_ready` — die Lane benutzt den Broker nicht. Das Gate ist
  reine Systemgesundheits-Kopplung. Es bleibt, weil ein Reparaturdeploy auf
  einem System mit defektem Privileged Broker ohnehin nicht in einen
  vertrauenswürdigen Zustand führt. **Preis:** defekter Broker blockiert
  Runtime-Reparatur.
* `local_backup_marker_fresh` — belegt einen frischen Backup-Marker, **keinen**
  verifizierten Restore. Der Deploy ist blue/green und behält das vorherige
  Release, Rollback hängt also nicht am Backup. Es bleibt als billige
  Zusatzabsicherung. **Preis:** abgelaufener Marker blockiert Reparatur.

Wer diese beiden Kosten nicht tragen will, sollte sie zu reiner Evidenz
degradieren statt sie zu entfernen — die Unterscheidung „blockierend“ vs.
„protokolliert“ ist die eigentliche Stellschraube.

### Bootstrap-Grenze: diese Lane repariert den *aktuellen* Deadlock nicht

Die Tools werden über den normalen Importpfad
(`grabowski_runtime` → `grabowski_provenance_recovery`) registriert. Sie
existieren also erst in einer Runtime, die dieses Release bereits deployt hat.

Konsequenz:

* Der am 2026-08-12 beobachtete Deadlock musste **einmalig von außen** behoben
  werden — über den direkten Deploy-Pfad (`make deploy-apply`), der als
  Werkzeug des Operators außerhalb des MCP-Gatesystems läuft.
* Diese Lane rettet **zukünftige** Deadlocks derselben Klasse, nicht den, der
  sie ausgelöst hat.

Ein In-Band-Pfad, der auch den allerersten Deadlock auffängt, müsste außerhalb
des Release-Artefakts liegen (z. B. im Privileged Broker). Das ist bewusst
nicht Teil dieser Arbeit.

### Operator-Checkliste

1. `grabowski_recovery_provenance_assess` mit dem exakten Ziel-Commit aufrufen.
2. Bei `allowed=false` die `reasons` lesen — jeder Eintrag benennt genau eine
   nicht erfüllte, unabhängige Bedingung.
3. `grabowski_recovery_provenance_repair` mit demselben Commit aufrufen.
4. Job bis zum Terminalzustand beobachten.
5. `grabowski_deployment_identity` lesen.
6. Bei gültiger Provenienz gelten wieder die normalen Gates.

### Kein Read-Pfad führt fremden Code aus

Eine frühere Fassung lud das kanonische Schema **aus dem Ziel-Commit** und
führte es aus — erst in-process, dann in einem Subprozess. Beides war falsch:

* `grabowski_recovery_provenance_assess` ist `read_only` und läuft auch dann,
  wenn ein Gate die Recovery ohnehin ablehnen würde. Ein Read-Tool, das beim
  bloßen Prüfen Wirkungen auslösen kann, ist kein Read-Tool.
* Ein Subprozess ist **keine Sandbox**: gleiche UID, gleiches Dateisystem.
  Belegt: ein Candidate-Validator hat während `assess` eine Datei auf dem Host
  geschrieben.

Heute gilt: Das Schema des Ziel-Commits wird **byteweise mit einem unabhängig
provisionierten root-eigenen Trust-Anchor** unter
`/etc/grabowski/runtime-contract-schema.py` verglichen und nie ausgeführt.
Zusätzlich muss der Validator, den der laufende Prozess bereits geladen hat,
bytegleich zu diesem Anchor sein. Erst dann dürfen dessen schon geladenen
Validatorfunktionen das Ziel-JSON beurteilen.

* Ziel == Anchor == laufender Validator → der Prozess besitzt einen unabhängig
  gebundenen Prüfer und darf urteilen;
* irgendeine Abweichung → `indeterminate`. Ehrliche Antwort: „das kann ich nicht
  beurteilen“. Eine Schemaänderung wird zuerst über den exakten commitgebundenen
  Rootbroker-Cutover im Anchor verankert und erst danach normal deployt.

Dieselbe Autoritätsgrenze gilt im Watchdog. Er lud früher das Schema aus der zu
prüfenden Release. Gemessen: ein Schema mit `os._exit` hat den Watchdog
**beendet** (der Integritäts-Exitcode 5 kam nie), eines mit Endlosschleife hat
ihn **dauerhaft aufgehängt**. Der Watchdog führt deshalb niemals Code aus dem
Candidate oder aus der geprüften Release aus. Er hasht deren Artefakte als Daten
und führt zur Schemaauswertung ausschließlich den zuvor mechanisch als
root-eigen, Single-Link und nicht fremdbeschreibbar geprüften Anchor aus. Fehlt
diese unabhängige Autorität oder weicht die installierte Schemakopie ab, lautet
das Ergebnis `integrity_indeterminate`, nicht `healthy`.

### Was der Watchdog beweist — und was nicht

Bewiesen bei `valid=true`: Manifest vorhanden, parsebar, `complete`;
Contract-Snapshot-Hash stimmt; eingebetteter Contract == Snapshot; **jedes
installierte Modul** und **jedes Runtime-Asset** hasht auf seinen Manifest-Eintrag;
der unabhängige Root-Anchor ist mechanisch verifiziert, die installierte
Schemakopie ist bytegleich dazu und das Manifest besteht diese Schema-Prüfung.
Ohne diese Schemaautorität gibt es keinen positiven Integritätsentscheid.

Nicht bewiesen: Python-/Executable-Bindung, Plattform-, Protokoll- und
Agent-Instruction-Identität, Release-Pfad- und Pointer-Prüfungen. Deshalb heißt
das Feld `scope` und trägt den Schemastatus mit; `valid` ist **kein**
`provenance_valid`.

### Bewusste Grenzen

* Die Lane verweigert, wenn die Runtime **nicht** integritätsungültig ist. Sie
  kann also nie benutzt werden, um aktuell geltende Gates zu umgehen.
* Sie schaltet keine Shell-, Kommando- oder Power-Worker-Autorität frei. Ihre
  einzige Wirkung ist ein Deployment des benannten Commits.
* Nach erfolgreicher Reparatur gelten wieder unverändert die normalen Gates;
  nichts an der Lane ist persistent.
* Typisierte Operator-Blockaden gelten weiterhin: die Lane ist eine begrenzte
  Ausnahme vom Integritätsgate, kein Loch im Blockade-System.

### TOCTOU-Bindung

Zwischen Gate-Auswertung und Deployment kann sich der Worktree ändern. Das ist
gebunden, nicht ignoriert:

* Das Deployment liest seine Inhalte über `git show <expected_head>:<pfad>`,
  nicht aus dem Worktree — der gebaute Artefaktinhalt ist revisionsgebunden.
* `snapshot_from_git` verlangt zusätzlich einen sauberen Worktree und bricht
  sonst ab.
* Der Job wird mit `finalization_expected_head=expected_head` gestartet.

Ein nachträglich veränderter Worktree kann das Ergebnis daher nicht
verfälschen; er kann den Deploy nur scheitern lassen.

### Was die Lane nicht belegt

* dass der Ziel-Commit funktional korrekt ist;
* dass normale Mutationsautorität vor einer erfolgreichen Reparatur
  wiederhergestellt ist;
* Server-Recovery-Frische — das bleibt ein eigenes, unabhängiges Gate für
  Power-Worker- und Privileged-Aktionen.

## Readback

Nach dem Job:

```
grabowski_deployment_identity
```

erwartet: `manifest_schema_valid`, `entrypoint_contract_identity_valid`,
`artifact_integrity_valid`, `provenance_valid` alle `true`.

## Watchdog

`tools/watchdog_runtime.py` unterscheidet seit dieser Arbeit explizit zwischen
positivem Integritätsentscheid, nachgewiesener Integritätsverletzung
(`integrity_invalid`, Exit 5) und fehlender unabhängiger Urteilsfähigkeit
(`integrity_indeterminate`, Exit 6). Der dritte Zustand entsteht insbesondere
bei fehlendem/unsicherem Root-Anchor oder Schemaabweichung und wird **niemals**
als `healthy` projiziert. Der Watchdog startet bei Schema-/Manifestproblemen
bewusst nicht neu — ein Neustart repariert weder einen fehlerhaften Contract
noch eine fehlende Vertrauenswurzel.

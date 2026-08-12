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

Alle Gate-Bedingungen (fail-closed, alle müssen erfüllt sein):

| Check | Bedeutung |
| --- | --- |
| `repair_warranted` | Runtime ist tatsächlich integritätsungültig |
| `audit_chain_valid` | Audit-Chain gültig |
| `audit_writable` | Audit-Chain beschreibbar |
| `kill_switch_clear` | Kill-Switch frei |
| `no_blocking_operator_blockade` | keine typisierte Operator-Blockade |
| `local_backup_fresh` | frische Backup-/Restore-Evidence |
| `privileged_broker_ready` | Privileged Broker vollständig gesund |
| `source_identity_bound` | Quelle sauber, `HEAD == origin/main == expected_head` |
| `target_contract_valid` | Ziel-Contract gültig unter dem kanonischen Schema **des Ziel-Commits** |
| `target_deploys_canonical_validator` | Ziel deployt sein eigenes Validierungsschema |
| `no_competing_deployment` | Deploy-Lock frei, kein laufender Deploy-Job |

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

`tools/watchdog_runtime.py` unterscheidet seit dieser Arbeit drei Zustände statt
zwei: Prozess/Transport lebt, Runtime ist operativ integritätsgültig, und
Runtime lebt aber ist integritätsungültig (`integrity_invalid`, Exit 5,
maschinenlesbarer `integrity.reason`). Der Watchdog startet in diesem Zustand
bewusst **nicht** neu — ein Neustart repariert kein fehlerhaftes Manifest — und
verweist stattdessen auf diese Lane.

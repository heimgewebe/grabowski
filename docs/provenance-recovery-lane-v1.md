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

### Akzeptiertes Risiko: `exec` des Ziel-Validators

`_target_contract_evidence` kompiliert und führt
`src/grabowski_runtime_contract.py` **aus dem Ziel-Commit** im aktuellen
Operator-Prozess aus. Das ist notwendig, damit ein Commit nach den Regeln
seiner eigenen Epoche beurteilt wird.

Warum das keine neue Vertrauensgrenze eröffnet:

* Der Ziel-Commit muss `origin/main` sein und wird unmittelbar danach ohnehin
  vollständig deployt und als Runtime ausgeführt.
* Der Code, der hier läuft, ist also exakt der Code, der gleich mit voller
  Autorität läuft.

Was trotzdem gilt:

* Der Namespace ist minimal (`{"__name__": ...}`), aber **keine** Sandbox —
  das Modul braucht `import`, also echte Builtins.
* Jede Exception aus `exec` wird generisch gefangen und in
  `contract_valid=false` übersetzt; ein fehlerhafter Ziel-Commit lässt die
  Diagnose fail-closed werden, statt den Prozess zu töten.

Eine stärkere Isolation (Subprozess mit Zeit- und Ressourcenlimit) wäre möglich
und ist als Folgetask registriert.

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

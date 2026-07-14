# Agent Workspace: Live-Audit vom 14. Juli 2026

## Urteil

Der Agent Workspace funktioniert technisch und erzwingt echte Isolation, Scope-Bindung, getrennte Writer-, Test- und Review-Rollen sowie hashgebundene Receipts. Er ist sinnvoll für begrenzte, nichttriviale Repository-Änderungen mit erhöhtem Risiko. Für kleine, deterministische Aufgaben ist der Direktweg schneller und angemessener.

Der Workspace ist kein allgemeiner Standardweg und kein autonom lernendes System. Der Optimierer liest mehrere abgeschlossene Workspace-Berichte, erkennt wiederkehrende Fehlerklassen und erzeugt ausschließlich unverbindliche Vorschläge. Er darf weder Code noch Policy oder Bureau-Zustand selbst ändern.

## Belegte Live-Evidenz

- Grabowski-Runtime und Manifest waren beim Audit gesund und integritätsgeprüft.
- Ein historischer T056-Workspace durchlief Writer, Tests, Review, Collection und Close erfolgreich; die Workspace-Leases wurden freigegeben.
- Andere reale Läufe endeten nach Create-Fehlern, Toolchain-Preflight, Timeout oder bewusstem Abbruch. Die Nutzung ist daher real, aber nicht gleichmäßig erfolgreich.
- Ein Optimizer-Lauf über 15 unabhängige Workspaces erkannte wiederkehrende Klassen wie `review:invalid_receipt`, `tests:preflight_probe_error` und `toolchain_probe_error`.
- Die Optimizer-Antwort setzte `execution_authorized`, `automatic_code_change`, `automatic_policy_change` und `automatic_bureau_change` jeweils auf `false`.
- Die erwarteten zentralen Dateien `workspace-metrics.jsonl` und `workspace-optimizer-state.json` waren im aktuellen Runtime-State nicht vorhanden. Eine belastbare globale Nutzungsquote lässt sich deshalb nicht aus einem kanonischen Aggregat ablesen.

## A/B-Test

### Mit Workspace

Aufgabe: Die Fehlerklassifikation des Workspace-Observers so ändern, dass eine spezifische Rollenklassifikation wie `review:invalid_receipt` nicht zusätzlich als unspezifisches `role_finished:failed` gezählt wird. Der generische Fallback bleibt erhalten, wenn keine spezifische Klassifikation vorliegt.

Ergebnis:

- Writer änderte exakt zwei erlaubte Dateien.
- Keine Scope-Verletzung und kein Base-Drift.
- Gebundener Funktionstest bestanden.
- Unabhängiges, read-only Review: `PASS`, keine Findings.
- Collection und Close erfolgreich; Leases freigegeben.
- Frozen identities:
  - Base/Writer-Head: `4a7a30ec40b65318fce6ff8280326ab9677c3a83`
  - Diff-SHA-256: `2986810c1943dce7bcb1a6c36c84feab03490b98ead7b06fb2090a71e3e65085`
  - Result-SHA-256: `cb49142a9f36a09b4644b11dc09dc988714c3b0d8e541c3e6f445fc767360d32`
  - Close-Receipt: `d96ec019b81fa3767c72aedfe5676562e8bb12c03c06fb05a2fd5590ac4e4434`
- Gemessener Workspace-Aufwand: 179 Sekunden und sechs bekannte mutierende Workspace-Aufrufe.

Aufgedeckter Defekt: Die Rollen-Sandbox konnte weder die Repo-venv, `~/.local/bin/pytest` noch die von Grabowski selbst verwendete deployte Python-venv als Test-Executable auflösen. Der erfolgreiche Workspace-Test musste deshalb als standardbibliotheksbasierter, dependency-freier AST-Funktionstest formuliert werden. Außerhalb der Rollen-Sandbox bestand anschließend die vollständige Observer-Testdatei mit 11 Tests.

### Ohne Workspace

Aufgabe: Diesen Auditbericht in einem eigenen, sauberen Worktree erstellen und deterministisch prüfen.

Routing-Empfehlung: `direct_operator`, Score 2; eine isolierte Vier-Rollen-Orchestrierung wäre für eine einzelne Dokumentationsdatei unverhältnismäßig.

Der Direktweg bewahrt weiterhin Git-Isolation durch einen eigenen Worktree, verzichtet aber auf Writer-/Test-/Review-Receipts und Workspace-Leases. Seine Aussagekraft ist daher geringer, sein Ausführungsaufwand für diese kleine Aufgabe jedoch deutlich niedriger.

## Nutzen und Grenzen

### Nutzen

- verhindert unbeabsichtigte Änderungen außerhalb erlaubter Pfade;
- bindet Tests und Review an denselben eingefrorenen Head und Diff;
- trennt Mutation, Validierung und Review technisch;
- bewahrt Patches und Worktrees bei Fehlern statt Änderungen zu verwerfen;
- veröffentlicht nachvollziehbare Ereignis- und Outcome-Receipts.

### Grenzen

- Toolchain-Bindung ist für normale Python-Projekttests derzeit unzureichend;
- Workspace-Abschluss beweist weder PR-Integration noch Bureau-Abgleich, Worktree-Bereinigung oder Operator-Zusammenfassung;
- historische Nutzung ist ohne kanonisches Aggregat nur durch Einzelscans messbar;
- der Optimierer erzeugt Vorschläge, führt sie aber absichtlich nicht selbst aus;
- für kleine Aufgaben ist der Orchestrierungsaufwand größer als der Nutzen.

## Entscheidung

Workspace beibehalten und selektiv nutzen. Gilt, wenn eine Aufgabe mehrere Dateien, erhöhte Laufzeit, Sicherheits- oder Runtime-Risiko, parallele Arbeit oder einen echten Nutzen aus getrennten Rollen hat. Kleine Dokumentations-, Metadaten- und deterministische Ein-Datei-Aufgaben sollen direkt in einem isolierten Worktree ausgeführt werden.

Vor einer breiteren Standardnutzung müssen mindestens die Rollen-Toolchain-Bindung, ein kanonisches Nutzungsaggregat und die externe Closeout-Reconciliation verbessert werden.

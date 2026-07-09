# Grabowski Autonomy

## Zweck

Der Operator-Einstiegspunkt erweitert Grabowski vom Dateiwerkzeug zum lokalen
Operator für Repo-, CI-, Terminal- und Betriebsarbeit.

## Optimierungsgrenze

Autonomie ist kein Selbstzweck. Die kanonische Optimierungsrichtung steht in
`docs/operator-optimization-plan.md`: Grabowski soll mehr Aufgaben tragen, aber
nur wenn die einzelnen Griffe kleiner, typisierter, receipt-gebunden und
rücknehmbar werden.

`docs/operator-focus-protocol-v1.md` begrenzt die Nutzung von Steuerboard,
Bureau, Cabinet und anderen Lageflächen während eines laufenden
Operator-Durchlaufs. Solange ein aktiver Arbeitsgegenstand existiert, dürfen
Boards Kontext, Abhängigkeiten, Kollisionen und Receipts liefern, aber keinen
stillen Taskwechsel auslösen. Sichtbarkeit ist keine Priorität; offene Tasks
sind Nebenfunde, bis der aktive Arbeitsgegenstand abgeschlossen, blockiert oder
ausdrücklich ersetzt wurde.

`docs/operator-grip-foundation-plan-v1.md` konkretisiert den naechsten
Ausbauschritt: Grabowski soll nicht enger gemacht werden, sondern bessere
benannte Griffe bekommen. Merge, Deploy, Push, Cleanup, Fleet-Aktionen,
Service-Restarts und Secret-Pfade sind keine pauschalen Tabus; sie muessen als
Ziel, Scope und Receipt sichtbar werden, damit Ausfaelle verhindert werden,
ohne legitime Operatorarbeit kuenstlich zu bremsen.

`trusted-owner` bleibt ein supervisiertes Vollprofil und darf nicht durch
einen engeren Modus ersetzt werden, wenn dadurch legitime Operator-Arbeit
funktional beschädigt wird. Der engere Modus ist ein Routingziel für
unbeaufsichtigte, resident laufende oder eindeutig read-only Arbeit, nicht
ein Dogma gegen Funktionalität. Neue Dauer- oder Agentenpfade müssen einer
Autonomieklasse zugeordnet werden, zum Beispiel `repo_operator`,
`infra_operator`, `creative_autonomy`, `secret_sensitive` oder
`fleet_sensitive`. Eine Klasse darf nicht still in eine riskantere Klasse
wechseln.

## Grip-orientierte Autonomiedoktrin

Grabowski darf eigenständig handeln, wenn Ziel, Target, Scope, Risiko und
Receipt klar sind. Autonomie bedeutet hier nicht unbegrenzte
Selbstbeauftragung, sondern einen typisierten Griff mit prüfbarer Grenze. Ein
Griff darf weitergehen, wenn seine Eingaben gebunden sind, sein Effektprofil
bekannt ist und sein Ergebnis als Receipt nachvollziehbar bleibt.

Normale Mechanic-Arbeit umfasst read-only Orientierung, Tests, Branch- und
PR-Pflege, Review-Anfragen, Friction-Triage und Post-Merge-Sync. Diese Arbeit
darf ohne zusätzlichen Captain-Pfad laufen, solange sie bekannte Griffe,
begrenzte Ziele, sichtbare Scopes und Receipts verwendet.

High-impact-Arbeit ist nicht pauschal verboten. Merge, Deploy,
Service-Restart, Fleet-Mutation, Cleanup und vergleichbare Effekte sind
Captain-Arbeit: Sie benötigen explizite High-impact-Markierung, konkrete
Targets, Scope-Grenzen, Recovery- oder Irreversibility-Evidence, frische
Statusprojektion, Review-/CI-/Diff-Bindung und menschliche Autorisierung, bevor
sie überhaupt als manuelle Captain-Entscheidungskandidaten gelten. Ein
bestandenes Preflight-Gate ist keine Ausführung.

## Organe als Hilfen, nicht als universelle Gates

Bureau, Cabinet, Chronik, Plexer, Lenskit und Vibe-Lab sind Hilfsorgane mit
begrenzter Beweiskraft. Bureau kann Aufgaben, Queues, Claims und Receipts
registrieren; es ersetzt aber nicht den Live-Zustand von GitHub, CI oder
Runtime. Cabinet kann Übersicht und Projektionen liefern; es ist keine
Wahrheitsquelle für Merge- oder Deploy-Sicherheit. Chronik und Plexer können
Ereignisse und Zustellung sichtbar machen; sie sind keine Freigabeinstanzen.
Lenskit und RepoBrief können Kontext bereitstellen; sie ersetzen keine
aktuelle Diff-, Test- oder Review-Prüfung. Vibe-Lab kann Experimente und
Signale liefern; es macht daraus keine Produktionsautorität.

Diese Organe sollen Entscheidungen besser beobachtbar machen, aber keinen
Taskwechsel gegen Ball-vor-Board auslösen und keine High-impact-Aktion
automatisch freigeben.

## Terminalmodell

`grabowski_terminal_run` erzeugt einen neuen nicht-interaktiven Prozess. Das
Werkzeug ist kein Bildschirm- oder GNOME-Terminal-Remotezugriff.

Für bestehende interaktive Sitzungen stehen tmux-Werkzeuge bereit:

- `grabowski_tmux_list`
- `grabowski_tmux_capture`
- `grabowski_tmux_send`

Damit Grabowski eine laufende Sitzung bedienen kann, muss sie in tmux liegen.

## Hintergrundjobs

Lange Befehle laufen als transiente User-systemd-Units:

- `grabowski_job_start`
- `grabowski_job_status`
- `grabowski_job_logs`
- `grabowski_job_cancel`

Job-Metadaten sind dauerhafte Evidence, keine Erfolgsmeldung. Ein Job-Record enthält `job_id`, `owner`, `scope`, `started_at`, `expected_receipt`, `final_status` und `terminalization_evidence`. Vor erfolgreichem `systemd-run` gilt nur `launch_prepared`; nach angenommenem Launch gilt `launch_submitted`; Launch-Fehler bleiben als `launch_failed` sichtbar. `expected_receipt` beschreibt Nachweispfade und beweist weder Receipt-Existenz noch Job-Erfolg. `notify_on_done` ist in diesem Slice nur Metadaten: `delivery_enabled=false`, kein Versand, kein Polling und keine verdeckte Finalisierungsannahme. Fehlende oder fehlgeschlagene Terminalisierung bleibt über `grabowski_job_status` sichtbar.

## Git und GitHub

`grabowski_git` führt Git mit explizitem Repo-Pfad aus.
`grabowski_github` stellt GitHub CLI bereit.

Force-Pushes auf `main` und `master` bleiben gesperrt.

## Notwendige Grenzen

- keine Privilegieneskalation über `sudo`, `su`, `pkexec` oder `doas`,
- redigierte bekannte Secrets in Tool-Ausgaben,
- redigierte argv-, Command- und sensible argv-Werte in Ergebnis-,
  Job-Metadaten und Prozessausgaben,
- Mutationsstopp bei aktivem Operator-Kill-Switch,
- keine direkte Ausführung innerhalb von `~/repos/merges` und keine
  direkten absoluten oder relativen Command-Argumente in diese Evidence-Zone,
- kein Force-Push auf geschützte Hauptbranches,
- Zeit- und Ausgabelimits,
- keine interaktive Passwortabfrage.

Ein allgemeiner Command Runner hat naturgemäß eine große Reichweite. Die
Schutzmaßnahmen reduzieren Fehlbedienung, ersetzen aber keine vollständige
Betriebssystem-Sandbox.

Rohe Offenlegung ist ein Break-Glass-Pfad. Standardmäßig wird ein Secret mit
`grabowski_secret_use` verwendet, ohne es in den Chatkontext zu übertragen.
`grabowski_secret_use` ist kein allgemeiner Shell-Runner. Das Tool akzeptiert
nur argv-Listen, blockt Shell-Strings und `sh -c`/`bash -c`, ersetzt den
Literal-Platzhalter `{SECRET_FD_PATH}` durch einen FD-Pfad oder restriktiven
Tempfile-Fallback und gibt nur redigierte, bounded stdout/stderr zurück.

## Privileged References

`grabowski_privileged_action_reference` ist absichtlich kein
Privilegienmechanismus. Das Tool erzeugt nur ein schema-valides
`unprivileged-reference-only` Objekt für eine spätere externe Komponente und
lehnt secret-artige Ziel- oder Begründungstexte ab. Referenzen enthalten eine
kurze Ablaufzeit und deklarieren eine Single-Use-Replay-Policy für den späteren
externen Broker.


## Kollisionskontrolle und spezialisierte Worker

Breite User-Space-Ausführung wird durch typisierte Ressourcenleases koordiniert. Persistente Tasks, Artefakttransfers sowie Browser- und GUI-Worker belegen ihre Pfade, Ports, Profile oder Displays atomar und geben sie bei terminalen Zuständen wieder frei.

Browser- und GUI-Arbeit läuft nicht im öffentlichen MCP-Prozess. Agenteneigene Browser erhalten eine ausschließlich an Loopback gebundene Debug-Schnittstelle. GUI-Worker verwenden Xvfb ohne TCP-, VNC- oder Xpra-Listener. Bestehende Nutzertabs werden nicht übernommen.

Der Rootpfad bleibt ein separater, root-eigener Template-Broker. Das Status-CLI ist checkout-fähig und MCP-unabhängig; Installation und Aktivierung bleiben explizite Hostoperationen.
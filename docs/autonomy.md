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


### Session capability profiles

Access profiles attenuate a session beyond coarse capabilities. A profile declares `read_roots`, `write_roots`, `allowed_grips`, `forbidden_hosts` and `max_risk_level`. `grip_run` checks the active session profile before dispatch: low-risk read-only grips can be allowed while medium mutating grips or high-risk Captain grips remain blocked. High-risk grip execution additionally requires `session_escalation` with target, reason, expiry and recovery or irreversibility metadata. Operator argv validation rejects configured `forbidden_hosts` in command targets before execution. These checks do not establish host reachability, action safety or successful execution; they are preconditions.
For `pr-merge`, Captain also reads the repository's current GitHub merge policy before mutation. It selects the first allowed method in the deterministic order `merge`, `squash`, `rebase`, binds the selected flag to the execution receipt and blocks if the policy query is missing, malformed or disables every method. This policy read is a precondition; post-merge target verification remains mandatory.

## Git und GitHub

`grabowski_git` führt Git mit explizitem Repo-Pfad und bereinigter Git-Umgebung aus. Sein generischer Push-Pfad akzeptiert nur einen benannten SSH-Remote und genau ein explizites RefSpec der Form `QUELLE:refs/heads/ARBEITSBRANCH`. Ziele auf `main` oder `master`, implizite oder mehrere Ziele, Tags, Wildcards, Löschungen, alle Force-Varianten, Aggregate, semantikändernde Push-Optionen, Push-Konfiguration und direkte Remote-Write-Unterbefehle werden fail-closed blockiert. Vor der Ausführung werden Hooks, Signaturprogramme, alternative Transporthelfer, SSH-Benutzerkonfiguration, lokale oder erweiterbare Protokolle sowie semantikändernde Push-Konfiguration neutralisiert. Für normale Veröffentlichungen bleibt der typisierte Grip `branch-publish` der vorgesehene Weg; auch dort sind `main` und `master` unveränderlich geschützt, Remote-Namen validiert und dieselben Ausführungshelfer deaktiviert. Diese Grenze gilt auch im Trusted-Owner-Modus.

`grabowski_github` stellt GitHub CLI bereit.

Der lokale Guard ist Defense-in-Depth und ersetzt keine serverseitige Branch-Regel. Der enge generische Vertrag reduziert lokale Fehlbedienung; die Remote-Regel bleibt für konkurrierende Clients und serverseitige Autorisierung maßgeblich.

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

`grabowski_power_run` ist die maximale Operator-Schiene. Standard ist
autonome Ausführung, Grenze ist nicht Zustimmung, sondern Auditierbarkeit,
Recovery und Kill-Switch. Das Tool führt kein lokales `sudo` im MCP-Prozess aus,
sondern sendet eine kurzlebige `operator_power_argv`-Referenz an den
root-eigenen Broker. Vor jedem Aufruf müssen Audit-Chain, Kill-Switch,
Broker-Status und Recovery-Gate grün sein. Der Befehl ist argv-basiert,
verlangt ein absolutes Executable, bounded Timeout, bounded Output und eine
nichtleere Begründung; der Broker auditiert Ziel-, cwd- und argv-Hashes. Die
root-eigene Konfiguration erzwingt zusätzlich eine Broker-seitige Gate-Prüfung
und entscheidet, ob direkte bekannte Shell-Executables erlaubt sind.
`allowed_argv_prefixes` kann diese Schiene in einen expliziten Admin-Katalog
verwandeln; ohne diese Liste bleibt sie generisch. Für maximale trusted-owner-
Funktionalität darf dieser Katalog bewusst breit sein. Er ist aber nur eine
Prefix-Bremse, keine vollständige Argument- oder Zielvalidierung. Die eigentliche
Grenze bleibt Recovery-Gate, Kill-Switch, Timeout, Audit und Broker-Ausführung.
Ein aktiviertes `operator_power_argv` bedeutet bewusst beliebige Root-Ausführung
über absolute argv.


## Kollisionskontrolle und spezialisierte Worker

Breite User-Space-Ausführung wird durch typisierte Ressourcenleases koordiniert. Persistente Tasks, Artefakttransfers sowie Browser- und GUI-Worker belegen ihre Pfade, Ports, Profile oder Displays atomar und geben sie bei terminalen Zuständen wieder frei.

Browser- und GUI-Arbeit läuft nicht im öffentlichen MCP-Prozess. Agenteneigene Browser erhalten eine ausschließlich an Loopback gebundene Debug-Schnittstelle. GUI-Worker verwenden Xvfb ohne TCP-, VNC- oder Xpra-Listener. Bestehende Nutzertabs werden nicht übernommen.

Der Rootpfad bleibt ein separater, root-eigener Template-Broker. Das Status-CLI ist checkout-fähig und MCP-unabhängig; Installation und Aktivierung bleiben explizite Hostoperationen.
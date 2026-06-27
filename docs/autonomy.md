# Grabowski Autonomy

## Zweck

Der Operator-Einstiegspunkt erweitert Grabowski vom Dateiwerkzeug zum lokalen
Operator für Repo-, CI-, Terminal- und Betriebsarbeit.

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

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
- keine direkte Ausführung innerhalb von `~/repos/merges`,
- kein Force-Push auf geschützte Hauptbranches,
- Zeit- und Ausgabelimits,
- keine interaktive Passwortabfrage.

Ein allgemeiner Command Runner hat naturgemäß eine große Reichweite. Die
Schutzmaßnahmen reduzieren Fehlbedienung, ersetzen aber keine vollständige
Betriebssystem-Sandbox.

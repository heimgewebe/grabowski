# Grabowski Autonomy

## Zweck

Der Operator-Einstiegspunkt erweitert Grabowski vom Dateiwerkzeug zum lokalen
Operator für Repo-, CI-, Terminal- und Betriebsarbeit. Zwei Betriebsarten
bleiben unterscheidbar:

- normale Profile behalten enge Schutzgrenzen,
- `trusted_owner=true` behandelt den lokalen Benutzer als entscheidungsbefugten
  Eigentümer des Rechners und öffnet einen vollständigen Escape Hatch.

## Trusted-Owner-Modell

Im Trusted-Owner-Profil darf `grabowski_terminal_run` beliebige argv-Prozesse
starten. Dazu gehören Shells, Privilegien-Frontends, Docker, Systemwerkzeuge und
Kommandos innerhalb zuvor geschützter Arbeitsbereiche. Die Operator-Unit ist in
diesem Profil nicht durch `ProtectSystem`, `ProtectHome`, `PrivateTmp`,
`MemoryDenyWriteExecute` oder `ReadWritePaths` eingeschränkt.

Der Modus erweitert außerdem die technischen Budgets:

- synchrone Kommandos bis 24 Stunden,
- Hintergrundjobs bis 30 Tage,
- Tool-Ausgaben bis 32 MiB,
- vollständige Vererbung des Operator-Environments,
- keine Evidence- oder Hauptbranch-Sonderblockade im Command-Runner.

Die spezialisierten Werkzeuge bleiben erhalten, weil sie bessere strukturierte
Ergebnisse, Hash-Vorbedingungen, Backups und Rollback-Belege liefern. Sie sind
Komfort- und Reparaturpfade, keine unüberwindbaren Verbote. Wenn ein Spezialtool
zu eng ist, wird der Terminal-Runner verwendet.

## Terminalmodell

`grabowski_terminal_run` erzeugt einen neuen nicht-interaktiven Prozess. Shell-
Expansion ist möglich, indem eine Shell explizit als argv gestartet wird. Für
bestehende interaktive Sitzungen stehen tmux-Werkzeuge bereit:

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

Diese Jobs sind vom Operator-Prozess entkoppelt und eignen sich deshalb auch für
Deployments, Reparaturen und Neustarts des Operators selbst.

## Git und GitHub

`grabowski_git` führt Git mit explizitem Repo-Pfad aus.
`grabowski_github` stellt GitHub CLI bereit. In normalen Profilen bleiben
Force-Pushes auf Hauptbranches gesperrt. Das Trusted-Owner-Profil hebt diese
Sonderblockade auf; Git selbst und Remote-Branch-Policies bleiben maßgeblich.

## Secrets

Bekannte Secret-Muster werden weiterhin in Ausgaben und Metadaten redigiert.
Das ist Beobachtbarkeitshygiene, keine Zugriffsverweigerung. Im Trusted-Owner-
Profil dürfen allgemeine Datei- und Terminalpfade auch sensible Bereiche
ansprechen. `grabowski_secret_use` bleibt der bevorzugte Pfad, wenn ein Wert
verwendet, aber nicht in den Chatkontext übertragen werden soll.

`grabowski_secret_reveal` akzeptiert im Trusted-Owner-Profil die Owner-Policy als
implizite Expositionsfreigabe. Eine explizite Begründung bleibt möglich und wird
weiterhin nur gehasht auditiert.

## Root und Betriebssystemgrenze

Die entsandboxte User-Runtime kann alle Rechte des Benutzers verwenden,
einschließlich dessen Docker- und Gruppenrechten. Ein echter UID-0-Prozess
benötigt weiterhin einen Betriebssystemmechanismus: vorhandenes
Passwort-/Polkit-Approval oder den root-eigenen Grabowski-Broker.

Der Broker bleibt absichtlich ein separater Systemdienst. Diese Trennung schützt
nicht vor dem Eigentümer, sondern verhindert, dass ein kompromittierter
unprivilegierter Prozess sich selbst root-eigene Dateien installiert. Nach der
administrativen Installation können freigegebene Systemaktionen ohne Umbau der
MCP-App ausgeführt werden.

## Verbleibende Leitplanken

Auch im Trusted-Owner-Modus bleiben nur wenige systemische Sicherungen bestehen:

- manipulationssichtbares Audit,
- Ausgabe-Redaktion bekannter Geheimnisse,
- Prozessgruppen-Abbruch bei Zeitüberschreitung,
- Operator-Kill-Switch als Not-Aus,
- lokale Loopback-Bindung des MCP-Servers,
- Git, Dateisystem und Kernel erzwingen weiterhin ihre echten Berechtigungen.

Diese Leitplanken sollen Reparatur ermöglichen, nicht Entscheidungen ersetzen.
Ein Fallschirm ist keine Flugverbotszone; er ist nur nützlich, wenn man ihn
mitnimmt.

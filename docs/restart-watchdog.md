# Restart- und Watchdog-Härtung

## Problembeleg

Ein kontrollierter Live-Test am 25. Juni 2026 beendete ausschließlich den
Grabowski-Operator unterhalb des weiterlaufenden Tunnel-Clients. Acht Sekunden
lang blieb der Zustand unverändert:

```text
ActiveState=active
SubState=running
NRestarts=0
current_operator_pid=none
health_http=200 body=live
ready_http=200 body=ready
```

Damit belegen weder `systemd active` noch `/healthz` oder `/readyz` allein die
Arbeitsfähigkeit des MCP-Servers. `Restart=on-failure` schützt nur den
Tunnel-Hauptprozess; der Tunnel-Client bleibt nach dem Tod seines stdio-MCP-
Kindprozesses im degradierten Zustand aktiv.

## Architektur

Die Härtung trennt zwei Fehlerklassen:

1. `tunnel-client-grabowski.service` startet den Hauptprozess bei dessen Fehler
   über `Restart=on-failure` neu. `StartLimitIntervalSec=5min` und
   `StartLimitBurst=5` begrenzen Startschleifen.
2. `grabowski-watchdog.timer` startet alle 30 Sekunden einen semantischen
   One-shot-Check. Dieser verlangt gleichzeitig:
   - den aktiven und laufenden systemd-Dienst,
   - die exakte MainPID-Kommandozeile `tunnel-client run --profile grabowski`,
   - genau einen Nachfahren mit dem erwarteten stabilen Runtime-Pythonpfad und
     `python -m <erwartetes Modul>`,
   - `/healthz` mit exakt `200 live`,
   - `/readyz` mit exakt `200 ready`.

Der Wächter startet einen aktiven, aber degradierten Dienst erst nach drei
aufeinanderfolgenden Fehlmessungen neu. Maximal drei Watchdog-Neustarts in 15
Minuten sind erlaubt. Ein persistenter State unter
`~/.local/state/grabowski/watchdog-state.json` trägt Fehlerserie und
Restart-Budget über einzelne Timerläufe hinweg.

Ein inaktiver Dienst wird absichtlich nicht durch den semantischen Wächter
wiederbelebt. Dadurch bleibt ein manueller `systemctl --user stop` wirksam.
Der Tod des Hauptprozesses bleibt Aufgabe von `Restart=on-failure`.

## Komponenten-Watchdogs: Operator- und Tunnel-Härtung

Neben dem kombinierten Wächter (`tools/watchdog_runtime.py`) existieren zwei
getrennte Komponenten-Watchdogs auf Basis von `tools/component_watchdog.py`:
`grabowski-operator-watchdog` und `grabowski-tunnel-watchdog`. Jeder startet
ausschließlich seinen eigenen Dienst neu.

### Vollständiger read-only MCP-Lebenszyklus (Operator)

Der Operator-Watchdog kombiniert zwei voneinander unabhängige Belege:

1. Er prüft MainPID, Listener und Bindung an die erwartete deployte Runtime.
2. Gegen den **tatsächlich laufenden** Streamable-HTTP-Endpunkt erzeugt er eine
   ausschließlich für die Probe bestimmte Sitzung, führt `initialize`,
   `notifications/initialized` und `tools/call` mit exakt
   `grabowski_runtime_health` aus und beendet diese Sitzung mit `DELETE`.
3. Zusätzlich startet er aus derselben Runtime einen isolierten kurzlebigen
   stdio-Prozess und wiederholt dort denselben MCP-Toolaufruf. Damit bleiben
   Live-Listener und importierbarer Runtime-Stand getrennt beobachtbar.
4. Ein fachliches `healthy: false` bleibt `indeterminate` und löst keine
   Restart-Schleife aus. Timeout, ungültiges Protokoll, fehlende Sitzung oder
   nicht beendbare Probesitzung gelten dagegen als Live-Pfad-Fehler.

Der Live-Probe ist auf Loopback, zwei Sekunden je Anfrage, 64 KiB Antwort und
vier deterministische Requests begrenzt. Er nutzt keine fremde Sitzung und
löscht seine eigene Sitzung auch auf Fehlerpfaden bestmöglich.

Vor einem automatischen Operator-Neustart sendet der Watchdog `SIGUSR1` an die
MainPID. Der Operator registriert dafür `faulthandler` und schreibt begrenzte
Stacks aller Python-Threads in das User-Journal. Die Stackaufnahme ist nur
Diagnoseevidenz und darf einen notwendigen Neustart nicht blockieren.

Der HTTP-Sitzungsmanager beendet inaktive Sitzungen nach 1.800 Sekunden. Das
begrenzt verwaiste Zustände, ohne normale Connector-Sitzungen aggressiv zu
unterbrechen. Die vom Tunnel abgefragten Pfade
`/.well-known/oauth-protected-resource` und
`/.well-known/oauth-protected-resource/mcp` liefern deterministisches JSON für
den auth-freien Loopback-Betrieb statt einer nicht parsebaren 404-Antwort.

### Backoff mit Jitter und persistenter Sperrzeit

Failure-Threshold (2 aufeinanderfolgende Fehlmessungen) und Restart-Budget
(3 Neustarts pro 15 Minuten) bleiben unverändert fail-closed und werden vor
dem Backoff geprüft. Zusätzlich trägt der State einen begrenzten
exponentiellen Restart-Backoff:

- Nach jedem Watchdog-Neustart steigt `backoff_level`; die nominale
  Verzögerung ist `backoff_base * 2^(level-1)` (Standard 60 s Basis), darauf
  kommen bis zu 20 % Jitter aus einer injizierbaren, deterministisch testbaren
  Quelle. Das Endergebnis wird hart auf `backoff_max` begrenzt (Standard
  900 s); Jitter kann die Obergrenze nicht überschreiten.
- `next_restart_not_before` wird als absoluter Unix-Zeitstempel persistiert.
  Es gibt keine Schlafschleife: fällig ist der nächste Neustart erst, wenn ein
  späterer Timerlauf den Zeitpunkt überschritten hat; vorher endet der Lauf
  mit dem Ereignis `restart_deferred`.
- Ein gesunder Lauf setzt Fehlerserie und Backoff zurück;
  `restart_generation` bleibt als monotone lokale Watchdog-Neustartnummer
  erhalten. Sie ist ausdrücklich keine Tunnel-Verbindungs- oder
  MCP-Sitzungsgeneration.
- Alte State-Dateien ohne Backoff-Felder werden sicher gelesen (Felder
  defaulten zu 0); formwidrige Werte führen fail-closed zu
  `invalid-state-shape` ohne Neustart.

Backoff- und lokale Restart-Evidenz erscheint in den JSON-Ereignissen
`restarting`, `restart_deferred`, `recovered`, `restart_unhealthy`,
`restart_budget_exhausted` und `healthy` (`backoff_level`,
`next_restart_not_before`, `restart_generation`).

### Arbeitsteilung mit systemd 249

systemd 249 kennt kein `RestartSteps`; eskalierendes Restart-Pacing kann dort
nicht deklariert werden. Die Aufteilung ist deshalb:

- `Restart=on-failure` mit flachem `RestartSec=5` bleibt der schnelle
  Fallback ausschließlich für den Tod des Hauptprozesses. Die Unit trägt
  bewusst keine zweite, konkurrierende Backoff-Wahrheit.
- `StartLimitIntervalSec`/`StartLimitBurst` begrenzen Startschleifen; das
  Drop-in `80-restart-budget.conf` spiegelt exakt die Werte der versionierten
  Unit (eine Budget-Wahrheit).
- `RandomizedDelaySec=3s` in den Timern bleibt reine äußere Entkopplung der
  Timerläufe; der semantische Watchdog trägt den eigentlichen Backoff. Der
  leichte Tunnelcheck läuft alle 30 s, der begrenzte Live-HTTP- plus stdio-Operatorcheck
  alle 60 s, um unnötige Prozess- und Importlast zu halbieren.
- `SuccessExitStatus=1` wertet Routine-Evidenz (Fehlmessung, aufgeschobener
  Neustart) nicht als Unit-Fehler; Exit 2/3/4 (indeterminate, Budget
  erschöpft, Neustart ohne Genesung) bleiben sichtbare Fehler.
  `TimeoutStartSec=90` deckt den ungünstigsten Pfad Probe + Neustart +
  begrenzte Genesungsprüfung ab.

### Geltungsbereich und Grenzen

Die beiden Komponentenprüfungen liefern getrennte lokale Belege:
Der Tunnel-Watchdog prüft dessen `/healthz` und `/readyz`; der
Operator-Watchdog prüft Live-Prozess/Listener, den produktiven lokalen
HTTP-Sitzungspfad und einen isolierten stdio-Pfad aus derselben deployten
Runtime. Nicht belegt bleiben der vollständige Roundtrip durch die OpenAI-
Control-Plane und die korrekte Zuordnung einer konkreten ChatGPT-Sitzung.

Connection-Generation, das Verwerfen veralteter Antworten und die
Neuerkennung des Tool-Katalogs durch den Client liegen außerhalb dieses
Repositories. Der Probe selbst führt keine Zielmutation aus. Der produktive
Watchdog besitzt als eng begrenzte Eingriffsautorität ausschließlich
`systemctl --user restart` für genau seine eigene Komponente.

### Installation der Komponenten-Watchdogs

```bash
install -m 0700 \
  tools/component_watchdog.py \
  "$HOME/.local/libexec/grabowski/component_watchdog.py"

install -m 0600 \
  systemd/grabowski-operator-watchdog.service.example \
  "$HOME/.config/systemd/user/grabowski-operator-watchdog.service"
install -m 0600 \
  systemd/grabowski-operator-watchdog.timer.example \
  "$HOME/.config/systemd/user/grabowski-operator-watchdog.timer"
install -m 0600 \
  systemd/grabowski-tunnel-watchdog.service.example \
  "$HOME/.config/systemd/user/grabowski-tunnel-watchdog.service"
install -m 0600 \
  systemd/grabowski-tunnel-watchdog.timer.example \
  "$HOME/.config/systemd/user/grabowski-tunnel-watchdog.timer"

systemctl --user daemon-reload
systemctl --user enable --now \
  grabowski-operator-watchdog.timer grabowski-tunnel-watchdog.timer
```

Die State-Dateien liegen unter
`~/.local/state/grabowski/<component>-watchdog-state.json` und enthalten nur
Zähler und Unix-Zeitstempel.

## Deployment-Koordination

Der Wächter hält während Prüfung und möglichem Neustart einen Shared-Lock auf
`~/.local/state/grabowski/deploy.lock`. Das Deployment benötigt denselben Lock
exklusiv. Ein laufendes Deployment führt deshalb zu einem übersprungenen
Watchdog-Lauf; umgekehrt beginnt kein Deployment mitten in einer Watchdog-
Entscheidung.

## Installation

Die versionierte Watchdog-Datei wird getrennt vom Git-Arbeitsbaum in einen
stabilen lokalen Pfad installiert:

```bash
install -d -m 0700 \
  "$HOME/.local/libexec/grabowski" \
  "$HOME/.local/state/grabowski" \
  "$HOME/.config/systemd/user" \
  "$HOME/.config/systemd/user/tunnel-client-grabowski.service.d"

install -m 0700 \
  tools/watchdog_runtime.py \
  "$HOME/.local/libexec/grabowski/watchdog_runtime.py"

install -m 0600 \
  systemd/grabowski-watchdog.service.example \
  "$HOME/.config/systemd/user/grabowski-watchdog.service"
install -m 0600 \
  systemd/grabowski-watchdog.timer.example \
  "$HOME/.config/systemd/user/grabowski-watchdog.timer"
install -m 0600 \
  systemd/tunnel-client-grabowski.service.d/80-restart-budget.conf.example \
  "$HOME/.config/systemd/user/tunnel-client-grabowski.service.d/80-restart-budget.conf"
```

Der aktuelle Operator-Slice verwendet `grabowski_operator`. Bei einer späteren
Migration des Tunnelprofils auf `grabowski_mcp` wird nur die lokale Konfiguration
angepasst:

```bash
install -d -m 0700 "$HOME/.config/grabowski"
printf '%s\n' \
  'GRABOWSKI_WATCHDOG_EXPECTED_MODULE=grabowski_operator' \
  >"$HOME/.config/grabowski/watchdog.env"
chmod 0600 "$HOME/.config/grabowski/watchdog.env"
```

Danach:

```bash
systemctl --user daemon-reload
systemctl --user enable --now grabowski-watchdog.timer
systemctl --user start grabowski-watchdog.service
```

## Validierung

```bash
systemctl --user status grabowski-watchdog.timer --no-pager --full
systemctl --user list-timers grabowski-watchdog.timer --no-pager
journalctl --user -u grabowski-watchdog.service -n 50 --no-pager

python3 tools/watchdog_runtime.py \
  --check-only \
  --expected-module grabowski_operator
```

Ein gesunder Lauf erzeugt ein einzelnes JSON-Ereignis
`grabowski.watchdog.healthy`. Ein fehlender Operator ist auch bei grünen HTTP-
Endpunkten `unhealthy`.

Der produktive Restart-Integrationstest am 25. Juni 2026 bestätigte den
damaligen lokalen Wiederanlaufvertrag: Nach dem gezielten Tod des Operators
meldeten zwei Timerläufe `failure-observed`; der dritte Lauf startete den
Dienst neu. Nach 85 Sekunden liefen eine neue Tunnel-MainPID und eine neue
Operator-PID. Das war kein Beleg für einen ChatGPT-Control-Plane-Roundtrip.

## Wartung und Rollback

Vor bewusster manueller Degradation wird der Timer gestoppt:

```bash
systemctl --user stop grabowski-watchdog.timer
```

Vollständiger Rollback:

```bash
systemctl --user disable --now grabowski-watchdog.timer
rm -f "$HOME/.config/systemd/user/grabowski-watchdog.timer"
rm -f "$HOME/.config/systemd/user/grabowski-watchdog.service"
rm -f "$HOME/.config/systemd/user/tunnel-client-grabowski.service.d/80-restart-budget.conf"
rm -f "$HOME/.config/systemd/user/tunnel-client-grabowski.service.d/override.conf"
systemctl --user daemon-reload
```

Die State-Datei kann zur Diagnose erhalten bleiben. Sie enthält nur Zähler und
Unix-Zeitstempel, keine Zugangsdaten.

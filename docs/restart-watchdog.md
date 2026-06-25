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

Der produktive End-to-End-Test am 25. Juni 2026 bestätigte die gesamte Kette:
Nach dem gezielten Tod des Operators meldeten zwei Timerläufe
`failure-observed`; der dritte Lauf startete den Dienst neu. Nach 85 Sekunden
liefen eine neue Tunnel-MainPID und eine neue Operator-PID. Der unabhängige
Fallback-Restart wurde nicht benötigt.

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

# Serving-Process-Identität

## Befund

`grabowski_deployment_identity` liest die Release-Identität aus dem
Plattenmanifest. Der MCP-Serverprozess, der einen Aufruf tatsächlich bedient,
behält jedoch den Code, den er beim Start importiert hat. Beides driftet ohne
jedes anzeigende Feld auseinander.

Live belegt am 2026-08-04 nach dem Deploy auf
`f18ea82f959ed097fb9c6bdc07502597d0ee85b2`:

- Runtime-Identität meldete `repo_head=f18ea82…`.
- Die live abgefragte Grip-Allowlist hatte 29 statt 31 Einträge; es fehlten
  `transport-roundtrip` und `runtime-refresh-lease-release`.
- venv-Modul und deployte Quelle waren byteidentisch
  (`sha256 4bce83ca2b1f902f3b9b5362c732db853cf21babe2186932b705dd7f8bd02397`).
- Der Unterschied lag allein im Speicher des bedienenden Prozesses, der am
  2026-08-02 gestartet war.
- `grip_run(transport-roundtrip, begin)` schlug im Preflight fehl:
  `grip is not exposed by surface allowlist`.

## Zwei gegenläufige Fehlklassen

Erstens meldete `source_identity_by_module` für ein Modul `true`, dessen Code im
bedienenden Prozess nachweislich älter war. Die Identitätsprojektion belegt
Plattenzustand, nicht Vollzug.

Zweitens hing die Durchsetzung einer fail-closed-Grenze am Startzeitpunkt der
Sitzung statt am deployten Stand: Sitzungen auf Prozessen vor dem Gate-Commit
`c4714a13` umgingen das Transport-Gate vollständig, während Sitzungen danach es
nutzen konnten. Konkret war `grabowski_runtime_deploy_schedule` in einer solchen
Sitzung ungeschützt.

## Entscheidung

Der Prozess friert beim Laden seines Codes die dann gültige Release-Identität
ein und vergleicht sie bei jedem mutierenden Aufruf gegen das Manifest. Ein
positiv beobachteter Unterschied weist die Mutation ab und nennt beide
Releases sowie die Abhilfe: den Connector neu verbinden.

Das Einfrieren geschieht genau einmal. Ein späterer Manifestwechsel kann nicht
zurückschreiben, unter welchem Release der Prozess tatsächlich gestartet ist.

## Sicherheitsgrenze

Nur ein *positiv beobachteter* Unterschied blockiert. Ist eine der beiden
Identitäten unbekannt oder unlesbar, bleibt es bei den bestehenden Gates; ein
unlesbares Manifest legt keinen gesunden Prozess still. Read-only-Werkzeuge
bleiben unberührt, die Prüfung sitzt hinter der `readOnlyHint`-Schranke.

Die Änderung lockert keine bestehende Autoritäts-, Lease-, Review-, Merge- oder
Recovery-Grenze. Sie fügt eine Bedingung hinzu und entfernt keine.

## Verifikation

`make validate` vollständig. Neu: 10 Tests für die Identitätsprojektion und 4
Gate-Integrationstests, die belegen, dass ein veralteter Prozess vor dem
Transport-Handshake abgewiesen wird, ein aktueller ihn unverändert erreicht,
eine unbekannte Manifestidentität nicht blockiert und Read-only-Werkzeuge
unbetroffen bleiben.

## Reichweite

Die Regel wirkt vorwärts, nicht rückwirkend. Ein Prozess kann nur die Regeln
durchsetzen, die in seinem eigenen Code stehen. Konkret:

- Prozesse, die vor dieser Änderung gestartet sind, enthalten die Prüfung
  nicht und bleiben unverändert ungeschützt. Für sie ist der Reconnect die
  einzige Abhilfe; das Deployment dieser Änderung repariert sie nicht.
- Ein Prozess, der mit dieser Änderung startet, blockiert seine Mutationen,
  sobald ein *späterer* Release deployt wird und er selbst weiterläuft.

Der Befund wird damit ab dem nächsten Deployment geschlossen, nicht sofort.
Genau deshalb nennt die Ablehnungsmeldung den Reconnect als Abhilfe statt ein
erneutes Deployment.

## Restrisiko

Sitzungen verlieren ihre Mutationsfähigkeit, sobald der Release unter ihnen
wechselt. Das ist beabsichtigt und der Kern des Befunds, bedeutet aber, dass
solche Sitzungen einen Reconnect brauchen statt einer stillen Weiterarbeit.

Verwaiste stdio-Operator-Prozesse werden hier nicht inventarisiert oder
begrenzt. Am 2026-08-04 liefen sieben davon ab dem 2026-07-30. Das bleibt eine
eigene Aufgabe.

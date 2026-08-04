# T139 stateless runtime regression hotfix

## Befund

Der auf `cb5ba94b772d21e113abd7e2bc2ddfc391c5a1c0` deployte Operator lief mit
`stateless_http=true`. FastMCP erzeugt in diesem Modus für jeden HTTP-Request ein
neues `ServerSession`-Objekt. T139 bindet Challenge, Bestätigung und Verbrauch
jedoch an genau dieses Objekt. Ein unmittelbar auf `begin` folgender `ack`
erhielt deshalb einen anderen Scope und meldete die Challenge als fehlend.

## Entscheidung

Der Operator nutzt wieder zustandsbehaftete Streamable-HTTP-Sitzungen. Anders
als vor Commit `e98a4adcc6afa4d830c9cd712c81579e3eacc354` wird kein fester
Idle-Timeout gesetzt. Dadurch bleiben Session-Objekt und T139-Scope über die
drei Aufrufe stabil, ohne die damals beobachteten gebündelten Cleanup-Wellen
wieder einzuführen.

## Sicherheitsgrenze

Die Reparatur führt weder den globalen `shared_unlabeled`-Pool noch eine
client-deklarierte Ersatzidentität wieder ein. Exakte Tool-/Argumentbindung,
Runtime-Bindung, Ablaufzeit, Einmalverbrauch und Trennung verschiedener
FastMCP-Sitzungen bleiben unverändert.

## Restrisiko

Verwaiste Sitzungen bleiben bis zum Operator-Neustart im Session-Manager. Eine
spätere Härtung soll Inventar, Obergrenze und druckfreien Einzelabbau ergänzen,
ohne eine gemeinsame Ablaufwelle einzuführen.

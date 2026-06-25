# Sicherheitsmodell

Grabowski soll ein starker lokaler Operator sein.

Die Sicherheitsarchitektur basiert nicht auf möglichst wenigen Fähigkeiten,
sondern auf folgenden Eigenschaften:

- explizite Wirkungsangabe,
- Vorschau vor folgenreichen Aktionen,
- Hash- und Zustandsprüfungen,
- atomare Änderungen,
- Audit-Trail,
- Rollback,
- Trennung von lokalen, Git- und Remote-Mutationen.

`~/repos/merges` bleibt eine unveränderbare Evidence-Zone.

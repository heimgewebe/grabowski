# Kanonischer Textartefakt-Export

`git-diff.v1` erzeugt aus zwei **vollständigen Commit-SHAs** eine unveränderliche
UTF-8-Textdatei mit der Endung `.txt` und ein SHA-256-gebundenes Receipt nach
`git-diff-artifact.v1`.

## Ablauf

1. `grabowski_text_artifact_publish` prüft Repository, Base und Head.
2. Git erzeugt ohne externe Diff- oder Textconv-Helfer einen vollständigen
   Unified Diff einschließlich binärer Git-Patches.
3. Hochkonfidente Zugangsdaten und Private-Key-Marker blockieren die Ausgabe.
4. Diff und Receipt werden privat und atomar unter
   `~/.local/state/grabowski/text-artifacts/<artifact_id>/` veröffentlicht.
5. `grabowski_text_artifact_read` verlangt bei jedem Aufruf den erwarteten
   Artefakt- und Receipt-Hash und liefert begrenzte, einzeln gehashte Chunks.
   Base64 ist ausschließlich die interne Transportkodierung zwischen getrennten
   Laufzeit-Dateisystemen; sie ist kein Nutzerformat.
6. Der Verbraucher dekodiert die Chunks in eine echte `.txt`-Datei und prüft
   abschließend Größe und SHA-256 gegen das Receipt.

## Sicherheitsgrenzen

- Nur vollständige 40-stellige, kleingeschriebene Commit-SHAs werden akzeptiert.
- Branches, Tags, Working-Tree-Änderungen und bewegliche Refs werden nicht exportiert.
- Git-Replace-Refs sind für Commitprüfung und Differzeugung deaktiviert.
- Maximalgröße: 32 MiB; Chunkgröße: maximal 256 KiB.
- Secret- und Browserprofil-Wurzeln sind ausgeschlossen.
- Der Reader öffnet Verzeichnisse und Dateien descriptorgebunden ohne Symlink-Folgen,
  verlangt Eigentum und private Modi und weist mehrfach hartverlinkte Dateien ab.
- Jeder Lesevorgang prüft Receipt, Dateityp, Größe und vollständigen SHA-256 neu.
- Der Vertrag ersetzt keine repositoryweite Secret-Prüfung vor einem Merge.

Der kanonische Nutzername lautet beispielsweise
`grabowski-pr-439-0123456789ab-diff.txt`; das Receipt, nicht der Dateiname, ist
autoritativ.

# Kanonischer Textartefakt-Export

`git-diff.v1` erzeugt aus zwei **vollständigen Commit-SHAs** eine unveränderliche
UTF-8-Textdatei mit der Endung `.txt` und ein SHA-256-gebundenes Receipt nach
`git-diff-artifact.v1`.

## Ablauf

1. `grabowski_text_artifact_publish` prüft Repository, den kanonischen
   `owner/repository`-Namen aus `origin`, Base und Head.
2. Git erzeugt ohne externe Diff- oder Textconv-Helfer einen vollständigen
   Unified Diff einschließlich binärer Git-Patches.
3. Hochkonfidente Zugangsdaten und Private-Key-Marker blockieren die Ausgabe.
4. Diff und Receipt werden privat und atomar unter
   `~/.local/state/grabowski/text-artifacts/<artifact_id>/` veröffentlicht.
   Ein hartes Budget von 4096 Artefakten und insgesamt 512 MiB verhindert
   unbegrenztes Wachstum; bei ausgeschöpfter Kapazität schlägt die Publikation
   fehl, statt vorhandene Evidenz still zu löschen.
   Ein nicht blockierender Store-Lock serialisiert Inventarprüfung und atomare
   Publikation; konkurrierende Publisher erhalten einen expliziten Busy-Fehler.
5. `grabowski_text_artifact_read` verlangt bei jedem Aufruf den erwarteten
   Artefakt- und Receipt-Hash und liefert begrenzte, einzeln gehashte Chunks.
   Base64 ist ausschließlich die interne Transportkodierung zwischen getrennten
   Laufzeit-Dateisystemen; sie ist kein Nutzerformat.
6. Der Verbraucher dekodiert die Chunks in eine echte `.txt`-Datei und prüft
   abschließend UTF-8, Größe und SHA-256 gegen das Receipt. Erst dieser
   Materialisierungs-Readback erlaubt die Behauptung, die Datei sei verfügbar.

## Sicherheitsgrenzen

- Nur vollständige 40-stellige, kleingeschriebene Commit-SHAs werden akzeptiert.
- Branches, Tags, Working-Tree-Änderungen und bewegliche Refs werden nicht exportiert.
- Git-Replace-Refs sind für Commitprüfung und Differzeugung deaktiviert.
- Maximalgröße: 32 MiB; Chunkgröße: maximal 256 KiB.
- Secret- und Browserprofil-Wurzeln sind ausgeschlossen.
- Neue Receipts enthalten zwingend die aus dem Netzwerk-Remote abgeleitete
  Repository-Identität `owner/repository`; lokale Pfade sind nicht autoritativ.
- Der Reader öffnet Verzeichnisse und Dateien descriptorgebunden ohne Symlink-Folgen,
  verlangt Eigentum und private Modi und weist mehrfach hartverlinkte Dateien ab.
- Jeder Lesevorgang prüft Receipt, Dateityp, Größe und vollständigen SHA-256 neu.
- Der Vertrag ersetzt keine repositoryweite Secret-Prüfung vor einem Merge.

Der kanonische Nutzername lautet beispielsweise
`grabowski-pr-439-0123456789ab-diff.txt`; das Receipt, nicht der Dateiname, ist
autoritativ. Vorhandene Receipts aus der kurzen Vorhärtungsphase mit einem
einzelnen Repository-Namen bleiben lesbar; der Publisher erzeugt sie nicht mehr.

## Unverwaltete Transportreste

Der Publisher bleibt fail-closed, wenn ein Artefaktverzeichnis außer dem
kanonischen Diff und `receipt.json` weitere Einträge enthält. Solche Einträge
werden nicht ignoriert und nicht anhand eines Dateinamens blind gelöscht.

`python -m grabowski_text_artifact_reconcile inspect-store` prüft den begrenzten
Gesamtbestand und nennt ausschließlich Artefakt-IDs mit Zusatzdateien.
`inspect --artifact-id <id>` erzeugt anschließend das digestgebundene
Einzelinventar. Es bindet das verwaltete Artefakt und Receipt sowie jede
Zusatzdatei an relativen Pfad, Dateityp, Dateiname, Eigentümer, Modus,
Linkzahl, Größe, Inode, Zeitstempel und SHA-256. Unbekannte Wurzeleinträge,
Symlinks, Hardlinks oder nicht erlaubte Modi blockieren geschlossen.

Eine Wirkung erfordert anschließend alle vier exakten Vorbedingungen:

```text
--artifact-id
--expected-inventory-sha256
--expected-artifact-sha256
--expected-receipt-sha256
```

`apply` kopiert nur die unverändert passenden Zusatzdateien in ein privates,
create-only Quarantäneverzeichnis unter
`~/.local/state/grabowski/text-artifact-quarantine/<inventory_sha256>/`.
Die abschließende Verzeichnisveröffentlichung verwendet unter Linux
`RENAME_NOREPLACE`; ein inzwischen vorhandenes Ziel wird niemals überschrieben.
Der Quarantänestore ist global auf 4096 Verzeichnisse und 512 MiB begrenzt.
Bestand und Neuzugang werden vor jeder Quellmutation vollständig geprüft.

Nach vollständigem Kopier- und Receipt-Readback wird jede gebundene Quelldatei
atomar in ein zufälliges privates Staging isoliert und dort erneut gegen Pfad,
Inode, Metadaten und SHA-256 geprüft. Nur die exakt gebundene Datei wird per
`RENAME_EXCHANGE` gegen ihre verifizierte Quarantänekopie getauscht. Eine
zwischen Prüfung und Isolation ersetzte Datei wird nicht gelöscht, sondern im
Recovery-Staging erhalten; der Store bleibt dann bewusst fail-closed. Symlinks,
Hardlinks, Hashdrift, unbekannte Modi, Kapazitätsüberschreitung und
konkurrierende Store-Nutzung blockieren. Das verwaltete Receipt und der
kanonische Diff werden niemals verschoben.

Das Modul wird über den bestehenden Runtime-Vertrag in den produktiven
Snapshot aufgenommen und dort mit dem privaten Runtime-Interpreter ausgeführt:
`<grabowski-runtime>/.venv/bin/python -m grabowski_text_artifact_reconcile`. Ein
separater Wheel- oder Launcher-Entry-Point wird nicht behauptet.

Nach eindeutig erfolgreicher Reconciliation darf der Publisher erneut
aufgerufen werden. Ein Quarantäne-Receipt begründet weder Reviewkorrektheit,
Mergeautorität noch die Urheberschaft der Transportdateien.

Altersbasierte Löschung ist eine eigene, explizit autorisierte Retention-Operation
und gehört nicht zur Publikationsberechtigung.

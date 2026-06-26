# Local Evidence Bundles

## Zweck

`tools/build_local_evidence.py` erzeugt ein begrenztes, read-only Beleg-Bundle
für genau einen lokalen Git-Arbeitsbaum. Der Builder ist kein zweiter Agent und
keine neue Control-Plane. Er macht den lokalen Repo-Zustand für Grabowski
kleiner, reproduzierbarer und prüfbar.

Der erste Slice löst fünf wiederkehrende Probleme:

1. Branch und `HEAD` werden vor der Analyse explizit geprüft.
2. Arbeitsbaum, geänderte Pfade und Patch werden gemeinsam erfasst.
3. Sichere ungetrackte UTF-8-Dateien werden begrenzt und redigiert aufgenommen.
4. Kandidaten für Tests, Workflows, Contracts und Dokumentation werden
   deterministisch abgeleitet.
5. Artefakte erhalten Hashes und Command-Provenance.

## Nicht-Ziele

Der Builder:

- führt keine Tests oder beliebigen Commands aus,
- schreibt nicht in das untersuchte Repository,
- nimmt keine Merge- oder Architekturentscheidung vor,
- behauptet keine vollständige Impact-Abdeckung,
- übernimmt keine ungetrackten Binärdateien, Symlinks oder übergroßen Dateien,
- bindet noch kein lokales LLM ein,
- verändert die produktive MCP-Tool-Liste nicht.

Der vorhandene Operator bleibt für Command-Ausführung zuständig. Eine spätere
Integration darf diese Trennung nicht verwischen.

## Contracts

Eingabe:

- `contracts/local-evidence-job.v1.schema.json`

Ergebnis:

- `contracts/local-evidence-result.v1.schema.json`

Unbekannte Job-Felder schlagen fail-closed fehl. `expected_branch` und
`expected_head` sind Pflichtfelder; ein Bundle ohne Zielzustand wäre nur eine
Momentaufnahme, aber kein Gate. `repo` muss ein absoluter Git-Toplevel unter
`GRABOWSKI_REPO_ROOT` sein. `output` muss neu und unter
`GRABOWSKI_WORKSPACE_ROOT` liegen. Symlink-Komponenten in Job-, Repo-, Policy-
und Workspace-Pfaden werden abgelehnt.

## Aufruf

```bash
python3 tools/build_local_evidence.py \
  --job config/local-evidence-job.example.json \
  --output "$HOME/grabowski-workspace/jobs/example-job"
```

Für einen realen Lauf müssen `repo`, `expected_branch` und `expected_head` im
Job-Manifest auf den gewünschten Arbeitsbaum zeigen.

Optionale Umgebungsvariablen:

```text
GRABOWSKI_REPO_ROOT
GRABOWSKI_WORKSPACE_ROOT
GRABOWSKI_POLICY_PATH
```

Standardwerte:

```text
~/repos
~/grabowski-workspace/jobs
~/.config/grabowski/access.json
```

## Bundle-Struktur

```text
JOB_ID/
├── job.json
├── result.json
├── repo-state.json
├── changed-paths.json
├── diff.patch
├── untracked-files.json
├── provenance.json
├── limitations.md
├── hashes.sha256
├── untracked/
│   └── <sicher aufgenommene neue Textdateien>
└── references/
    ├── tests.json
    ├── workflows.json
    ├── contracts.json
    └── docs.json
```

`hashes.sha256` deckt alle anderen Dateien des Bundles ab. `result.json`
listet die vor seiner Erzeugung vorhandenen Artefakte mit Hash und Größe.
`untracked-files.json` hält für jede sichtbare ungetrackte Datei fest, ob ihr
Inhalt aufgenommen wurde, welchen Quellhash sie hatte und warum eine Aufnahme
gegebenenfalls unterblieb.

## Statussemantik

### `complete`

Der erwartete Branch und Head stimmen, der Zustand blieb während der Sammlung
stabil und es trat keine bekannte Kürzung oder Auslassung auf. Sichere,
begrenzte ungetrackte UTF-8-Dateien können dabei vollständig als Artefakte
enthalten sein.

### `partial`

Das Bundle ist nutzbar, besitzt aber eine explizite Begrenzung, zum Beispiel:

- ungetrackte Binär-, Symlink-, Nicht-UTF-8- oder übergroße Inhalte wurden
  ausgelassen,
- Änderungen außerhalb von `allowed_paths` wurden ausgelassen,
- sensible Pfade wurden ausgelassen,
- secret-artige Patch- oder Textwerte wurden redigiert,
- ein Größen-, Pfad-, Datensatz- oder Scanbudget wurde erreicht,
- Git-Status, Patchquelle, ungetrackte Quelle oder gelesene Referenzquelle
  änderte sich während der Sammlung.

### `rejected`

`expected_branch` oder `expected_head` stimmen nicht. Repo-State wird dennoch
belegt; Patch, ungetrackte Inhalte und Referenzsuche bleiben leer. Der Prozess
endet mit Exitcode 2.

### `failed`

Im v1-Result-Contract reserviert. Unerwartete Builderfehler enden derzeit mit
Exitcode 2, ohne ein autoritatives Ergebnisbundle zu publizieren.

## Sicherheitsgrenzen

- Git-Leseoperationen laufen mit `GIT_OPTIONAL_LOCKS=0`.
- Der Builder prüft den Index in Tests auf Unverändertheit.
- Sensible Komponenten und Dateimuster stammen aus der Zugriffspolicy und
  werden durch konservative Defaults ergänzt.
- Patchinhalte und aufgenommene ungetrackte Texte werden zusätzlich auf
  typische Schlüssel- und Secretmuster redigiert.
- Sichtbare Änderungen sind auf 5.000 Einträge begrenzt.
- Patches sind auf 1.000 Pfade, 200.000 Pfad-Argumentbytes und höchstens 2 MB
  Ergebnisgröße begrenzt.
- Ungetrackte Textdateien sind auf 2 MB je Datei, 10 MB insgesamt und 1.000
  Datensätze begrenzt.
- Referenzdateien werden nur bis 2 MB je Datei und 50 MB insgesamt gelesen.
- Symlink-Referenzkandidaten und ungetrackte Symlinks werden nicht gelesen;
  Symlink-Komponenten in Steuerpfaden werden abgelehnt.
- Ausgabe wird zunächst in einem temporären Verzeichnis aufgebaut und erst
  nach vollständiger Erzeugung atomar publiziert.

Diese Grenzen verhindern nicht jede denkbare Geheimnisform. Ein
sprachmodellfreies Werkzeug wird nicht dadurch allwissend, dass sein JSON sehr
gerade Kanten hat.

## Stabilitätsnachweis

`repo-state.json` trennt vier Prüfflächen:

- `status_stable`: Branch, `HEAD`, Status und Auslassungszähler blieben gleich,
- `patch_source_stable`: der rohe Git-Diff der tatsächlich aufgenommenen
  Patchpfade behielt denselben Hash,
- `untracked_sources_stable`: aufgenommene oder klassifizierte ungetrackte
  Quellen blieben unverändert,
- `reference_sources_stable`: alle gelesenen Referenzdateien behielten ihren
  Hash.

Nur wenn alle vier Prüfflächen grün sind, ist `stable_during_collection` wahr.
Ein gleichbleibendes `M` im Git-Status genügt damit nicht als
Inhaltsstabilitätsbeweis.

## Referenzmapping

Die Referenzlisten sind Kandidaten, keine Vollständigkeitsbehauptung. Die
Ausgabe enthält deshalb stets:

```json
{
  "complete": false
}
```

Die Ableitung nutzt:

- direkt geänderte Test-, Workflow-, Contract- oder Dokumentationspfade,
- Fixed-String-Treffer von Dateiname und Dateistamm in getrackten Kandidaten.

Dynamische Imports, generierte Dateien, indirekte Shell-Aufrufe und externe
Konsumenten können fehlen.

## Reale Pilotkorrektur

Der erste Selbstlauf auf dem Implementierungs-Worktree zeigte, dass ein Bundle
mit bloßen Namen ungetrackter Dateien für neue PR-Dateien praktisch
unzureichend ist. Daraufhin wurde die begrenzte Textaufnahme ergänzt. Dieses
Beispiel ist der gewünschte Nutzen des Piloten: Nicht die Architektur wird
bestätigt, sondern ihre erste falsche Annahme wird früh sichtbar gemacht.

Der zweite Selbstlauf nahm alle sechs neuen Textdateien auf und endete mit
`complete`; Git-Status, Patchquelle, ungetrackte Quellen und Referenzquellen
blieben dabei stabil.

## Mess-Gate vor Ausbau

Der nächste Slice wird nur gerechtfertigt, wenn reale Aufgaben mindestens zwei
der folgenden Effekte zeigen:

- 30 Prozent weniger manuelle Evidenzschritte,
- 40 Prozent weniger übertragener Kontext,
- keine Zunahme übersehener relevanter Dateien oder Fehlbefunde.

Bis diese Messung vorliegt, werden weder Queue noch Vektordatenbank, lokales
LLM oder autonome Patchfunktion ergänzt.

# Agent Workspace v1

## Zweck

`Agent Workspace v1` ist eine kleine Grabowski-Ausführungsoberfläche für genau einen schreibenden Agenten und zwei nachgelagerte Prüfrollen. tmux zeigt Prozesse nur an; es besitzt keine Aufgaben-, Fortschritts- oder Erfolgswahrheit.

Wahrheitsquellen:

- Bureau bindet Aufgabe oder Thread-Fokus.
- Git und GitHub führen Code-, Branch-, Diff-, PR- und Merge-Wahrheit.
- Grabowski führt Tasks, Ressourcen-Leases, Ausführungszustände und Receipts.
- tmux ist ausschließlich die sichtbare Oberfläche.

## Befehlsfamilie

- `grabowski_agent_workspace_create`
- `grabowski_agent_workspace_status`
- `grabowski_agent_workspace_attach`
- `grabowski_agent_workspace_collect`
- `grabowski_agent_workspace_role_retry`
- `grabowski_agent_workspace_close`

## Ablauf

### Create

`create` bindet einen live geprüften, aktiven Bureau-Thread-Fokus oder einen vorhandenen, nicht abgeschlossenen Bureau-Registry-Task sowie Repository und erwarteten Basis-Head. Es erzeugt deterministisch eine tmux-Session mit den Rollen `Captain`, `Writer`, `Tests` und `Review`, legt für den Writer einen eigenen Branch und Worktree an und startet ausschließlich den Writer als langlebigen Grabowski-Task. Writer-, Test- und Review-Kommandos durchlaufen bereits vor Speicherung und vor dem Python-Rollenwrapper dieselbe Operator-Argv-Policy wie direkte Tasks. Geheimnistragende Argumente und Privileg-Eskalatoren wie `sudo`, `su`, `pkexec` oder `doas` blockieren auch im Trusted-Owner-Modus.

Der Writer-Worktree muss außerhalb des kanonischen Checkouts liegen. Lokale, remote-tracking und live auf `origin` vorhandene Branches blockieren. Ein Repo-weites Writer-Lease verhindert in v1 parallele Writer. Der Writer besitzt keine Merge-Autorität. Kollisionen mit Session, Branch, Worktree, Workspace-ID oder Lease blockieren fail-closed.

Ein wiederholtes `create` ist nur dann idempotent, wenn der aus dem Manifest neu berechnete Planhash exakt passt, das Manifest nach erfolgreichem Runtime-Ready-Audit ausdrücklich den Zustand `ready` trägt, Writer-Task und vier eindeutige Pane-IDs vollständig gebunden sind, keine Create-Failure-Receipt oder offene Rollen-Startabsicht vorliegt und Workspace-Leases, tmux-Session, Pane-Inventar, Writer-Task sowie Writer-Branch und unveränderter Writer-Head live zur gespeicherten Identität passen. Uncommittierter Writer-Fortschritt und ein später fortgeschrittener Basisbranch gelten dabei nicht als Create-Fehler; Inhalts-, Scope- und Basisdrift werden durch `status` und `collect` bewertet. Teilweise, nicht auditierte oder fehlgeschlagene Erzeugungen werden als Recovery-Fall ausgewiesen und niemals als erfolgreicher bestehender Workspace zurückgegeben. Ist der Ausgang eines Writer-Starts, einer Worktree-Erzeugung oder ihrer Stornierung unklar, bleiben Worktree beziehungsweise Branch und die konfliktverhindernde Lease erhalten, solange eine sichere, exakt basisgebundene Bereinigung nicht beobachtet wurde; der Fehlerbeleg bindet Wrapper-Argv-Hash, Host und Arbeitsverzeichnis.

Der Writer läuft in einem Bubblewrap-Minimalroot. Sichtbar sind nur Systemlaufzeit, sein eigener Worktree sowie die zugehörigen Git-Metadaten read-only. Der gesamte Worktree wird zunächst read-only eingebunden; ausschließlich die bei `create` gebundenen, bereits vorhandenen Scope-Wurzeln werden darüber gezielt schreibbar eingebunden. Die Root-Metadaten `.git` sind als Scope ausdrücklich verboten. Home, Haupt-Checkout und Secrets-Pfade sind nicht sichtbar. Git-Head, Branch, Index und Refs bleiben read-only. Der nachgelagerte Scope-Check prüft zusätzlich alle geänderten und untracked Pfade. Untracked Symlinks und Hardlinks werden abgelehnt. Damit ist der Scope sowohl während als auch nach der Writer-Ausführung gebunden.

### Status

`status` liest live:

- Bindung, Repository und Basis-Head
- Writer-Branch, Worktree, Head, Diff, Dirty State und Scope
- Grabowski-Taskzustände und offene, hashgebundene Rollen-Startabsichten
- tmux-Session und Pane-IDs
- Tests, Review-Findings und Abschlussfähigkeit
- fehlgeschlagene Rollen (`failed_roles`), Retry-Eignung je Rolle (`role_retry`), eine prospektive Abschlussklassifikation (`closure_outcome`) und eine deterministische `recommended_next_action`

Ein laufendes oder beendetes Pane ist niemals ein Erfolgsbeleg. Jedes Pane zeigt diese Grenze prominent und blendet vorhandene Receipt-Fehler ein. `success_ready` verlangt erfolgreich abgeschlossene Tasks, einen unveränderten Head und Diff, grünen Scope, keine Basisdrift, erfolgreiche Tests, `PASS`-Review ohne Findings und eine vollständige Collection-Receipt.

`role_retry` klassifiziert je Rolle deterministisch, ob ein Retry zulässig ist. `eligible` gilt für einen vor Taskstart typisiert blockierten Toolchain-Preflight sowie für einen terminalen Rollenlauf, dessen unveränderliche, vollständig an Writer und Kommando gebundene Receipt ausdrücklich `environment_toolchain_failure` ausweist. Bestehende untypisierte Receipts bleiben lesbar, erteilen aber keine Retry-Autorität. Ein echter Testfehlschlag (`semantic_test_failure`) oder ein `NEEDS_CHANGE`/`BLOCK`-Review-Verdict (`review_verdict_blocks_retry`) bleibt ausdrücklich nicht retry-fähig, ebenso ein bereits erfolgreicher Lauf (`already_succeeded`), ein laufender Task (`role_running`), ein unklarer Ausgang (`unknown_prior_outcome`), ein Probe-Infrastrukturfehler oder ein ungültiges Receipt (`invalid_receipt`). `recommended_next_action` leitet sich deterministisch aus Erzeugungszustand, offener Retry-Eignung, Vollständigkeit der Rollenbelege, Abschlussfähigkeit und Erfolgszustand ab (`retry_role:<rolle>`, `close`, `close_with_abandon_failed_roles`, `recollect_or_reconcile_incomplete_role_evidence`, `collect`, `await_creation`, `await_collection_or_reconcile` oder `none_closed`).

### Attach

`attach` liefert nur den exakten `tmux attach-session`-Aufruf für die bestehende Session. Es erzeugt keine neue Wahrheit und keinen neuen Zustand.

### Collect

`collect` wartet zunächst auf einen erfolgreich abgeschlossenen Writer-Task mit passender Writer-Receipt. Unklare oder verwaiste Zustände lösen einen Reconcile-Check aus. Scope-Verletzung oder Basisdrift blockieren, ohne Änderungen zu löschen. v1 akzeptiert ausschließlich einen schmutzigen, exakt erfassten Worktree auf unverändertem Basis-Head; daraus materialisiert `collect` einen vollständigen Binärpatch einschließlich untracked Dateien. Direkte Writer-Commits sind absichtlich ausgeschlossen, weil die Git-Metadaten read-only eingebunden sind.

Alle vom Captain ausgeführten Git-Aufrufe laufen nicht-interaktiv mit deaktivierten Hooks, deaktiviertem fsmonitor, ohne globale oder systemweite Git-Konfiguration und mit einer engen Protokoll-Allowlist. Diff-, Textconv- und externe Diff-Helfer sind auf den Evidenzpfaden ausdrücklich deaktiviert. Dadurch kann Repository-Konfiguration keine zusätzlichen Hostprozesse in den Prüfpfad einschleusen.

Die Patch-Erzeugung verarbeitet Git-Diffs als rohe Bytes und liest Dateilisten NUL-getrennt. Dadurch bleiben Binärdateien sowie Pfade mit Leerzeichen, Tabs oder Zeilenumbrüchen unverändert. Nach der Patch-Materialisierung wird der Writer-Stand sofort und nach einer kurzen Settle-Phase erneut vollständig gelesen. Nur wenn Branch, Head, Basis, Dirty State, Scope und Diff-Hash in allen drei Beobachtungen identisch sind, wird das Ergebnis eingefroren. Eine späte Mutation blockiert als `writer_changed_during_freeze`; ein bloßes `sleep` oder `fsync` gilt nicht als Wahrheitsbeweis.

Erst dieser hashgebundene Writer-Patch bindet Basis-Head, Diff und Ergebnisartefakt. Vor dem Writer-Start werden alle bereits vorhandenen Einträge der schreibbaren Scope-Bäume begrenzt und ohne Symlink-Folgen geprüft: Hardlinks, Nicht-Regulärdateien und Übergänge auf ein anderes Dateisystem blockieren fail-closed; höchstens 100.000 Einträge werden betrachtet. Dadurch kann ein vorab angelegter Hardlink innerhalb eines erlaubten Verzeichnisses keinen außerhalb liegenden Host-Inode beschreibbar machen. Der Writer-Beleg speichert den abschließenden Git-Status nur als Anzahl und SHA-256, nicht als unbeschränkte Pfadliste.

Danach startet `collect` Tests und Review als eigene langlebige Tasks in einem Bubblewrap-Minimalroot mit ausschließlich read-only eingebundenem Writer-Stand, fallengelassenen Linux-Capabilities und schreibbarem privatem `/tmp`. Bevor eine Tests- oder Review-Rolle startet, prüft `collect` in genau demselben read-only Bubblewrap-Sandbox per Toolchain-Preflight, ob das deklarierte Rollenkommando ausführbar ist. Ein per `-m` aufgerufenes Python-Modul wird ausschließlich anhand des Top-Level-Namens aus dem Kommando abgeleitet. Die erste Probe löst das deklarierte Executable im Sandbox-PATH auf. Ein deklariertes Python-Modul wird anschließend durch genau diesen aufgelösten Interpreter mit `-I -S` geprüft. Dadurch werden weder `sitecustomize` noch `.pth`-Code geladen; die Prüfung verwendet nur eingebaute Importer und `PathFinder` auf einer expliziten Liste aus Arbeitsverzeichnis, Interpreterpfaden und den aus dem Interpreterpfad abgeleiteten Site-Packages-Verzeichnissen. Das Zielmodul selbst wird nicht importiert oder ausgeführt. Fehlt das Kommando oder das deklarierte Modul, liefert `collect` einen typisierten `role_toolchain_preflight_failed`-Zustand, startet keinen dauerhaften Rollen-Task und verbraucht keinen Rollen-Versuch; der Befund wird append-only im Manifest unter `role_preflight_blocks` protokolliert. Vor jedem tatsächlichen Rollenstart wird zusätzlich eine dauerhafte, an Rolle, Wrapper-Argv, Host, Arbeitsverzeichnis, Writer-Head und Diff gebundene Startabsicht gespeichert. Bleibt der Ausgang eines normalen Starts oder Retry-Starts unklar, blockieren Status, Collect, Close und ein erneuter Retry mit Reconcile-Bedarf, statt dieselbe Rolle möglicherweise doppelt zu starten. Der lokale Task-Host ist in v1 ausdrücklich an den registrierten Adapter `heim-pc` gebunden und im Workspace-Plan sichtbar; eine freie Fleet-Zielwahl ist kein Teil dieser Oberfläche. stdout und stderr werden durch den übergeordneten Prozess getrennt gestreamt und begrenzt, ohne die Dateigröße legitimer Build-Artefakte im Kindprozess zu beschränken. Für Tests und Review gelten jeweils 4 MiB pro Ausgabestrom; strukturiertes Review-JSON ist auf 1 MiB begrenzt. Nach Ende oder Abbruch des Gruppenleiters wird die vollständige Prozessgruppe beendet, damit keine Kindprozesse den Freeze überleben.

Netzwerkisolation ist in v1 ausdrücklich nicht garantiert: Bubblewrap-Netzwerk-Namensräume sind im aktuellen Grabowski-Dienstkontext wegen der Host-Adressfamiliengrenze nicht verwendbar. Writer, Tests und Review dürfen daher nur als vertrauensbegrenzte lokale Agenten laufen, nicht als vollständig untrusted Code. Der vor Ausführung geprüfte Bubblewrap-Pfad wird auf seinen kanonischen, aufgelösten Binary-Pfad festgelegt. Beide Prüfrollen verifizieren vor und nach der Ausführung denselben Head und Diff. Review muss genau ein strukturiertes JSON-Objekt mit `verdict` und `findings` liefern.

Workspace-Manifeste, Fehlerbelege und Receipts werden ausschließlich aus privaten, eigentümerkontrollierten regulären Dateien mit einfacher Linkzahl gelesen. Metadatenprüfung und begrenztes JSON-Lesen erfolgen über denselben mit `O_NOFOLLOW` geöffneten Deskriptor; Pfadtausch, FIFO-, Symlink- und Hardlink-Zustände blockieren fail-closed.

Writer-, Test- und Review-Receipts werden beim Einsammeln aus ihren kanonischen Feldern erneut gehasht; ein lediglich vorhandener oder nachträglich manipulierter Hash genügt nicht. Rollen-Receipts müssen außerdem Basis, Kommando, Vor- und Nachzustand sowie den erwarteten Sandboxvertrag bestätigen. Ein erfolgreiches Rollen-Receipt wird nur akzeptiert, wenn der aktuell im Manifest gebundene Task selbst als `completed` beobachtet wird; ein altes PASS-Receipt kann einen fehlgeschlagenen aktuellen Task nicht ersetzen. Review-Findings sind ausschließlich strukturierte Objekte. Der Writer-Patch ist exakt an `writer.patch` im Workspace gebunden, muss eine private, eigentümerkontrollierte reguläre Datei innerhalb der 128-MiB-Grenze sein und wird bei der Verifikation chunkweise gehasht. Collection und Close werden zusätzlich gegen getrennte, inhaltlich identische Receipt-Dateien verifiziert. Status und Close bleiben bei Hash- oder Dateiabweichung blockiert. Atomare Workspace- und Rollen-Schreibvorgänge fsyncen Datei und Elternverzeichnis; schlägt die Übergabe eines Rohdeskriptors an den Python-Datei-Wrapper fehl, wird der Deskriptor explizit geschlossen und das temporäre Artefakt entfernt.

`collect` und `close` serialisieren ihre Zustandsübergänge über eine private, eigentümerkontrollierte reguläre Lockdatei mit einfacher Linkzahl. Der Lock wird nicht unbegrenzt blockierend erworben: Nach zehn Sekunden endet der Aufruf fail-closed mit einem Timeout, statt einen MCP-Aufruf dauerhaft festzuhalten.

Diese lokalen Hashes liefern Integritäts- und Bindungsevidence, aber keine kryptographische Authentizität gegenüber einem privilegierten Host-Angreifer. Ein Nutzer mit Schreibzugriff auf Workspace-State und Auditquellen liegt außerhalb des v1-Bedrohungsmodells; entsprechende Manipulation kann nicht allein durch selbst gespeicherte Hashes ausgeschlossen werden.

Die abschließende Collection-Receipt bindet:

- Basis-Head
- Writer-Head
- Diff-SHA-256
- geänderte Pfade und Scope
- Dirty State, Patch-Bindung und Basisdrift
- Teststatus
- Review-Verdict und Findings
- Task-IDs
- Resultat-SHA-256

Status-, Collection- und Close-Antworten tragen zusätzlich eine maschinenlesbare `external_closeout_checklist` mit den Punkten PR-/Integrationswahrheit, Bureau-Task-Abgleich, Freigabe der Workspace-Lease, Archivierung/Bereinigung des Writer-Worktrees und operativer Abschlussbericht. PR-/Integrationswahrheit, Bureau-Abgleich, Worktree-Lifecycle und operativer Abschluss bleiben `unknown`, bis ihre jeweilige externe Wahrheitsquelle sie bestätigt. Die Workspace-Lease ist vor `close` ebenfalls `unknown`; nach einer integritätsgeprüften vollständigen Close-Receipt mit live bestätigter Freigabe wird genau dieser Punkt als `verified` ausgewiesen.

### Rollen-Retry

`grabowski_agent_workspace_role_retry` erlaubt genau einen expliziten Neuversuch je Tests- oder Review-Rolle in einem bereits eingesammelten (`frozen_writer` vorhanden), aber noch nicht geschlossenen Workspace, mit einem explizit übergebenen Ersatz-Argv. Der Retry bleibt strikt an den eingefrorenen Writer-Head, Basis-Head, Diff und Dirty-Zustand sowie den eingefrorenen Patch gebunden; ein aktuell abweichender Live-Zustand blockiert als `binding_drift`. Der Writer selbst darf nie erneut versucht werden.

Ein Retry ist zulässig, wenn entweder der ursprüngliche Toolchain-Preflight vor Taskstart typisiert blockierte oder ein tatsächlich gestarteter, terminaler Rollenlauf in einer gültigen Receipt einen durch erneute Sandbox-Prüfung belegten `environment_toolchain_failure` ausweist. Ein echter Testfehlschlag oder ein `NEEDS_CHANGE`-/`BLOCK`-Review-Verdict blockiert den Retry ausdrücklich, ebenso ein bereits erfolgreicher Lauf, ein laufender Task, ein ungültiges Receipt, ein Probe-Infrastrukturfehler oder ein unklarer Task-Ausgang. Ein beliebiger Returncode 127, frei formulierter stderr-Text oder ein altes untypisiertes Receipt reicht nicht als Umweltbeleg. Retry ist niemals automatisch; er läuft ausschließlich über diesen expliziten Aufruf. Je Rolle ist höchstens ein expliziter Retry erlaubt; ein Aufruf, dessen eigener Toolchain-Preflight fehlschlägt, verbraucht weder Retry-Budget noch Rollenversuch, da kein Task startet.

Ein blockierter Preflight ist kein Rollenversuch: Der erste tatsächlich gestartete Ersatzlauf bleibt Versuch 1 und verwendet die kanonische `<rolle>-receipt.json`. Nur wenn bereits ein Rollen-Task lief, wird der Ersatzlauf Versuch 2 und schreibt `<rolle>-receipt.attempt-2.json`; das Receipt von Versuch 1 bleibt bytegenau unverändert. Jeder gestartete Rollenversuch besitzt höchstens eine solche create-only Receipt-Datei. Ein doppelter Prozessstart kann ein vorhandenes Attempt-Receipt nicht ersetzen; ein bereits vorhandenes Ziel blockiert den Start beziehungsweise lässt den zweiten Prozess fail-closed scheitern. Die Kommando-Bindung wird aus dem exakt ausgewählten Versuch gelesen, nicht aus dem lediglich neuesten Retry-Eintrag. Das Manifest bindet zusätzlich vorherige Task-ID und Receipt-Hash, `retry_reason`, vorherige Fehlklassifikation, alte und neue Kommando-Hashes, die neue Task-ID, die Versuchsnummer sowie den ausgewählten, für `collect` maßgeblichen finalen Versuch je Rolle. Bestehende v1-Workspaces und -Manifeste ohne diese Felder bleiben lesbar.

### Close

`close` akzeptiert nur die exakten Head-, Diff- und Resultat-Hashes der Collection-Receipt. Aktive Tasks blockieren standardmäßig; kontrolliertes Stoppen muss ausdrücklich aktiviert werden. Die tmux-Session kann entfernt werden. Eine erfolgreiche Lease-Freigabe wird erst behauptet, wenn eine anschließende Live-Beobachtung bestätigt, dass keiner der erwarteten Workspace-Schlüssel mehr aktiv ist. Verbleibende Schlüssel oder ein nicht beobachtbarer Freigabeausgang bleiben als persistente, nicht idempotente Recovery-Zustände blockiert; ein verlorener Rückkanal allein widerlegt eine live bestätigte Freigabe dagegen nicht.

Fehlen in einer als vollständig markierten Collection-Receipt strukturell gebundene Tests- oder Review-Belege, blockiert `close` stets mit `incomplete_role_evidence`; ein solcher Zustand kann weder als Erfolg noch als bewusste Aufgabe geschlossen werden. Enthält eine vollständige Collection-Receipt eine fehlgeschlagene Tests- oder Review-Rolle (kein `passed`-Status, kein `PASS`-Verdict ohne Findings), blockiert `close` standardmäßig mit `failed_roles_require_explicit_abandonment` und nennt die betroffenen Rollen. Erst der zusätzliche, standardmäßig auf `false` gesetzte Parameter `abandon_failed_roles=true` erlaubt das Schließen eines solchen Workspace; die Close-Receipt trägt dann `closure_outcome: "abandoned_failed_roles"` statt `"successful"` sowie die Liste der abgebrochenen Rollen. Diese Erweiterung ist rückwärtskompatibel: Ein Workspace ohne fehlgeschlagene Rolle schließt wie zuvor ohne den neuen Parameter.

Auch `close`-Antworten tragen dieselbe maschinenlesbare `external_closeout_checklist` wie `collect`.

Writer-Branch, Writer-Worktree und gegebenenfalls der materialisierte Patch werden in v1 immer erhalten. Dadurch kann `close` keine ungesicherten Änderungen verwerfen. Eine spätere Archivierung oder Entfernung erfolgt separat über die bestehenden Checkout-Werkzeuge.

### Ausführungsmodell

Agent Workspace v1 erzeugt keine vier Kopien des aktuellen ChatGPT-Kontexts. Captain ist eine Operatoransicht; Writer, Tests und Review sind Prozess-Slots für explizit gebundene Kommandos. Der Standard für Grabowski-Arbeit ist deshalb **operator-nativ**: Derselbe ChatGPT-Operator verantwortet Aufgabenzerlegung, Writer-Änderung, Tests, kritischen Review, Integration und Recovery mit einem gemeinsamen Gesamtkontext. Externe Coding-Agenten sind nicht Standardbesetzung der Lanes, sondern werden nur opt-in für ein eng begrenztes großes Implementierungspaket, unabhängigen Kontrast oder einen Kapazitäts-Fallback eingesetzt. Ihre Delegationsreihenfolge ist Claude, Codex, agy, Cline. Der Workspace selbst wird nur genutzt, wenn seine Isolation, langlebigen Tasks oder zusätzliche Delegation einen nachweisbaren Vorteil gegenüber dem normalen operator-nativen Worktree-/Test-/Review-Ablauf bieten.

## Abgrenzung

Nicht Bestandteil von v1:

- mehrere Writer
- automatische Scope-Aufteilung
- Zellij
- lokale KI oder Ollama
- automatische PR-Erstellung oder Befundbehebung
- automatische Konfliktauflösung oder Merges
- eigene Queue oder Statusdatenbank
- langfristige Agentenplanung

Workspace-Manifeste und Receipts sind größenbegrenzt und werden als Ausführungsartefakte behandelt. Live-Zustände werden aus Grabowski-Tasks, Git und tmux abgeleitet; die Artefakte ersetzen keine dieser Wahrheitsquellen.

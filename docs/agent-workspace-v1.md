# Agent Workspace v1

## Zweck

`Agent Workspace v1` ist eine kleine Grabowski-Ausführungsoberfläche für genau einen isolierten **beratenden Kontrast-Writer-Slot** und zwei nachgelagerte Prüfrollen. ChatGPT/Grabowski bleibt der einzige autoritative Writer und Integrator. tmux zeigt Prozesse nur an; es besitzt keine Aufgaben-, Fortschritts- oder Erfolgswahrheit.

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

`create` bindet einen live geprüften, aktiven Bureau-Thread-Fokus oder einen vorhandenen, nicht abgeschlossenen Bureau-Registry-Task sowie Repository und erwarteten Basis-Head. Neue Workspaces verlangen zusätzlich schema-v2-Routenevidenz für eine **ausdrücklich angeforderte beratende Kontrast- oder Wettbewerbsausführung**. Ohne diesen Beleg blockiert `create` vor jeder Mutation. Es erzeugt deterministisch eine tmux-Session mit den Rollen `Captain`, `Writer`, `Tests` und `Review`, legt für den Kontrast-Writer einen eigenen Branch und Worktree an und startet ausschließlich diesen Slot als langlebigen Grabowski-Task. Der Slot besitzt keine Autorität über den direkten Operatorpfad. Writer-, Test- und Review-Kommandos durchlaufen bereits vor Speicherung und vor dem Python-Rollenwrapper dieselbe Operator-Argv-Policy wie direkte Tasks. Geheimnistragende Argumente und Privileg-Eskalatoren wie `sudo`, `su`, `pkexec` oder `doas` blockieren auch im Trusted-Owner-Modus.

Bureau-Antworten werden an einer eigenen Adaptergrenze gelesen. Sowohl das historische direkte JSON-Objekt als auch das aktuelle `result`-Envelope sind syntaktisch unterstützt. Enthält die Antwort eine `runtime_identity`, akzeptiert der Workspace nur `compatible` oder `canonical-read-only`; `stale`, `dirty`, `unbound` und unbekannte Zustände blockieren mit dem konkreten Bureau-Grund. Task-Bindungen lesen danach ausschließlich aus dem im gültigen Envelope ausgewiesenen, vorhandenen und schreibgeschützten kanonischen Registry-Snapshot. Der lokale Bureau-Hauptcheckout wird weder als Arbeitsverzeichnis noch über `--root` erzwungen und kann deshalb bei Dirty-State oder Rückstand die Runtime-Wahrheit nicht mehr überschreiben. Nur ein historisches direktes JSON ohne Runtime-Identität verwendet weiterhin den explizit konfigurierten Legacy-Root und weist dies in der Evidenz als `legacy-explicit-root` aus. Dadurch wird ein Adapterwechsel nicht mehr fälschlich als fehlendes Feld gemeldet, ohne die Wahrheits- und Aktualitätssperre abzuschalten.

Wrapper-Argv und Task Store verwenden eine gemeinsame versionierte Kommandoidentität. Die UTF-8-JSON-Kanonisierung und der daraus berechnete `argv_sha256` stammen aus einem einzigen Modul; nicht-ASCII-Argumente können daher nicht mehr zwischen Workspace-Intent, Task-Datensatz und Live-Validierung auseinanderlaufen.

Der Kontrast-Writer-Worktree muss außerhalb des kanonischen Checkouts liegen. Lokale, remote-tracking und live auf `origin` vorhandene Branches blockieren. Ein Repo-weites Lease verhindert parallele mutierende Agenten-Slots. Der Kontrast-Writer besitzt weder Merge- noch Integrationsautorität; ChatGPT/Grabowski bleibt der autoritative Writer. Kollisionen mit Session, Branch, Worktree, Workspace-ID oder Lease blockieren fail-closed.

Ein wiederholtes `create` ist nur dann idempotent, wenn der aus dem Manifest neu berechnete Planhash exakt passt, das Manifest nach erfolgreichem Runtime-Ready-Audit ausdrücklich den Zustand `ready` trägt, Writer-Task und vier eindeutige Pane-IDs vollständig gebunden sind, keine Create-Failure-Receipt oder offene Rollen-Startabsicht vorliegt und Workspace-Leases, tmux-Session, Pane-Inventar, Writer-Task sowie Writer-Branch und unveränderter Writer-Head live zur gespeicherten Identität passen. Uncommittierter Writer-Fortschritt und ein später fortgeschrittener Basisbranch gelten dabei nicht als Create-Fehler; Inhalts-, Scope- und Basisdrift werden durch `status` und `collect` bewertet. Teilweise, nicht auditierte oder fehlgeschlagene Erzeugungen werden als Recovery-Fall ausgewiesen und niemals als erfolgreicher bestehender Workspace zurückgegeben. Ist der Ausgang eines Writer-Starts, einer Worktree-Erzeugung oder ihrer Stornierung unklar, bleiben Worktree beziehungsweise Branch und die konfliktverhindernde Lease erhalten, solange eine sichere, exakt basisgebundene Bereinigung nicht beobachtet wurde; der Fehlerbeleg bindet Wrapper-Argv-Hash, Host und Arbeitsverzeichnis.

Der Writer läuft in einem Bubblewrap-Minimalroot. Sichtbar sind nur Systemlaufzeit, sein eigener Worktree sowie die zugehörigen Git-Metadaten read-only. Der gesamte Worktree wird zunächst read-only eingebunden; ausschließlich die bei `create` gebundenen, bereits vorhandenen Scope-Wurzeln werden darüber gezielt schreibbar eingebunden. Die Root-Metadaten `.git` sind als Scope ausdrücklich verboten. Home, Haupt-Checkout und Secrets-Pfade sind nicht sichtbar. Git-Head, Branch, Index und Refs bleiben read-only. Der nachgelagerte Scope-Check prüft zusätzlich alle geänderten und untracked Pfade. Untracked Symlinks und Hardlinks werden abgelehnt. Damit ist der Scope sowohl während als auch nach der Writer-Ausführung gebunden.

Nach Erzeugung des Worktrees, aber vor dem langlebigen Writer-Task, läuft derselbe begrenzte Toolchain-Preflight wie für read-only Rollen. Fehlt das deklarierte Programm oder sein expliziter External-Agent-Kontext, wird kein Writer-Task gestartet und der Workspace bleibt als fehlgeschlagene Erzeugung mit Beleg erhalten. Für direkte `claude`-Kommandos existiert genau ein versioniertes Profil: Das aufgelöste Claude-Binary, die private Credentialdatei und vorhandene private Claude-Einstellungsdateien werden einzeln read-only in `/opt/grabowski-external` beziehungsweise das private `/tmp` gebunden. Das Benutzer-Home, andere Claude-Verzeichnisse und beliebige Secrets bleiben unsichtbar. Andere Programme erhalten durch dieses Profil keine zusätzlichen Bindings.

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

### Base-Drift-Integrationsprobe

Wenn der kanonische Repository-Head vom gebundenen Workspace-Base abweicht, berechnet `status` eine reine Integrationsdiagnose. Die Probe arbeitet niemals im Quell-Repository: Sie erzeugt ein privates temporäres Git-Repository, liest vorhandene Objekte ausschließlich über `objects/info/alternates` und verwirft anschließend dessen Objekt-Datenbank, Index, Arbeitsbaum und Konfliktdateien vollständig. Quellindex, Refs, Worktrees und Objekt-Datenbank bleiben unverändert.

Auf Git-Versionen mit `git merge-tree --write-tree` wird dieser Modus im isolierten Repository verwendet. Die Produktionsbasis Git 2.34.1 fällt ausschließlich bei einem exakt erkannten fehlenden `--write-tree`-Modus auf `merge-recursive` zurück. Der Fallback initialisiert einen temporären Index und bestimmt echte Konflikte aus dessen unmerged stages; ein fehlendes Objekt, ein ungültiger Tree-Hash, ein nicht lesbarer Index oder ein anderer interner Fehler bleibt `status: error` mit `conflicting: null`. Ein beliebiger Nichtnull-Returncode wird daher nicht mehr als Mergekonflikt ausgegeben. Ausgabe und Konfliktpfade sind begrenzt. Die Probe löst keine Konflikte und gewährt keine Merge-Autorität.

### Close

`close` akzeptiert nur die exakten Head-, Diff- und Resultat-Hashes der Collection-Receipt. Aktive Tasks blockieren standardmäßig; kontrolliertes Stoppen muss ausdrücklich aktiviert werden. Die tmux-Session kann entfernt werden. Eine erfolgreiche Lease-Freigabe wird erst behauptet, wenn eine anschließende Live-Beobachtung bestätigt, dass keiner der erwarteten Workspace-Schlüssel mehr aktiv ist. Verbleibende Schlüssel oder ein nicht beobachtbarer Freigabeausgang bleiben als persistente, nicht idempotente Recovery-Zustände blockiert; ein verlorener Rückkanal allein widerlegt eine live bestätigte Freigabe dagegen nicht.

Fehlen in einer als vollständig markierten Collection-Receipt strukturell gebundene Tests- oder Review-Belege, blockiert `close` stets mit `incomplete_role_evidence`; ein solcher Zustand kann weder als Erfolg noch als bewusste Aufgabe geschlossen werden. Enthält eine vollständige Collection-Receipt eine fehlgeschlagene Tests- oder Review-Rolle (kein `passed`-Status, kein `PASS`-Verdict ohne Findings), blockiert `close` standardmäßig mit `failed_roles_require_explicit_abandonment` und nennt die betroffenen Rollen. Erst der zusätzliche, standardmäßig auf `false` gesetzte Parameter `abandon_failed_roles=true` erlaubt das Schließen eines solchen Workspace; die Close-Receipt trägt dann `closure_outcome: "abandoned_failed_roles"` statt `"successful"` sowie die Liste der abgebrochenen Rollen. Diese Erweiterung ist rückwärtskompatibel: Ein Workspace ohne fehlgeschlagene Rolle schließt wie zuvor ohne den neuen Parameter.

Auch `close`-Antworten tragen dieselbe maschinenlesbare `external_closeout_checklist` wie `collect`.

Writer-Branch, Writer-Worktree und gegebenenfalls der materialisierte Patch werden in v1 immer erhalten. Dadurch kann `close` keine ungesicherten Änderungen verwerfen. Eine spätere Archivierung oder Entfernung erfolgt separat über die bestehenden Checkout-Werkzeuge.

### Ausführungsmodell

Agent Workspace v1 erzeugt keine vier Kopien des aktuellen ChatGPT-Kontexts. Captain ist eine Operatoransicht; Writer, Tests und Review sind Prozess-Slots für explizit gebundene Kommandos. Der Standard für Grabowski-Arbeit ist **operator-nativ und direct-first**: Derselbe ChatGPT-Operator verantwortet Liveprüfung, Aufgabenzerlegung, jede autoritative Codeänderung, Tests, kritischen Review, Integration, Merge, Deployment, Closeout und Recovery mit einem gemeinsamen Gesamtkontext. Externe Modelle dürfen nur unabhängige Reviews oder ausdrücklich angeforderte isolierte Kontrast- beziehungsweise Wettbewerbspatches liefern. Aufgabengröße und Kapazität legitimieren keine Writer-Delegation. Der Workspace wird daher nur als Isolation für diesen beratenden Ausnahmeweg genutzt.

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

## Workspace Routing v3.0 — Direct-first

`grabowski_agent_execution_route` ordnet Aufgaben weiterhin den Risikostufen R0 bis R3 zu, aber die Risikostufe verändert den autoritativen Ausführer nicht. Für jede neue Aufgabe lautet `execution_mode=direct_operator`. Große, lang laufende oder sicherheitskritische Arbeit wird durch ChatGPT/Grabowski zerlegt, in eigene Worktrees und Tests isoliert und selbst integriert.

Externe Kandidaten entstehen nur, wenn `user_requested_external=true`, eine echte Designunsicherheit vorliegt und mindestens ein geeigneter Agent verfügbar ist. Die konkrete externe Modellwahl stammt aus dem kanonischen Coding-Agent-Katalog und wird zusätzlich als `external_route_candidates` mit `route_id`, Harness, Modell, Paid-Klassifikation und Katalog-SHA-256 ausgegeben. Ein Kandidat ergibt `workspace_with_contrast`; zwei Kandidaten mit zusätzlichem `decision_fork=true` und mindestens zwei Architekturhypothesen ergeben `workspace_with_competition`. Diese Werte beschreiben ausschließlich einen beratenden Nebenpfad, nicht die empfohlene Hauptausführung. Der kostenfreie Frontier-Pfad bevorzugt Codex über `codex-sol-high`, kann aber bei besserem Aufgabenfit oder Quota-Zustand auch eine andere aktivierte kostenfreie Kontrastroute wie Agy wählen. Fable wird als pay-only nur mit expliziter Paid-Autorisierung berücksichtigt.

Der Parallel-Writer-Pilot ist unter Direct-first dauerhaft nicht ausführbar: `eligible_for_assessment=false`, `execution_authorized=false` und `workspace_group_implemented=false`. Weder Umfang noch Laufzeit noch fremde Aktivität können diese Sperre aufheben.

Route-Evidenzschema 2 bindet weiterhin Policy-Version, Risikostufe, Direct-first-Entscheidung, externe Kandidaten und den gesperrten Parallel-Writer-Status an die `recommendation_id`. Die `recommendation_id` bindet nun zusätzlich die katalogbasierten `external_route_candidates`, den Kontrast-Katalog-SHA-256 und die Paid-Autorisierungsentscheidung. Ein neuer Agenten-Workspace verlangt vollständig verifizierte schema-v2-Evidenz, eine ausdrückliche externe Anforderung, mindestens einen beratenden Kandidaten und einen zur Kandidatenzahl passenden tatsächlichen Kontrast- oder Wettbewerbsmodus. `full_workspace` ist für neue schema-v2-Erzeugungen unzulässig.

Das Workspace-Routenevidenzschema bleibt dabei bewusst **Schema 2**. Davon getrennt verwendet der kanonische `grabowski_agent_competition_start` für einen konkreten kataloggebundenen Candidate **Schema 3** für Packet, Manifest und Receipt. Dieses Candidate-Schema bindet `route_id`, Katalog-SHA-256, Harness, Modell, Effort, Permission-Modus, Quota-Pools und Paid-Klassifikation bis zum Receipt durch. Legacy-Candidates ohne Route-ID bleiben als Schema 1/2 lesbar.

Schema-1-Evidenz wird weiterhin mit der ursprünglichen Routinglogik validiert. Dadurch bleiben vorhandene Workspace-Manifeste, historische `full_workspace`-Receipts und frühere Outcome-Belege lesbar, ohne neue Autorität zu erhalten. Schattenkalibrierung darf historische oder beratende Ergebnisse auswerten, verändert aber weder die Direct-first-Regel noch die Live-Route.

## Evidence-bound outcomes and observer v3

`grabowski_agent_execution_route` returns a deterministic `recommendation_id` bound to the direct-first policy version, risk tier, normalized score, `direct_operator` recommendation, normalized input facts, advisory provider-level candidate plan and disabled parallel-writer assessment. Legacy schema-1 evidence retains its original hash contract. New workspace creation accepts only complete schema-2 evidence for an explicitly requested advisory contrast or competition route; the create path replays and rehashes this provider-level workspace decision before any mutation. Concrete `external_route_candidates`, catalog identity and Paid-Autorisierung are a separate advisory projection and are not part of the Workspace-Schema-2 hash, because their eligibility depends on mutable quota/runtime state. A concrete Candidate start resolves the chosen `route_id` again against the current canonical catalog and binds route ID, catalog SHA-256, Paid-Klassifikation, Budget, Permission-Modus and Runner-Vertrag in schema-3 packet/manifest/receipt artifacts. Existing v1 manifests without route evidence remain readable and closeable as `legacy_absent`, but they do not authorize new external writer work.

Collection and close publish separate immutable, hash-addressed outcome receipts named `outcome-receipt.<phase>.<bound-identity>.json`. Collection receipts are keyed by `result_sha256`; close receipts by the close-receipt hash. A repeated collection after an allowed read-role retry creates another file and appends a manifest history entry instead of overwriting earlier evidence. Each outcome records route evidence, first-pass and final role results, retry counts, elapsed time, known mutating workspace calls, frozen result identity, integration-or-salvage state and external closeout status. Missing required fields remain listed in `missing_fields`; `evidence_complete` stays false rather than inferring success. Read-only connector call counts and external integration truth are explicitly outside the receipt's authority.

Observer schema v3 extends the cohort-bound metrics with observed writer wait, test and review durations, validation wall time and explicit operator-intervention counts. It records unavailable external cost and integration evidence as unavailable rather than estimating it. Observer schema v2 already recovered writer head, base and diff identity from an integrity-bound collection receipt when live Git state is unavailable. Legacy failure classification is conservative: only a missing module that exactly matches the declared `python -m <module>` command, or a missing executable named in a 126/127 receipt, becomes `environment_toolchain_failure`. An unrelated application import failure remains `semantic_test_failure`. Success classifications such as `already_succeeded` are never emitted as failures.

Optional external closeout evidence must be one SHA-256-bound envelope tied to the workspace ID, current collection result, writer head, diff and current close receipt, with explicitly named sources of truth. It may resolve only the named checklist items and remains caller-supplied; a valid self-hash does not turn it into independent GitHub, Bureau, checkout or operator verification.

The optimizer counts only actionable failure classes from present, integrity-valid event logs. Legacy receipt classifications remain diagnostic in observer reports but absent or invalid event logs, success states and unknown external closeout are excluded from optimizer evidence. A proposal requires the same actionable class in at least two distinct workspaces and reports sample size, expected benefit, regression risk and a normal reviewed validation plan. No observer or optimizer result grants mutation, retry, merge, deployment or Bureau authority.

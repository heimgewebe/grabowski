# Chronik First – Grabowski-Agenteneinstieg

Der bestehende kanonische Chronik-Ledger wird ausschließlich über die
vorhandene read-only Grabowski-Vollsuche gelesen. Keine zweite Datenhaltung,
kein zusätzlicher Dienst und keine neue Autorisierungsgrenze.

## Nachweisbare Funktion

Wenn ein aufrufender Agent einen ausdrücklichen Zielselektor übergibt
(Repository-Slug, Host, Komponentenname, PR), führt der
Grabowski-Agent-Bootstrap vor seinen weiteren Beobachtungen einmal
grabowski_chronik_full_search mit maximal zehn Treffern aus. Der Rückgabewert
chronik_first enthält nur geprüfte zeitgebundene Event-Referenzen,
SHA-256-Bindungen, Operationen, Outcomes und Belegreferenzen sowie
Trefferzahl, Snapshot-Hash und den Hinweis auf weitere Treffer.
Unbekannte Felder des Quellereignisses werden nicht in die Agentenkapsel
übernommen.

Ohne Ziel wird keine Suchanfrage ausgelöst. Ist Chronik nicht verfügbar
oder die Integrität nicht verifiziert, liefert der Bootstrap
historical_context_unavailable und setzt die zulässige Arbeit fort.
Aktuelle Git-, CI-, Runtime- oder Review-Wahrheit wird nie durch alte
Ereignisse ersetzt.

## Gezielter Aufruf

grabowski_agent_bootstrap(repo="heimgewebe/grabowski")
grabowski_agent_bootstrap(host="heim-pc", subject_component="rustdesk")
grabowski_agent_bootstrap(repo="heimgewebe/grabowski", pr_number=1724)
grabowski_agent_bootstrap(task_id="<bekannte Task-ID zur Incident-Fortsetzung>")

Die zugrunde liegende Vollsuche unterstützt weitere Selektoren,
Cursor und Pagination. Das Bootstrap-Budget bleibt bewusst auf zehn
Treffer pro zielgebundenem Einstieg beschränkt.

Repository-Kontext akzeptiert ausschließlich `subject.repo` als Arbeitsziel.
`source.repo` bezeichnet den Ereignisproduzenten; bei Grabowski steht dort
auch für fremde Repositories und Host-Aufgaben `heimgewebe/grabowski`.
Die kanonische Vollsuche behält ihren bestehenden Vertrag (Quelle oder Ziel).
Der Bootstrap verwirft deshalb reine Quelltreffer vor der Kontextübernahme.
`provider_matching_count` ist die ungefilterte Kandidatenzahl. Bei weiteren
Kandidatenseiten bleibt `matching_count` unbekannt, `selection_complete=false`
und `context_gap=bounded_candidate_page_only`. Eine leere erste Seite beweist
keine fehlende Historie. Für vollständige Recherche die bestehende Vollsuche
mit Snapshot-gebundenem Cursor verwenden; es gibt keinen automatischen Retry.

## Nicht beanspruchte Fähigkeiten

Der Code sorgt für echte historische Evidenz **im zielgebundenen
Bootstrap-Aufruf**, nicht für eine unsichtbare Ausführung beim Start
jedes externen CLI-Prozesses. Die bestehende allgemein aufrufbare
grabowski_task_start-Schnittstelle ruft diesen Bootstrap noch nicht
automatisch auf. Ein neues ChatGPT-Gespräch kann mit Repository-Code
nicht gestartet, sein Plugin nicht installiert oder seine
Projektanweisungen nicht geändert werden. All dies benötigt einen
separaten Plattformnachweis.

An der tatsächlichen `grabowski_task_start`-Grenze werden argv, Chronik-Kontext,
Ressourcen und Operation für Wiederverwendung und Retry gebunden. Eine dort
eingefügte dynamische CLI-Prompt-Erweiterung würde ohne geprüften Vertrag für
jede CLI Argumentsemantik, Datenschutz und Ausführungsidentität gefährden.
Deshalb erfolgt keine automatische Injektion. Aufrufer müssen den expliziten
Bootstrap vor ihrer Arbeit lesen und seine Referenzen in ihrem Kontext behalten.
Die globale Anforderung „historischer Kontext bei jedem Agentenstart“ bleibt
damit unerfüllt; die Einstiegskapsel ist keine technische Durchsetzung davon.

Die Live-Runtime muss erst eine Version mit diesen Änderungen
bereitstellen. Erfolg der Unit-Tests allein ist kein Nachweis für
Produktivdeployment oder für tatsächliche Nutzung im neuen Chat.

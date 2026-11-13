# Chronik First – Grabowski-Agenteneinstieg

Der bestehende kanonische Chronik-Ledger wird ausschließlich über die
vorhandene read-only Grabowski-Vollsuche gelesen. Keine zweite Datenhaltung,
kein zusätzlicher Dienst und keine neue Autorisierungsgrenze.

## Nachweisbare Funktion

Wenn ein aufrufender Agent einen ausdrücklichen Zielselektor übergibt
(Repository-Slug, Host, Komponentenname, PR), führt der
Grabowski-Agent-Bootstrap vor seinen weiteren Beobachtungen bis zu zwei
unabhängige gezielte Chronik-Vollsuchen mit je maximal zehn Treffern aus:
eine repository-scoped Suche nach Repository-Slug und eine host-scoped
Suche nach der Komponente, die üblicherweise den Repository-Basename trägt.
Bei PR-Anfragen wird dieselbe PR-Nummer in beiden Suchen verwendet.
Einträge werden anhand ihrer Ereignisreferenz dedupliziert. Host-Ereignisse
werden als heuristische Komponentenzuordnung gekennzeichnet, denn sie
enthalten keinen beweiskräftigen Repository-Slug. Der Rückgabewert
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

## Wissenseinträge (knowledge.ledger)

Zusätzlich zu den Laufereignissen enthält `chronik_first.knowledge` bis zu
acht Einträge aus dem semantischen `knowledge.ledger` (bestätigte Ursachen,
Reparaturen, Entscheidungen, Widerlegungen, offene Probleme) zum Repository
(`subject.repo`) oder – ohne Repository – zum Host.
Eine explizite Zielkomponente wird über Chroniks bestehenden `--component`-
Filter **vor** dem 20er-Seitenlimit eingeschränkt; so verschwinden ältere,
relevante Ursachen nicht hinter fremden Komponenten. Eine PR-Nummer bleibt
hingegen eine nachträgliche harte Einschränkung und kann auf einer begrenzten
Kandidatenseite weiterhin Lücken ergeben. Aktuelle Einträge stehen vor
überholten (`superseded_by` nicht leer); überholte bleiben als Historie
sichtbar. Aussagen werden auf 400 Zeichen gekürzt, Quellfelder außerhalb der
kompakten Auswahl werden nicht übernommen.

Gelesen wird über dieselbe schreibfreie Sandbox wie bei der Vollsuche
(`tools/knowledge_ledger.py search`); es gibt **kein neues MCP-Werkzeug** und
keine neue Autorität. Ein Ausfall erscheint als
`knowledge.status=knowledge_context_unavailable` und ändert den Status der
Laufereignisse nicht. Eine Task-ID allein ist kein Wissensselektor
(`skipped_no_supported_selector`). Für die vollständige Wissensrecherche die
Chronik-CLI `knowledge_ledger.py search` verwenden.

### Repositorienübergreifende Ursachenrecherche ohne bekanntes Zielrepo

Das vorhandene MCP-Werkzeug `grabowski_chronik_full_search` verwendet
standardmäßig `ledger="agent.ledger"` und sucht ausschließlich
**Laufereignisse**. Null Treffer dort sind kein Beleg, dass Chroniks
semantisches `knowledge.ledger` keine Ursachen, Reparaturen oder Entscheidungen
enthält. Für einen unbekannten zuständigen Repository-Bereich kann dasselbe
read-only Werkzeug nun ausdrücklich den semantischen Korpus wählen:

`grabowski_chronik_full_search(ledger="knowledge.ledger", keyword="libgit2", limit=10)`

Im semantischen Modus gelten nur `repo`, `host`, `subject_component` (das
kanonische `subject.component`), `keyword`, `knowledge_type` und ein Limit von
1–20. Laufereignisfilter, PR-Nummer, Zeitfenster, `event_id` und Cursor werden
abgewiesen statt still ignoriert. Es gibt keinen automatischen Wechsel zwischen
den Ledgers, keinen zusätzlichen MCP-Toolnamen und keine Schreibbefugnis.
Der vorhandene Knowledge-Provider liefert Snapshot-Integrität und
`has_more`; eine begrenzte Trefferseite bedeutet weiterhin keine vollständige
Geschichte. Für die danach benötigten aktuellen Code-/Abhängigkeitsbelege
zuerst Git, optional die kleinste passende revisionsgebundene RepoGround-S1-
Abfrage und für Betrieb GitHub/CI/Runtime verwenden.

## Gezielter Aufruf

grabowski_agent_bootstrap(repo="heimgewebe/grabowski")
grabowski_agent_bootstrap(host="heim-pc", subject_component="rustdesk")
grabowski_agent_bootstrap(repo="heimgewebe/grabowski", pr_number=1724)
grabowski_agent_bootstrap(task_id="<bekannte Task-ID zur Incident-Fortsetzung>")

Die zugrunde liegende Vollsuche unterstützt weitere Selektoren,
Cursor und Pagination. Das Bootstrap-Budget bleibt bewusst auf zehn
Treffer pro Query und zehn Ereignisse im Gesamtergebnis beschränkt.
Wenn eine Kandidatenseite unvollständig ist, bleibt selection_complete=false
und context_gap=bounded_candidate_page_only. Unterschiedliche Snapshots der
beiden Suchscopes führen zu ledger_snapshot_changed_between_scopes.
Bei zugeordneten Host-Ereignissen wird ein
host_component_attribution_heuristic-Kontextvorbehalt ausgewiesen.
Fehlt einer der Scopes, darf nicht behauptet werden, die Historie sei vollständig.
Die Query- und Snapshot-Belege bleiben pro Scope erhalten.

Repository-Kontext akzeptiert `subject.repo` als Arbeitsziel.
`source.repo` bezeichnet den Ereignisproduzenten; bei Grabowski steht dort
auch für fremde Repositories und Host-Aufgaben `heimgewebe/grabowski`.
Die kanonische Vollsuche behält ihren bestehenden Vertrag (Quelle oder Ziel).
Der Bootstrap verwirft deshalb reine Quelltreffer vor der Kontextübernahme.
Passende Host-Ereignisse bleiben dagegen mit dem expliziten
match_basis=host_component_heuristic als historische Hinweise erhalten.
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

# Repo-Audit 2026-07

Vollständiges Repository-Audit vom 2026-07-02. Baseline vor dem Audit:
`make validate` grün, 345 Tests OK auf `main` (`59cec34`). Das Audit umfasste
Quellcode (`src/`, `tools/`), Tests, Build/CI (Makefile, pyproject, Workflow,
Lockfiles), Verträge (`contracts/`, `config/`), systemd-/Deploy-Artefakte und
alle Dokumente. Geprüft wurden statische Analyse (pyflakes), doppelte
Definitionen, riskante Muster (shell=True, bare except, mutable defaults),
Markdown-Linkintegrität, Tool-Contract-Parität (`runtime-entrypoint.json`
gegen deklarierte MCP-Tools, 91/91 deckungsgleich) und Status-Claims der
Roadmap gegen den Code.

## Behobene Fehler

1. **rLens Stem-zu-Repo-Mapping** (`src/grabowski_mcp.py`,
   `_rlens_repo_from_stem`): Der `-full-max-`-Zweig war unerreichbar, weil
   jeder `-full-max-`-Stem auch `-max-` enthält und der `-max-`-Zweig zuerst
   griff. Folge: `repo-full-max-…`-Bundles wurden dem Phantom-Repo
   `repo-full` zugeordnet; der Discovery-Filter verfehlte sie und
   `rlens_context_pack` lehnte sie mit `bundle_repo_mismatch` ab.
   Fix: Reihenfolge der Prüfungen getauscht; Regressionstest ergänzt.
2. **Patch-Relay `--three-way` wirkungslos**
   (`tools/operator_patch_relay.py`): Der Gate-Schritt lief immer als
   `git apply --check` ohne `--3way`. Patches, die nur per 3-Way-Merge
   anwendbar sind, scheiterten dadurch vor dem Apply — der Flag konnte nie
   helfen (reproduziert mit git 2.43). Fix: `--3way` wird an den Check
   durchgereicht; Regressionstest mit verschobenem Kontext ergänzt.
3. **Friction-Ledger Doppel-Close** (`src/grabowski_friction.py`,
   `_append_jsonl`): Der File-Deskriptor wurde durch den
   `os.fdopen`-Kontextmanager geschlossen und anschließend erneut per
   `os.close` — unter nebenläufigen Tool-Aufrufen ein fd-Reuse-Risiko.
   Fix: `os.close` nur noch im Fehlerpfad vor erfolgreichem `fdopen`.
4. **`friction_summary` bricht bei korrupter Logzeile hart ab**: Eine einzige
   nicht parsebare Zeile machte die gesamte Zusammenfassung unbrauchbar.
   Fix: defekte Zeilen werden übersprungen und sichtbar als `invalid_lines`
   gezählt; Verhaltenstests ergänzt.
5. **Deploy-Fehler ohne Phasenangabe** (`tools/deploy_runtime_dual.py`): Der
   `phase`-Fortschrittsmarker wurde gepflegt, aber im Fehlerpfad nie
   ausgegeben; `PRIMARY-DEPLOY-ERROR` verlor die Information, welche Phase
   scheiterte. Fix: Phase ist Teil der Fehlerzusammenfassung (eine
   spezifischere `DeployError`-Phase behält Vorrang).
6. **CHANGELOG mitten im Satz abgeschnitten**: Die Schlusszeile
   "audit, protected-root and kill-switch gates." wurde in Commit `879b6a1`
   versehentlich gelöscht. Wiederhergestellt; zusätzlich fehlten Einträge für
   Friction-Ledger, Operator Relay/Patch-Relay, Safety Observer,
   rLens-Tools, Operator-Completion und Watchdog-Budgets — ergänzt.

## Behobene Inkonsistenzen

7. **Makefile `syntax`-Lücken**: `src/grabowski_friction.py`,
   `tools/check_no_secrets.py`, `tools/component_watchdog.py`,
   `tools/grabowski_safety_observer.py`, `tools/validate_access_policy.py`
   und `tools/verify_tooling_venv.py` wurden nicht kompiliert. Fix: das
   Target nutzt jetzt `$(wildcard src/*.py) $(wildcard tools/*.py)` und kann
   nicht mehr veralten; der Contract-Test prüft die Wildcards.
8. **`pyproject.toml` unvollständig**: `py-modules` nannte 2 von 21 Modulen;
   eine Paketinstallation hätte eine kaputte Importfläche erzeugt. Fix: alle
   `src/`-Module deklariert.
9. **Roadmap ohne Statuszeilen**: `GIT-001`, `KNOWLEDGE-001`, `OPS-001`,
   `FLEET-001` und `DEPLOY-002` trugen keinen Status; `KNOWLEDGE-001`
   ignorierte die gelandeten rLens-Slices. Fix: Statuszeilen ergänzt und mit
   dem Code-Stand abgeglichen.
10. **Unbenutzte Importe**: `os` in `src/grabowski_read_surface.py`, `sys` in
    `tools/operator_patch_relay.py`. Entfernt. (Die scheinbar unbenutzten
    Importe in `src/grabowski_runtime.py` sind beabsichtigt: das Modul ist
    das Import-Aggregat des deployten Layouts.)
11. **Board-Drift**: Die Roadmap-Issues spiegelten den Implementierungsstand
    nicht (u. a. war der Operator-Bootstrap aus Issue #9 vollständig live).
    Statuskommentare bzw. Schließung erfolgen auf den GitHub-Issues.

## Offene Empfehlungen (bewusst nicht umgesetzt)

- **CI-Matrix um Python 3.13 erweitern**: sinnvoll als Frühwarnung, aber
  lokal nicht verifizierbar (kein 3.13-Interpreter); erfordert einen
  CI-Durchlauf inkl. `deploy-check`-Wheel-Auflösung, bevor es Pflicht wird.
- **Strukturierte Timeout-Ergebnisse für rLens-Subprozesse**: `_rlens_git`
  (timeout=10) und der Lenskit-Preflight (timeout=30) lassen
  `subprocess.TimeoutExpired` bis zum MCP-Fehler durchschlagen. Ein
  strukturiertes `"unknown"`-Ergebnis wäre für Read-Tools freundlicher;
  fail-visible ist aber vertretbar, daher nur Empfehlung.
- **`changed_files` im Patch-Relay** basiert auf `git diff --name-only` und
  listet neu angelegte (untracked) Dateien nicht; `status_after` deckt sie
  ab. Kosmetik, kein Fehler.

## Nicht-Befunde

Keine Duplikat-Definitionen, keine `shell=True`/`eval`/bare-except-Muster,
keine mutablen Default-Argumente, keine kaputten Markdown-Links, keine
JSON-Syntaxfehler in `contracts/` und `config/`, Tool-Contract und
Deklarationen deckungsgleich, Lockfiles konsistent, keine offensichtlichen
Secrets. Die Kernaussagen von README, GRABOWSKI.md, SECURITY.md und
`docs/autonomy.md` decken sich mit dem Code.

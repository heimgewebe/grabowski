# Gate-Evidence- und Konvergenz-Griffe v1

## Zweck

Wiederholte Fail-closed-Sperren sollen nicht durch Policy-Ausnahmen oder unveränderte Wiederholungen umgangen werden. Zwei read-only-Griffe bereiten stattdessen Belege vor und trennen historische Zustandsbedeutungen.

## `gate-evidence-preflight`

Der Griff verlangt einen benannten Gate-Eigentümer, eine unveränderliche Policy-Grenze, Ziel, Scope, erwartete Identität sowie sechs Evidenzklassen: Leases, Dirty-State, laufende Arbeit, Receipt, Akzeptanz und Post-State-Readback. Evidenzreferenzen werden nur gehasht ausgegeben.

Ein erneuter Versuch nach einer früheren Ablehnung ist nur vorbereitet, wenn eine benannte Evidenz- oder Zielzustandsänderung vorliegt. Ein positives Ergebnis bedeutet ausschließlich, dass die Eingabe für eine erneute Gate-Auswertung vollständig ist.

Der Griff erteilt insbesondere keine Ausführungsautorität, keinen Policy-Bypass, keine sichere Mutationswiederholung und keinen Gate-Pass.

## `convergence-state-classify`

Der Griff klassifiziert bis zu 100 explizit evidenzgebundene Datensätze als `defect`, `expected`, `blocked`, `superseded`, `resolved`, `unknown` oder `conflicted`. Widersprüchliche erwartete und blockierende Evidenz wird nicht geglättet. Terminale Resolution darf frühere nichtterminale Fehlersignale erklären; gleichzeitig vorliegende Resolution und Supersession bleibt konfliktbehaftet.

Die Projektion schreibt keine Historie um, schließt keine Tasks und ändert keine Prioritäten. Sie ist für kontrollierte Altbestandsbereinigung und Bureau-Entscheidungen gedacht.

from __future__ import annotations

import html
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .models import Snapshot


CSS = """
:root { color-scheme: light dark; font-family: -apple-system, BlinkMacSystemFont, system-ui, sans-serif; }
body { margin: 0; padding: 18px; background: #111318; color: #f2f4f8; }
header { display:flex; gap:12px; align-items:flex-end; justify-content:space-between; margin-bottom:16px; }
h1 { font-size: 28px; margin:0; }
.subtle { color:#aeb6c2; font-size:13px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:12px; }
.card { background:#1b1f27; border:1px solid #303744; border-radius:14px; padding:14px; overflow:hidden; }
.card h2 { font-size:17px; margin:0 0 10px; }
.badge { display:inline-block; padding:3px 8px; border-radius:999px; font-size:12px; font-weight:700; }
.healthy { background:#173c2b; color:#8ce3b4; }
.warning { background:#463618; color:#f7ce78; }
.unreachable { background:#4b2025; color:#ff9ba5; }
.unknown,.stale { background:#323642; color:#c9d0dc; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th,td { text-align:left; padding:7px 5px; border-bottom:1px solid #303744; vertical-align:top; }
code { word-break:break-all; font-size:12px; }
details { margin-top:8px; }
pre { white-space:pre-wrap; max-height:280px; overflow:auto; background:#0d0f13; padding:10px; border-radius:8px; font-size:11px; }
@media (prefers-color-scheme: light) { body {background:#f5f7fa;color:#17202a}.card{background:#fff;border-color:#d8dee8}.subtle{color:#5d6877}th,td{border-color:#e0e5ec}pre{background:#f0f2f5} }
"""


def _fmt_bytes(value: Any) -> str:
    if not isinstance(value, int):
        return "–"
    units = ["B", "KB", "MB", "GB", "TB"]
    amount = float(value)
    for unit in units:
        if abs(amount) < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return str(value)


def _storage_html(data: dict[str, Any]) -> str:
    rows = []
    for root in data.get("roots", []):
        disk = root.get("disk", {})
        rows.append(
            "<tr>"
            f"<td><strong>{html.escape(str(root.get('label')))}</strong><br><code>{html.escape(str(root.get('path')))}</code></td>"
            f"<td>{'ja' if root.get('readable') else 'nein'}</td>"
            f"<td>{'ja' if root.get('writable_hint') else 'nein'}</td>"
            f"<td>{_fmt_bytes(disk.get('free_bytes'))}</td>"
            f"<td>{html.escape(str(root.get('entry_count_observed', 0)))}</td>"
            "</tr>"
        )
    return "<table><thead><tr><th>Bereich</th><th>Lesen</th><th>Schreiben</th><th>Frei</th><th>Einträge</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def _targets_html(data: dict[str, Any]) -> str:
    rows = []
    for target in data.get("targets", []):
        result = target.get("result", {})
        detail = result.get("status_code", result.get("peer", target.get("error", "–")))
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(target.get('label')))}</td>"
            f"<td><span class='badge {html.escape(str(target.get('status')))}'>{html.escape(str(target.get('status')))}</span></td>"
            f"<td>{html.escape(str(detail))}</td>"
            "</tr>"
        )
    return "<table><thead><tr><th>Ziel</th><th>Status</th><th>Beleg</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def render(snapshot: Snapshot, destination: Path) -> Path:
    cards: list[str] = []
    for result in snapshot.results:
        if result.source == "storage":
            body = _storage_html(result.data)
        elif result.source == "targets":
            body = _targets_html(result.data)
        else:
            body = "<pre>" + html.escape(json.dumps(result.data, ensure_ascii=False, indent=2, sort_keys=True)) + "</pre>"
        messages = "".join(f"<div class='subtle'>{html.escape(message)}</div>" for message in (*result.warnings, *result.errors))
        cards.append(
            f"<section class='card'><h2>{html.escape(result.source)} <span class='badge {result.status}'>{result.status}</span></h2>"
            f"<div class='subtle'>Beobachtet: {html.escape(result.observed_at)}</div>{messages}{body}"
            f"<details><summary>Rohdaten</summary><pre>{html.escape(json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))}</pre></details></section>"
        )
    document = f"""<!doctype html><html lang='de'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Juno Operator</title><style>{CSS}</style></head><body><header><div><h1>Juno Operator</h1><div class='subtle'>Lokaler Read-only-Leitstand</div></div><div><span class='badge {snapshot.overall_status}'>{snapshot.overall_status}</span><div class='subtle'>{html.escape(snapshot.generated_at)}</div></div></header><main class='grid'>{''.join(cards)}</main></body></html>"""
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(document)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return destination

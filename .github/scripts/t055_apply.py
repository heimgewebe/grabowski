from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def update_runtime_manifest() -> None:
    path = ROOT / "config" / "runtime-entrypoint.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    items = payload["supporting_sources"]
    modules = [item["module"] for item in items]

    if "grabowski_alert_outbox" in modules:
        raise SystemExit("grabowski_alert_outbox is already packaged")
    try:
        index = modules.index("grabowski_ntfy_dispatch")
    except ValueError as exc:
        raise SystemExit("grabowski_ntfy_dispatch anchor is missing") from exc

    items.insert(
        index,
        {
            "module": "grabowski_alert_outbox",
            "source": "src/grabowski_alert_outbox.py",
        },
    )
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def update_repository_contract_test() -> None:
    path = ROOT / "tests" / "test_repository_contract.py"
    text = path.read_text(encoding="utf-8")
    anchor = '            "grabowski_ntfy_dispatch",\n'
    replacement = '            "grabowski_alert_outbox",\n' + anchor

    if replacement in text:
        raise SystemExit("repository contract already packages alert outbox")
    if text.count(anchor) != 1:
        raise SystemExit("repository-contract anchor is not unique")

    path.write_text(text.replace(anchor, replacement, 1), encoding="utf-8")


def update_documentation() -> None:
    path = ROOT / "docs" / "ntfy-alert-outbox-v1.md"
    text = path.read_text(encoding="utf-8")
    old = """The runtime-entrypoint manifest is intentionally outside this change. The
integration therefore loads the packaged alert module through an optional
boundary. If an older deployed source set does not contain the module,
terminal-job dispatch continues and reports `alert_outbox_unavailable` with an
explicit `alert_outbox_empty` non-claim; producer transitions remain primary
and do not fail during a staggered package rollout.
"""
    new = """The runtime-entrypoint manifest packages `grabowski_alert_outbox` alongside
the shared dispatcher and producer modules. The optional import boundary
remains a staggered-rollout safeguard only: an older deployed source set may
continue terminal-job dispatch and report `alert_outbox_unavailable`, but the
canonical current runtime contract includes the alert module. Producer
transitions remain primary and do not fail if an incomplete historical source
set is observed.
"""

    if old not in text:
        raise SystemExit("documentation rollout paragraph does not match expected base")

    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    update_runtime_manifest()
    update_repository_contract_test()
    update_documentation()


if __name__ == "__main__":
    main()

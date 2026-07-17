#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from juno_operator.app import create_incident, refresh


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh the local Juno Operator dashboard")
    parser.add_argument("--incident", action="store_true", help="also create a bounded incident package")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    snapshot, dashboard = refresh(root)
    print(f"Juno Operator: {snapshot.overall_status}")
    print(f"Dashboard: {dashboard}")
    if args.incident:
        print(f"Incident: {create_incident(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

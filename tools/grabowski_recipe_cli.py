#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import grabowski_operations as recipes

parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=["list", "plan", "run"])
parser.add_argument("name", nargs="?")
parser.add_argument("--parameters", default="{}")
args = parser.parse_args()

try:
    if args.mode == "list":
        raw = recipes._load()
        result = {name: recipes._validated(name)["description"] for name in sorted(raw["operations"])}
    elif args.mode == "plan":
        result = recipes._render(args.name, json.loads(args.parameters))
    else:
        result = recipes.grabowski_operation_run(args.name, json.loads(args.parameters))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
except Exception as exc:
    print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
    raise SystemExit(2)

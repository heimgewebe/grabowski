#!/usr/bin/env python3
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import grabowski_privileged as privileged

try:
    print(json.dumps(privileged.grabowski_privileged_broker_status(), sort_keys=True))
except Exception as exc:
    print(json.dumps({"error": str(exc)}, sort_keys=True))
    raise SystemExit(2)

#!/usr/bin/env python3
"""Proposal-only operator-routing shadow capture CLI.

The implementation lives in ``src/grabowski_operator_routing_shadow_capture.py`` so
workspace-adjacent prospective cohort capture and the CLI share one record logic.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_operator_routing_shadow_capture as _capture_core  # noqa: E402
from grabowski_operator_routing_shadow_capture import *  # noqa: F401,F403,E402

ShadowCaptureError = _capture_core.ShadowCaptureError
_build_parser = _capture_core._build_parser
_read_regular_json = _capture_core._read_regular_json
main = _capture_core.main


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ShadowCaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)

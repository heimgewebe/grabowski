from __future__ import annotations

import importlib
from typing import Any


def __getattr__(name: str) -> Any:
    return getattr(importlib.import_module("grabowski_operator"), name)

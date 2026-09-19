from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pty
import select
import signal
import stat
import time
from typing import Callable

from grabowski_privileged_broker import (
    claim_once,
    load_root_config,
    parse_reference,
    parse_transport_request,
    resolve_secret_pty_execution,
    validate_secret_pty_session_authority,
    _require_kill_switch_clear,
)

SECRET_PTY_MAX_TRANSCRIPT_BYTES = 512 * 1024
SECRET_PTY_TERMINATE_GRACE_SECONDS = 2.0
SAFE_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}

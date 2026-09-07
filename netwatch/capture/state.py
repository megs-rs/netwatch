"""Capture run-state coordination for live capture commands."""

from __future__ import annotations

import json
import os
import signal
from datetime import datetime
from pathlib import Path

DEFAULT_STATE_PATH = "~/.netwatch/capture.status"


def state_path(override: str | None = None) -> Path:
    return Path(override or DEFAULT_STATE_PATH).expanduser()


def write_state(interface: str, state_path_override: str | None = None) -> Path:
    path = state_path(state_path_override)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "pid": os.getpid(),
        "interface": interface,
        "started_at": datetime.utcnow().isoformat(),
    }
    path.write_text(json.dumps(data))
    return path


def read_state(state_path_override: str | None = None) -> dict | None:
    path = state_path(state_path_override)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def clear_state(state_path_override: str | None = None) -> None:
    path = state_path(state_path_override)
    if path.exists():
        path.unlink()


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def stop_capture(state_path_override: str | None = None) -> bool:
    """Signal a running capture process to stop. Returns True if a process was signalled."""
    state = read_state(state_path_override)
    if not state or "pid" not in state:
        return False
    pid = state["pid"]
    try:
        os.kill(pid, signal.SIGTERM)
        return True
    except ProcessLookupError:
        return False

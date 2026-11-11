"""JSON-lines run/tool logging and the stats the Monitoring tab reads.

Complements app/approval/store.py's SQLite stats (counts by type/status,
rejection rate) with per-tool latency and error tracking, per CLAUDE.md's
"Monitoring (runs, latency per tool, errors, rejection rate per type)".

Logging a line must never break the caller: every write is best-effort.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

DEFAULT_LOG_PATH = Path(os.environ.get("LOG_PATH", "app/monitoring/logs.jsonl"))


def _resolve(log_path: Optional[Path]) -> Path:
    return Path(log_path) if log_path is not None else DEFAULT_LOG_PATH


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_event(event: dict[str, Any], *, log_path: Optional[Path] = None) -> None:
    """Appends one JSON line. Swallows write failures -- logging is a
    side concern and must never take down the agent loop or the UI.
    """
    try:
        path = _resolve(log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"timestamp": _now(), **event}, default=str)
        with path.open("a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def log_run(
    finding_id: str,
    misconfig_type: str,
    duration_seconds: float,
    *,
    error: Optional[str] = None,
    log_path: Optional[Path] = None,
) -> None:
    log_event(
        {
            "event": "run",
            "finding_id": finding_id,
            "misconfig_type": misconfig_type,
            "duration_seconds": duration_seconds,
            "error": error,
        },
        log_path=log_path,
    )


def log_tool_call(
    finding_id: str, tool: str, duration_seconds: float, *, error: Optional[str] = None, log_path: Optional[Path] = None
) -> None:
    log_event(
        {
            "event": "tool_call",
            "finding_id": finding_id,
            "tool": tool,
            "duration_seconds": duration_seconds,
            "error": error,
        },
        log_path=log_path,
    )


def read_events(log_path: Optional[Path] = None, *, event: Optional[str] = None) -> list[dict[str, Any]]:
    path = _resolve(log_path)
    if not path.exists():
        return []
    events = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event is None or record.get("event") == event:
            events.append(record)
    return events


def compute_monitoring_stats(log_path: Optional[Path] = None) -> dict[str, Any]:
    runs = read_events(log_path, event="run")
    tool_calls = read_events(log_path, event="tool_call")

    run_durations = [r["duration_seconds"] for r in runs]
    errors = [r for r in runs if r.get("error")] + [t for t in tool_calls if t.get("error")]

    latency_by_tool: dict[str, list[float]] = {}
    for call in tool_calls:
        latency_by_tool.setdefault(call["tool"], []).append(call["duration_seconds"])
    avg_latency_by_tool = {tool: sum(d) / len(d) for tool, d in latency_by_tool.items()}

    return {
        "total_runs": len(runs),
        "total_errors": len(errors),
        "avg_run_seconds": sum(run_durations) / len(run_durations) if run_durations else 0.0,
        "max_run_seconds": max(run_durations) if run_durations else 0.0,
        "avg_latency_by_tool": avg_latency_by_tool,
    }

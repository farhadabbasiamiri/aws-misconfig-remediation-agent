"""SQLite-backed approval queue and audit log.

Every analyzed finding is stored here with its AgentOutput and tool-call
trace. A finding whose output has requires_approval=True starts out
"pending" until a human approves or rejects it; everything else is
"auto_approved" immediately. Every status change is also appended to an
append-only audit log, which the Export tab turns into a CSV.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from app.agent.loop import AgentRunResult
from app.schemas import AgentOutput

DEFAULT_DB_PATH = Path(os.environ.get("APPROVAL_DB_PATH", "app/approval/approvals.db"))

STATUS_AUTO_APPROVED = "auto_approved"
STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
DECIDED_STATUSES = (STATUS_APPROVED, STATUS_REJECTED)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    finding_id TEXT PRIMARY KEY,
    resource_type TEXT NOT NULL,
    region TEXT NOT NULL,
    output_json TEXT NOT NULL,
    trace_json TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class StoredResult:
    finding_id: str
    resource_type: str
    region: str
    output: AgentOutput
    trace: list[dict[str, Any]]
    status: str
    created_at: str
    updated_at: str


@contextmanager
def _connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: Optional[Path] = None) -> Path:
    """Creates the schema if needed and returns the resolved db_path.

    Every other function in this module routes its db_path through here
    first, so an explicit db_path=None (not just an omitted argument)
    still resolves to DEFAULT_DB_PATH instead of crashing on Path(None).
    """
    resolved = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    resolved.parent.mkdir(parents=True, exist_ok=True)
    with _connect(resolved) as conn:
        conn.executescript(_SCHEMA)
    return resolved


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_result(row: sqlite3.Row) -> StoredResult:
    return StoredResult(
        finding_id=row["finding_id"],
        resource_type=row["resource_type"],
        region=row["region"],
        output=AgentOutput.model_validate_json(row["output_json"]),
        trace=json.loads(row["trace_json"]),
        status=row["status"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def save_result(
    resource_type: str, region: str, run_result: AgentRunResult, *, db_path: Optional[Path] = None
) -> str:
    """Persists one analyzed finding's output and trace; returns its starting status.

    Takes resource_type/region as plain strings rather than a Finding object
    so a parse failure (which has no valid Finding) can be recorded the same
    way as a successful run -- see app/ui/controller.py.
    """
    db_path = init_db(db_path)
    output = run_result.output
    status = STATUS_PENDING if output.requires_approval else STATUS_AUTO_APPROVED
    now = _now()
    trace_json = json.dumps([asdict(t) for t in run_result.trace], default=str)

    with _connect(db_path) as conn:
        conn.execute(
            """INSERT INTO results
                   (finding_id, resource_type, region, output_json, trace_json, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(finding_id) DO UPDATE SET
                   resource_type=excluded.resource_type, region=excluded.region,
                   output_json=excluded.output_json, trace_json=excluded.trace_json,
                   status=excluded.status, updated_at=excluded.updated_at""",
            (
                output.finding_id,
                resource_type,
                region,
                output.model_dump_json(),
                trace_json,
                status,
                now,
                now,
            ),
        )
        conn.execute(
            "INSERT INTO audit_log (finding_id, action, actor, note, created_at) VALUES (?, ?, ?, ?, ?)",
            (output.finding_id, "analyzed", "agent", f"verdict={output.misconfig_type.value}", now),
        )
    return status


def list_results(db_path: Optional[Path] = None, *, status: Optional[str] = None) -> list[StoredResult]:
    db_path = init_db(db_path)
    query = "SELECT * FROM results"
    params: tuple[Any, ...] = ()
    if status:
        query += " WHERE status = ?"
        params = (status,)
    query += " ORDER BY created_at"
    with _connect(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_result(row) for row in rows]


def get_result(finding_id: str, db_path: Optional[Path] = None) -> Optional[StoredResult]:
    db_path = init_db(db_path)
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM results WHERE finding_id = ?", (finding_id,)).fetchone()
    return _row_to_result(row) if row else None


def _set_status(finding_id: str, new_status: str, actor: str, note: str, db_path: Optional[Path]) -> bool:
    db_path = init_db(db_path)
    with _connect(db_path) as conn:
        cursor = conn.execute(
            "UPDATE results SET status = ?, updated_at = ? WHERE finding_id = ?",
            (new_status, _now(), finding_id),
        )
        if cursor.rowcount == 0:
            return False
        conn.execute(
            "INSERT INTO audit_log (finding_id, action, actor, note, created_at) VALUES (?, ?, ?, ?, ?)",
            (finding_id, new_status, actor, note, _now()),
        )
    return True


def approve(finding_id: str, *, actor: str = "analyst", note: str = "", db_path: Optional[Path] = None) -> bool:
    return _set_status(finding_id, STATUS_APPROVED, actor, note, db_path)


def reject(finding_id: str, *, actor: str = "analyst", note: str = "", db_path: Optional[Path] = None) -> bool:
    return _set_status(finding_id, STATUS_REJECTED, actor, note, db_path)


def list_audit_log(db_path: Optional[Path] = None) -> list[dict[str, Any]]:
    db_path = init_db(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
    return [dict(row) for row in rows]


def get_monitoring_stats(db_path: Optional[Path] = None) -> dict[str, Any]:
    results = list_results(db_path)
    by_type: dict[str, int] = {}
    by_status: dict[str, int] = {}
    rejections_by_type: dict[str, int] = {}
    decided_by_type: dict[str, int] = {}

    for result in results:
        misconfig_type = result.output.misconfig_type.value
        by_type[misconfig_type] = by_type.get(misconfig_type, 0) + 1
        by_status[result.status] = by_status.get(result.status, 0) + 1
        if result.status in DECIDED_STATUSES:
            decided_by_type[misconfig_type] = decided_by_type.get(misconfig_type, 0) + 1
            if result.status == STATUS_REJECTED:
                rejections_by_type[misconfig_type] = rejections_by_type.get(misconfig_type, 0) + 1

    rejection_rate_by_type = {
        misconfig_type: rejections_by_type.get(misconfig_type, 0) / count
        for misconfig_type, count in decided_by_type.items()
    }

    return {
        "total_runs": len(results),
        "by_misconfig_type": by_type,
        "by_status": by_status,
        "rejection_rate_by_type": rejection_rate_by_type,
    }

"""Business logic behind the Gradio tabs, kept free of any Gradio import so
it can be tested without launching a UI.

analyze_file is the only function that drives the agent loop; everything
else just reads from or writes to the approval store app/ui/app.py wires
these onto buttons/tables.
"""

from __future__ import annotations

import csv
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from app.agent.loop import AgentRunResult, run_agent
from app.agent.mock import mock_chat_fn
from app.approval import (
    STATUS_PENDING,
    approve as _approve,
    get_monitoring_stats,
    get_result,
    list_audit_log,
    list_results,
    reject as _reject,
    save_result,
)
from app.monitoring import compute_monitoring_stats, log_run, log_tool_call
from app.parser import parse_file
from app.schemas import AgentOutput, Confidence, MisconfigVerdict

DEFAULT_MODEL = os.environ.get("MODEL_NAME", "qwen2.5:7b")


def ollama_is_available(model: str = DEFAULT_MODEL) -> bool:
    """Best-effort check used to decide whether to fall back to mock demo mode."""
    try:
        import ollama

        ollama.list()
        return True
    except Exception:
        return False


def analyze_file(
    file_path: str,
    *,
    force_mock: bool = False,
    model: str = DEFAULT_MODEL,
    collection: Any = None,
    db_path: Optional[Path] = None,
    log_path: Optional[Path] = None,
) -> dict[str, Any]:
    """Parses an uploaded file and runs the agent on every valid finding.

    Records both successfully-analyzed findings and parse failures in the
    approval store, so nothing a user uploads is silently dropped. Each
    run and tool call is also logged (app/monitoring) for the Monitoring tab.
    """
    report = parse_file(file_path)
    if report.file_error:
        return {"error": report.file_error, "analyzed": 0, "needs_review": 0, "used_mock": None}

    use_mock = force_mock or not ollama_is_available(model)

    analyzed = 0
    for finding in report.findings:
        kwargs: dict[str, Any] = {"collection": collection, "model": model}
        if use_mock:
            kwargs["chat_fn"] = mock_chat_fn
        run_start = time.perf_counter()
        result = run_agent(finding, **kwargs)
        run_duration = time.perf_counter() - run_start
        save_result(finding.resource_type.value, finding.region, result, db_path=db_path)

        for tool_trace in result.trace:
            log_tool_call(
                finding.finding_id,
                tool_trace.tool,
                tool_trace.duration_seconds,
                error=tool_trace.result.get("error") if isinstance(tool_trace.result, dict) else None,
                log_path=log_path,
            )
        # _fallback_output (app/agent/loop.py) always starts its explanation
        # with this exact prefix, regardless of which handled error it was
        # (timeout, invalid JSON, a failed call, max iterations, ...), so
        # it's a reliable way to flag the run as an error after the fact.
        is_error_fallback = result.output.explanation.startswith("Automated explanation unavailable:")
        log_run(
            finding.finding_id,
            result.output.misconfig_type.value,
            run_duration,
            error=result.output.explanation if is_error_fallback else None,
            log_path=log_path,
        )
        analyzed += 1

    for i, unparsable in enumerate(report.needs_review):
        finding_id = unparsable.finding_id or f"PARSE-ERROR-{i + 1:03d}"
        output = AgentOutput(
            finding_id=finding_id,
            misconfig_type=MisconfigVerdict.NEEDS_REVIEW,
            explanation=f"This record could not be parsed into a valid Finding: {unparsable.reason}",
            confidence=Confidence.LOW,
            requires_approval=True,
        )
        save_result("UNKNOWN", "UNKNOWN", AgentRunResult(output=output, trace=[]), db_path=db_path)

    return {
        "error": None,
        "analyzed": analyzed,
        "needs_review": len(report.needs_review),
        "used_mock": use_mock,
    }


def results_table(db_path: Optional[Path] = None) -> list[list[Any]]:
    rows = []
    for stored in list_results(db_path=db_path):
        output = stored.output
        rows.append(
            [
                output.finding_id,
                stored.resource_type,
                stored.region,
                output.misconfig_type.value,
                output.severity.value if output.severity else "",
                output.confidence.value,
                stored.status,
            ]
        )
    return rows


def finding_ids(db_path: Optional[Path] = None) -> list[str]:
    return [stored.finding_id for stored in list_results(db_path=db_path)]


def finding_detail(finding_id: str, db_path: Optional[Path] = None) -> Optional[dict[str, Any]]:
    stored = get_result(finding_id, db_path=db_path)
    if stored is None:
        return None
    output = stored.output
    return {
        "finding_id": output.finding_id,
        "resource_type": stored.resource_type,
        "region": stored.region,
        "status": stored.status,
        "misconfig_type": output.misconfig_type.value,
        "severity": output.severity.value if output.severity else "-",
        "confidence": output.confidence.value,
        "requires_approval": output.requires_approval,
        "control_ids": output.control_ids,
        "mitre_techniques": output.mitre_techniques,
        "evidence": output.evidence,
        "explanation": output.explanation,
        "remediation_steps": output.remediation_steps,
        "fix_snippet": output.fix_snippet,
        "side_effects": output.side_effects,
        "field_sources": {field: source.value for field, source in output.field_sources.items()},
    }


def agent_trace(finding_id: str, db_path: Optional[Path] = None) -> Optional[list[dict[str, Any]]]:
    stored = get_result(finding_id, db_path=db_path)
    return stored.trace if stored else None


def pending_queue(db_path: Optional[Path] = None) -> list[list[Any]]:
    rows = []
    for stored in list_results(db_path=db_path, status=STATUS_PENDING):
        output = stored.output
        rows.append(
            [
                output.finding_id,
                output.misconfig_type.value,
                output.severity.value if output.severity else "",
                output.explanation,
            ]
        )
    return rows


def approve(finding_id: str, *, actor: str = "analyst", note: str = "", db_path: Optional[Path] = None) -> bool:
    return _approve(finding_id, actor=actor, note=note, db_path=db_path)


def reject(finding_id: str, *, actor: str = "analyst", note: str = "", db_path: Optional[Path] = None) -> bool:
    return _reject(finding_id, actor=actor, note=note, db_path=db_path)


def export_audit_log_csv(db_path: Optional[Path] = None, out_path: Optional[Path] = None) -> str:
    rows = list_audit_log(db_path=db_path)
    out_path = Path(out_path or Path(tempfile.gettempdir()) / "audit_log.csv")
    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "finding_id", "action", "actor", "note", "created_at"])
        writer.writeheader()
        writer.writerows(rows)
    return str(out_path)


def export_fixes_text(db_path: Optional[Path] = None, out_path: Optional[Path] = None) -> str:
    lines: list[str] = []
    for stored in list_results(db_path=db_path):
        output = stored.output
        if not output.fix_snippet:
            continue
        lines.append(f"# {output.finding_id} - {output.misconfig_type.value} ({stored.status})")
        lines.append(f"# Side effects: {output.side_effects or 'none noted'}")
        lines.append(output.fix_snippet)
        lines.append("")
    out_path = Path(out_path or Path(tempfile.gettempdir()) / "fixes.txt")
    out_path.write_text("\n".join(lines))
    return str(out_path)


def monitoring_summary(db_path: Optional[Path] = None, log_path: Optional[Path] = None) -> dict[str, Any]:
    """Combines approval-DB stats (counts, rejection rate per type) with
    the JSON-lines log's run/tool latency and error counts.
    """
    stats = get_monitoring_stats(db_path=db_path)
    stats["logged"] = compute_monitoring_stats(log_path=log_path)
    return stats

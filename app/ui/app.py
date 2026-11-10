"""Gradio Blocks UI: Analyze, Results, Finding Detail, Agent Trace,
Approval Queue, Export, Monitoring.

All the actual logic lives in app/ui/controller.py; this module is just
widget wiring, kept thin on purpose so the logic stays testable without
launching Gradio.
"""

from __future__ import annotations

from typing import Any

import gradio as gr
import pandas as pd

from app.ui import _gradio_patches, controller

_gradio_patches.apply()

RESULTS_HEADERS = ["Finding ID", "Resource Type", "Region", "Misconfig Type", "Severity", "Confidence", "Status"]
QUEUE_HEADERS = ["Finding ID", "Misconfig Type", "Severity", "Explanation"]


def _as_dataframe(rows: list[list[Any]], headers: list[str]) -> pd.DataFrame:
    # gr.Dataframe silently renders only the first row when given a plain
    # list-of-lists from an event handler in this gradio version; a real
    # pandas DataFrame is the format that actually displays every row.
    return pd.DataFrame(rows, columns=headers)


def _results_df() -> pd.DataFrame:
    return _as_dataframe(controller.results_table(), RESULTS_HEADERS)


def _queue_df() -> pd.DataFrame:
    return _as_dataframe(controller.pending_queue(), QUEUE_HEADERS)


def _analyze(file_path: str, force_mock: bool) -> tuple[str, pd.DataFrame]:
    if not file_path:
        return "Upload a JSON, YAML, or CSV file first.", _results_df()

    outcome = controller.analyze_file(file_path, force_mock=force_mock)
    if outcome["error"]:
        return f"Could not parse the file: {outcome['error']}", _results_df()

    mode = "mock demo mode (Ollama unavailable or forced)" if outcome["used_mock"] else "live Ollama"
    summary = (
        f"Analyzed {outcome['analyzed']} finding(s) using {mode}. "
        f"{outcome['needs_review']} record(s) could not be parsed and were flagged for review."
    )
    return summary, _results_df()


def _refresh_finding_ids() -> dict[str, Any]:
    return gr.update(choices=controller.finding_ids())


def _show_finding_detail(finding_id: str) -> tuple[str, dict[str, Any], str]:
    if not finding_id:
        return "Select a finding.", {}, ""
    detail = controller.finding_detail(finding_id)
    if detail is None:
        return f"No finding with id {finding_id!r}.", {}, ""

    sources = detail["field_sources"]
    by_source = {"Rule": [], "Retrieved": [], "LLM": []}
    for field, source in sources.items():
        by_source.setdefault(source, []).append(field)
    tags = "\n\n".join(f"**{source}:** {', '.join(fields) or '-'}" for source, fields in by_source.items())
    return "", detail, tags


def _show_agent_trace(finding_id: str) -> list[dict[str, Any]]:
    if not finding_id:
        return []
    return controller.agent_trace(finding_id) or []


def _act_on_finding(action: str, finding_id: str, actor: str, note: str) -> tuple[str, pd.DataFrame, pd.DataFrame]:
    if not finding_id:
        return "Enter a finding id.", _queue_df(), _results_df()
    handler = controller.approve if action == "approve" else controller.reject
    ok = handler(finding_id, actor=actor or "analyst", note=note)
    verb = "Approved" if action == "approve" else "Rejected"
    message = f"{verb} {finding_id}." if ok else f"No pending finding with id {finding_id!r}."
    return message, _queue_df(), _results_df()


def build_app() -> gr.Blocks:
    with gr.Blocks(title="AWS Misconfiguration Remediation Agent") as demo:
        gr.Markdown("# AWS Cloud Misconfiguration Remediation Agent")
        gr.Markdown(
            "Upload scanner-style AWS findings (JSON/YAML/CSV). Nothing here executes "
            "a fix or touches a real AWS account -- every fix is a text template for a human to review."
        )

        with gr.Tab("Analyze"):
            file_input = gr.File(label="Findings file (JSON/YAML/CSV)", file_types=[".json", ".yaml", ".yml", ".csv"], type="filepath")
            force_mock = gr.Checkbox(label="Force mock demo mode (skip Ollama)", value=False)
            analyze_button = gr.Button("Analyze", variant="primary")
            analyze_summary = gr.Markdown()
            analyze_results = gr.Dataframe(headers=RESULTS_HEADERS, label="Results so far")

        with gr.Tab("Results"):
            results_table = gr.Dataframe(headers=RESULTS_HEADERS, label="All analyzed findings")
            results_refresh = gr.Button("Refresh")

        with gr.Tab("Finding Detail"):
            with gr.Row():
                detail_dropdown = gr.Dropdown(label="Finding ID", choices=controller.finding_ids())
                detail_refresh_ids = gr.Button("Refresh list")
            detail_error = gr.Markdown()
            detail_sources = gr.Markdown(label="Field sources (Rule / Retrieved / LLM)")
            detail_json = gr.JSON(label="Full AgentOutput")

        with gr.Tab("Agent Trace"):
            with gr.Row():
                trace_dropdown = gr.Dropdown(label="Finding ID", choices=controller.finding_ids())
                trace_refresh_ids = gr.Button("Refresh list")
            trace_json = gr.JSON(label="Tool-call trace")

        with gr.Tab("Approval Queue"):
            queue_table = gr.Dataframe(headers=QUEUE_HEADERS, label="Pending approval")
            queue_refresh = gr.Button("Refresh queue")
            with gr.Row():
                action_finding_id = gr.Textbox(label="Finding ID")
                action_actor = gr.Textbox(label="Your name", value="analyst")
            action_note = gr.Textbox(label="Note (optional)")
            with gr.Row():
                approve_button = gr.Button("Approve", variant="primary")
                reject_button = gr.Button("Reject", variant="stop")
            action_message = gr.Markdown()

        with gr.Tab("Export"):
            gr.Markdown("Export the audit log (CSV) or every recommended fix (text) for offline review.")
            export_audit_button = gr.Button("Export audit log (CSV)")
            export_audit_file = gr.File(label="audit_log.csv")
            export_fixes_button = gr.Button("Export fixes (text)")
            export_fixes_file = gr.File(label="fixes.txt")

        with gr.Tab("Monitoring"):
            monitoring_json = gr.JSON(label="Run statistics")
            monitoring_refresh = gr.Button("Refresh")

        analyze_button.click(_analyze, inputs=[file_input, force_mock], outputs=[analyze_summary, analyze_results])
        results_refresh.click(_results_df, outputs=results_table)
        detail_refresh_ids.click(_refresh_finding_ids, outputs=detail_dropdown)
        detail_dropdown.change(_show_finding_detail, inputs=detail_dropdown, outputs=[detail_error, detail_json, detail_sources])
        trace_refresh_ids.click(_refresh_finding_ids, outputs=trace_dropdown)
        trace_dropdown.change(_show_agent_trace, inputs=trace_dropdown, outputs=trace_json)
        queue_refresh.click(_queue_df, outputs=queue_table)
        approve_button.click(
            lambda fid, actor, note: _act_on_finding("approve", fid, actor, note),
            inputs=[action_finding_id, action_actor, action_note],
            outputs=[action_message, queue_table, results_table],
        )
        reject_button.click(
            lambda fid, actor, note: _act_on_finding("reject", fid, actor, note),
            inputs=[action_finding_id, action_actor, action_note],
            outputs=[action_message, queue_table, results_table],
        )
        export_audit_button.click(controller.export_audit_log_csv, outputs=export_audit_file)
        export_fixes_button.click(controller.export_fixes_text, outputs=export_fixes_file)
        monitoring_refresh.click(controller.monitoring_summary, outputs=monitoring_json)

    return demo

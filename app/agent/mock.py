"""A deterministic, offline stand-in for an Ollama chat call.

Used as run_agent's chat_fn when Ollama isn't installed or its server isn't
reachable (CLAUDE.md requires a "mock demo mode that replays saved outputs
when Ollama is unavailable"). It drives the exact same tool-calling protocol
a real model would -- check_misconfig, then lookup_controls and
get_fix_template, then a final JSON explanation -- just with templated text
instead of a real one, so the rest of the pipeline (rules, retrieval, fix
templates, approval, export) can be demoed end-to-end without a GPU, a
model pull, or network access.
"""

from __future__ import annotations

import json
from typing import Any, Optional


def _last_tool_result(messages: list[dict[str, Any]], tool_name: str) -> Optional[dict[str, Any]]:
    for message in reversed(messages):
        if message.get("role") == "tool" and message.get("name") == tool_name:
            try:
                return json.loads(message["content"])
            except (json.JSONDecodeError, TypeError):
                return None
    return None


def _tool_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {"function": {"name": name, "arguments": arguments}}


def _final_json(
    rule_result: dict[str, Any], fix: Optional[dict[str, Any]]
) -> str:
    misconfig_type = rule_result.get("misconfig_type", "UNKNOWN")
    severity = rule_result.get("severity")
    evidence = rule_result.get("evidence") or {}

    if misconfig_type == "COMPLIANT":
        explanation = (
            "[Mock demo mode -- Ollama unavailable] The rule engine found no "
            "misconfiguration for this finding; its configuration is compliant."
        )
        remediation_steps: list[str] = []
    else:
        evidence_text = ", ".join(f"{k}={v}" for k, v in evidence.items()) or "see evidence"
        explanation = (
            f"[Mock demo mode -- Ollama unavailable] The rule engine flagged this "
            f"as {misconfig_type} ({severity or 'unknown'} severity), based on: {evidence_text}."
        )
        remediation_steps = []
        if fix and "error" not in fix:
            remediation_steps = [
                line.strip()
                for line in fix.get("cli", "").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]

    return json.dumps(
        {
            "explanation": explanation,
            "remediation_steps": remediation_steps,
            # Mock mode never claims a real judgment call, so it always
            # reports low confidence regardless of the verdict.
            "confidence": "low",
        }
    )


def mock_chat_fn(messages: list[dict[str, Any]], tools: list[dict[str, Any]], model: str) -> dict[str, Any]:
    rule_result = _last_tool_result(messages, "check_misconfig")
    if rule_result is None:
        return {"message": {"content": "", "tool_calls": [_tool_call("check_misconfig", {})]}}

    misconfig_type = rule_result.get("misconfig_type")
    if misconfig_type in (None, "COMPLIANT"):
        return {"message": {"content": _final_json(rule_result, None), "tool_calls": []}}

    controls = _last_tool_result(messages, "lookup_controls")
    fix = _last_tool_result(messages, "get_fix_template")

    if controls is None or fix is None:
        calls = []
        if controls is None:
            calls.append(_tool_call("lookup_controls", {"misconfig_type": misconfig_type}))
        if fix is None:
            calls.append(_tool_call("get_fix_template", {"misconfig_type": misconfig_type}))
        return {"message": {"content": "", "tool_calls": calls}}

    return {"message": {"content": _final_json(rule_result, fix), "tool_calls": []}}

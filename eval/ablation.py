"""Ablation study: rules-only vs full-system detection, and a hook for
comparing two Ollama models (Qwen2.5 vs Llama 3.1) when a live Ollama
server is available.

"LLM only" (no rule engine at all) is deliberately not implemented as a
production code path -- hard rule 1 requires the rule engine to always
decide the verdict -- but a teammate can still study it by pointing
`run_full_system` at a hand-written chat_fn that classifies from the raw
finding text alone, since the function is fully pluggable.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from app.agent.loop import ChatFn, run_agent
from app.agent.mock import mock_chat_fn
from app.schemas import Finding
from app.tools.rules import check_misconfig
from eval.metrics import DetectionMetrics, detection_metrics


@dataclass(frozen=True)
class AblationResult:
    name: str
    metrics: DetectionMetrics
    avg_seconds_per_finding: float


def run_rules_only(findings: list[Finding]) -> list[str]:
    """The rule engine alone, with no retrieval, fix templates, or LLM call."""
    return [check_misconfig(f).misconfig_type.value for f in findings]


def run_full_system(
    findings: list[Finding], *, chat_fn: Optional[ChatFn] = None, collection: Any = None, model: str = "mock"
) -> list[str]:
    """check_misconfig + lookup_controls + get_fix_template + an LLM explanation.

    Defaults to the offline mock_chat_fn so this runs without Ollama; pass a
    real chat_fn (or leave chat_fn=None with Ollama reachable) to benchmark
    an actual model.
    """
    chat_fn = chat_fn or mock_chat_fn
    predictions = []
    for finding in findings:
        result = run_agent(finding, chat_fn=chat_fn, collection=collection, model=model)
        predictions.append(result.output.misconfig_type.value)
    return predictions


def ablation_study(
    findings: list[Finding], labels: list[str], *, collection: Any = None
) -> dict[str, AblationResult]:
    """Compares rules-only detection against the full pipeline (mock LLM)."""
    results: dict[str, AblationResult] = {}

    start = time.perf_counter()
    rules_predictions = run_rules_only(findings)
    rules_duration = time.perf_counter() - start
    results["rules_only"] = AblationResult(
        name="rules_only",
        metrics=detection_metrics(labels, rules_predictions),
        avg_seconds_per_finding=rules_duration / len(findings) if findings else 0.0,
    )

    start = time.perf_counter()
    full_predictions = run_full_system(findings, collection=collection)
    full_duration = time.perf_counter() - start
    results["full_system_mock_llm"] = AblationResult(
        name="full_system_mock_llm",
        metrics=detection_metrics(labels, full_predictions),
        avg_seconds_per_finding=full_duration / len(findings) if findings else 0.0,
    )

    return results


def compare_models(
    findings: list[Finding],
    labels: list[str],
    *,
    model_names: tuple[str, str] = ("qwen2.5:7b", "llama3.1:8b"),
    collection: Any = None,
) -> dict[str, AblationResult]:
    """Runs the full pipeline against two live Ollama models and compares them.

    Requires a running Ollama server with both models pulled -- there is no
    offline fallback here, since the whole point is comparing two real
    models. Raises whatever run_agent's default chat_fn raises (e.g. a
    connection error) if Ollama isn't reachable; callers should catch that
    and skip the comparison rather than treat it as a hard failure.
    """
    results: dict[str, AblationResult] = {}
    for model_name in model_names:
        start = time.perf_counter()
        predictions = run_full_system(findings, chat_fn=None, collection=collection, model=model_name)
        duration = time.perf_counter() - start
        results[model_name] = AblationResult(
            name=model_name,
            metrics=detection_metrics(labels, predictions),
            avg_seconds_per_finding=duration / len(findings) if findings else 0.0,
        )
    return results

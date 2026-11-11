"""Evaluation metrics against the CLAUDE.md targets.

Every function here is a pure function over plain data (ground-truth
labels, AgentOutput objects, ToolTrace lists) so it can be unit tested
without running the agent loop, and reused by both eval/run_eval.py and
eval/ablation.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from app.agent.loop import ToolTrace
from app.schemas import AgentOutput
from app.schemas.enums import APPROVAL_REQUIRED_VERDICTS

COMPLIANT = "COMPLIANT"


@dataclass(frozen=True)
class DetectionMetrics:
    accuracy: float
    precision: float
    recall: float
    f1: float
    confusion: dict[str, dict[str, int]] = field(default_factory=dict)


def detection_metrics(labels: list[str], predictions: list[str]) -> DetectionMetrics:
    """Exact-label accuracy plus misconfigured-vs-compliant precision/recall/F1.

    `labels` is the dataset's ground truth (data/generator.py's `label`,
    never shown to the agent); `predictions` is what the system reported.
    """
    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must be the same length")
    if not labels:
        return DetectionMetrics(accuracy=1.0, precision=1.0, recall=1.0, f1=1.0, confusion={})

    confusion: dict[str, dict[str, int]] = {}
    exact_matches = 0
    tp = fp = fn = 0

    for truth, pred in zip(labels, predictions):
        confusion.setdefault(truth, {})
        confusion[truth][pred] = confusion[truth].get(pred, 0) + 1
        if truth == pred:
            exact_matches += 1

        truth_positive = truth != COMPLIANT
        pred_positive = pred != COMPLIANT
        if truth_positive and pred_positive:
            tp += 1
        elif not truth_positive and pred_positive:
            fp += 1
        elif truth_positive and not pred_positive:
            fn += 1

    accuracy = exact_matches / len(labels)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return DetectionMetrics(accuracy=accuracy, precision=precision, recall=recall, f1=f1, confusion=confusion)


def expected_controls_by_type(controls_path: Optional[Path] = None) -> dict[str, dict[str, list[str]]]:
    """The answer key for control/MITRE mapping: kb/controls.md itself."""
    from kb.ingest import CONTROLS_PATH, parse_controls_markdown

    sections = parse_controls_markdown((controls_path or CONTROLS_PATH).read_text())
    return {
        section["misconfig_type"]: {
            "control_ids": section["control_ids"],
            "mitre_techniques": section["mitre_techniques"],
        }
        for section in sections
    }


def _mapping_accuracy(outputs: list[AgentOutput], expected: dict[str, dict[str, list[str]]], field_name: str) -> float:
    scored = [o for o in outputs if o.misconfig_type.value in expected]
    if not scored:
        return 1.0
    correct = sum(
        1 for o in scored if set(getattr(o, field_name)) == set(expected[o.misconfig_type.value][field_name])
    )
    return correct / len(scored)


def control_mapping_accuracy(
    outputs: list[AgentOutput], expected: Optional[dict[str, dict[str, list[str]]]] = None
) -> float:
    return _mapping_accuracy(outputs, expected or expected_controls_by_type(), "control_ids")


def mitre_mapping_accuracy(
    outputs: list[AgentOutput], expected: Optional[dict[str, dict[str, list[str]]]] = None
) -> float:
    return _mapping_accuracy(outputs, expected or expected_controls_by_type(), "mitre_techniques")


def tool_selection_accuracy(runs: list[tuple[list[ToolTrace], str]]) -> float:
    """Checks each run followed the required protocol: check_misconfig
    first, then (for a non-COMPLIANT verdict) both lookup_controls and
    get_fix_template before answering.
    """
    if not runs:
        return 1.0
    correct = 0
    for trace, verdict in runs:
        tools_called = [t.tool for t in trace]
        if not tools_called or tools_called[0] != "check_misconfig":
            continue
        if verdict == COMPLIANT:
            correct += 1
            continue
        if "lookup_controls" in tools_called and "get_fix_template" in tools_called:
            correct += 1
    return correct / len(runs)


def approval_routing_compliance(outputs: list[AgentOutput]) -> float:
    """Fraction of High/Critical/IAM-sensitive outputs that require approval.

    AgentOutput's own validator already makes a violation impossible to
    construct, so this is a structural sanity check, not a probe for bugs:
    a result below 1.0 would mean something bypassed that validator.
    """
    sensitive = [o for o in outputs if o.misconfig_type in APPROVAL_REQUIRED_VERDICTS]
    if not sensitive:
        return 1.0
    return sum(1 for o in sensitive if o.requires_approval) / len(sensitive)


def verdict_integrity_rate(outputs: list[AgentOutput], rule_verdicts: dict[str, str]) -> float:
    """Fraction of outputs whose misconfig_type matches check_misconfig's own verdict.

    A stand-in for "hallucination" specific to hard rule 1: the LLM must
    never override the rule engine. True hallucination detection (fabricated
    facts in free-text explanations) needs a judge LLM, which is out of
    scope here -- this instead verifies the one hallucination the system
    design must make impossible.
    """
    scored = [o for o in outputs if o.finding_id in rule_verdicts]
    if not scored:
        return 1.0
    correct = sum(1 for o in scored if o.misconfig_type.value == rule_verdicts[o.finding_id])
    return correct / len(scored)


@dataclass(frozen=True)
class LatencyStats:
    count: int
    avg_seconds: float
    max_seconds: float
    under_30s_rate: float


def latency_stats(durations_seconds: list[float]) -> LatencyStats:
    if not durations_seconds:
        return LatencyStats(count=0, avg_seconds=0.0, max_seconds=0.0, under_30s_rate=1.0)
    return LatencyStats(
        count=len(durations_seconds),
        avg_seconds=sum(durations_seconds) / len(durations_seconds),
        max_seconds=max(durations_seconds),
        under_30s_rate=sum(1 for d in durations_seconds if d < 30.0) / len(durations_seconds),
    )

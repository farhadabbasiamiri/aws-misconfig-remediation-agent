"""Runs the full agent pipeline over the synthetic dataset and reports the
CLAUDE.md evaluation targets.

Run directly: python eval/run_eval.py
Writes a timestamped JSON report to eval/results/ and prints a pass/fail
summary against each target to stdout.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

# Allow `python eval/run_eval.py` to find the app package without needing -m.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.agent.loop import run_agent  # noqa: E402
from app.agent.mock import mock_chat_fn  # noqa: E402
from app.schemas import Finding  # noqa: E402
from app.tools.rules import check_misconfig  # noqa: E402
from data.generator import generate  # noqa: E402
from eval.metrics import (  # noqa: E402
    approval_routing_compliance,
    control_mapping_accuracy,
    detection_metrics,
    latency_stats,
    mitre_mapping_accuracy,
    tool_selection_accuracy,
    verdict_integrity_rate,
)
from eval.test_cases.adversarial import adversarial_pass_rate, check_adversarial_handling  # noqa: E402

RESULTS_DIR = Path(__file__).resolve().parent / "results"

# (target name, computed value, passes, target description)
TARGETS = {
    "detection_f1": 0.90,
    "control_mapping_accuracy": 0.90,
    "mitre_mapping_accuracy": 0.90,
    "tool_selection_accuracy": 0.95,
    "verdict_integrity_rate": 0.95,  # stand-in for "hallucination <= 5%"; see eval/metrics.py
    "approval_routing_compliance": 1.00,
    "adversarial_pass_rate": 1.00,
    "latency_under_30s_rate": 1.00,
}


def run_pipeline(findings: list[Finding], *, collection=None) -> list[dict]:
    rule_verdicts = {f.finding_id: check_misconfig(f).misconfig_type.value for f in findings}
    records = []
    for finding in findings:
        start = time.perf_counter()
        result = run_agent(finding, chat_fn=mock_chat_fn, collection=collection)
        duration = time.perf_counter() - start
        records.append(
            {
                "finding_id": finding.finding_id,
                "output": result.output,
                "trace": result.trace,
                "duration": duration,
                "rule_verdict": rule_verdicts[finding.finding_id],
            }
        )
    return records


def evaluate(records: list[dict], labels_by_id: dict[str, str]) -> dict:
    outputs = [r["output"] for r in records]
    predictions = [r["output"].misconfig_type.value for r in records]
    labels = [labels_by_id[r["finding_id"]] for r in records]
    runs = [(r["trace"], r["output"].misconfig_type.value) for r in records]
    rule_verdicts = {r["finding_id"]: r["rule_verdict"] for r in records}
    durations = [r["duration"] for r in records]

    detection = detection_metrics(labels, predictions)
    adversarial_results = check_adversarial_handling()

    computed = {
        "detection_f1": detection.f1,
        "detection_accuracy": detection.accuracy,
        "control_mapping_accuracy": control_mapping_accuracy(outputs),
        "mitre_mapping_accuracy": mitre_mapping_accuracy(outputs),
        "tool_selection_accuracy": tool_selection_accuracy(runs),
        "verdict_integrity_rate": verdict_integrity_rate(outputs, rule_verdicts),
        "approval_routing_compliance": approval_routing_compliance(outputs),
        "adversarial_pass_rate": adversarial_pass_rate(adversarial_results),
        "latency": asdict(latency_stats(durations)),
    }
    computed["latency_under_30s_rate"] = computed["latency"]["under_30s_rate"]

    summary = []
    for name, target in TARGETS.items():
        value = computed[name]
        summary.append({"target": name, "value": value, "threshold": target, "passes": value >= target})

    return {"computed": computed, "summary": summary, "confusion": detection.confusion}


def main() -> None:
    result = generate()
    clean = [r for r in result["findings"] if not r["finding_id"].startswith("SYN-BAD-")]
    findings = [Finding(**r) for r in clean]
    labels_by_id = {r["finding_id"]: r["label"] for r in clean}

    records = run_pipeline(findings)
    report = evaluate(records, labels_by_id)

    print(f"{'Target':<28} {'Value':>8}  {'Threshold':>9}  Status")
    for row in report["summary"]:
        status = "PASS" if row["passes"] else "FAIL"
        print(f"{row['target']:<28} {row['value']:>8.2%}  {row['threshold']:>9.2%}  {status}")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / f"report_{time.strftime('%Y%m%d_%H%M%S')}.json"
    out_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"\nFull report written to {out_path}")


if __name__ == "__main__":
    main()

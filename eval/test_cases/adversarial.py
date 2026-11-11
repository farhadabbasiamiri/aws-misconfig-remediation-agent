"""Adversarial / hard-case evaluation.

Pulls the hard cases data/generator.py deliberately builds in (private-CIDR
SSH, conditioned wildcard IAM, misleading names, prompt injection in tags,
and malformed records) and checks the system handles every one exactly as
CLAUDE.md requires. This is the "100% of adversarial cases handled" target.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.parser import parse_text
from app.schemas import Finding
from app.tools.rules import check_misconfig
from data.generator import generate


@dataclass(frozen=True)
class AdversarialCaseResult:
    finding_id: str
    expected_label: str
    actual_verdict: str
    passed: bool
    note: str = ""


def load_hard_cases() -> tuple[list[dict[str, Any]], list[str]]:
    """Returns (all generated findings as raw dicts, hard_case_ids)."""
    result = generate()
    return result["findings"], result["hard_case_ids"]


def check_adversarial_handling() -> list[AdversarialCaseResult]:
    """Runs check_misconfig on every clean hard case and the parser on every
    malformed one, and records whether each behaved as required.
    """
    records, hard_case_ids = load_hard_cases()
    by_id = {r["finding_id"]: r for r in records}
    results: list[AdversarialCaseResult] = []

    for finding_id in hard_case_ids:
        record = by_id[finding_id]

        if finding_id.startswith("SYN-BAD-"):
            # Malformed record: the parser must flag it NEEDS_REVIEW, not crash.
            report = parse_text(json.dumps([record]), ".json")
            passed = not report.findings and len(report.needs_review) == 1
            results.append(
                AdversarialCaseResult(
                    finding_id=finding_id,
                    expected_label="NEEDS_REVIEW",
                    actual_verdict="NEEDS_REVIEW" if passed else "(parsed as valid or dropped)",
                    passed=passed,
                    note="malformed record must be flagged, not silently parsed or dropped",
                )
            )
            continue

        finding = Finding(**record)
        verdict = check_misconfig(finding).misconfig_type.value
        passed = verdict == record["label"]
        results.append(
            AdversarialCaseResult(
                finding_id=finding_id,
                expected_label=record["label"],
                actual_verdict=verdict,
                passed=passed,
            )
        )

    return results


def adversarial_pass_rate(results: list[AdversarialCaseResult]) -> float:
    if not results:
        return 1.0
    return sum(1 for r in results if r.passed) / len(results)

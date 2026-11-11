from eval.test_cases.adversarial import (
    adversarial_pass_rate,
    check_adversarial_handling,
    load_hard_cases,
)


def test_load_hard_cases_returns_at_least_fifteen():
    _, hard_case_ids = load_hard_cases()
    assert len(hard_case_ids) >= 15


def test_check_adversarial_handling_passes_every_case():
    results = check_adversarial_handling()
    failures = [r for r in results if not r.passed]
    assert not failures, failures


def test_adversarial_pass_rate_is_100_percent():
    results = check_adversarial_handling()
    assert adversarial_pass_rate(results) == 1.0


def test_adversarial_pass_rate_on_empty_is_perfect_by_convention():
    assert adversarial_pass_rate([]) == 1.0


def test_malformed_cases_are_included_and_flagged_needs_review():
    results = check_adversarial_handling()
    malformed = [r for r in results if r.finding_id.startswith("SYN-BAD-")]
    assert len(malformed) == 5
    assert all(r.expected_label == "NEEDS_REVIEW" and r.passed for r in malformed)


def test_private_cidr_hard_case_is_compliant():
    results = check_adversarial_handling()
    private_cidr_cases = [
        r for r in results if r.expected_label == "COMPLIANT" and not r.finding_id.startswith("SYN-BAD-")
    ]
    assert private_cidr_cases
    assert all(r.actual_verdict == "COMPLIANT" for r in private_cidr_cases)

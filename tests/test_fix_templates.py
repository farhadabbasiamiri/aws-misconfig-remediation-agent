from app.schemas.enums import APPROVAL_REQUIRED_VERDICTS, MisconfigVerdict
from app.tools.fix_templates import get_fix_template


def test_get_fix_template_returns_a_template_for_every_misconfig_type():
    for i in range(1, 11):
        misconfig_type = f"M{i:02d}"
        template = get_fix_template(misconfig_type)
        assert template is not None, misconfig_type
        assert template.misconfig_type == misconfig_type
        assert template.terraform
        assert template.cli
        assert template.side_effects


def test_get_fix_template_accepts_enum_or_string():
    by_string = get_fix_template("M01")
    by_enum = get_fix_template(MisconfigVerdict.M01)
    assert by_string == by_enum


def test_get_fix_template_returns_none_for_compliant():
    assert get_fix_template("COMPLIANT") is None


def test_get_fix_template_returns_none_for_needs_review():
    assert get_fix_template("NEEDS_REVIEW") is None


def test_get_fix_template_returns_none_for_unknown_string():
    assert get_fix_template("NOT_A_REAL_TYPE") is None


def test_get_fix_template_requires_approval_matches_the_shared_approval_set():
    for i in range(1, 11):
        misconfig_type = f"M{i:02d}"
        template = get_fix_template(misconfig_type)
        expected = MisconfigVerdict(misconfig_type) in APPROVAL_REQUIRED_VERDICTS
        assert template.requires_approval == expected


def test_sensitive_types_mention_side_effects_a_human_should_weigh():
    # Every template with requires_approval=True must give a human something
    # concrete to weigh before running the fix -- an empty or trivial note
    # would defeat the point of the approval gate.
    for i in range(1, 11):
        misconfig_type = f"M{i:02d}"
        template = get_fix_template(misconfig_type)
        if template.requires_approval:
            assert len(template.side_effects) > 20

"""check_misconfig: the deterministic rule engine.

Hard rule 1 (CLAUDE.md): only this module sets misconfiguration type and
severity. The LLM explains a verdict, it never overrides one. Rules read
Finding.config only -- never Finding.tags -- so misleading names and prompt
injection in tags cannot affect a verdict. Any missing or unexpected shape
in config is handled and reported as NEEDS_REVIEW rather than raised.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Callable

from app.schemas import Confidence, Finding, MisconfigVerdict, ResourceType, Severity
from app.schemas.enums import APPROVAL_REQUIRED_VERDICTS

SEVERITY_BY_TYPE: dict[MisconfigVerdict, Severity] = {
    MisconfigVerdict.M01: Severity.HIGH,
    MisconfigVerdict.M02: Severity.MEDIUM,
    MisconfigVerdict.M03: Severity.HIGH,
    MisconfigVerdict.M04: Severity.CRITICAL,
    MisconfigVerdict.M05: Severity.CRITICAL,
    MisconfigVerdict.M06: Severity.MEDIUM,
    MisconfigVerdict.M07: Severity.HIGH,
    MisconfigVerdict.M08: Severity.HIGH,
    MisconfigVerdict.M09: Severity.MEDIUM,
    MisconfigVerdict.M10: Severity.MEDIUM,
}

RISKY_PORTS = {22, 3389}
OPEN_CIDR_V4 = "0.0.0.0/0"
OPEN_CIDR_V6 = "::/0"


@dataclass(frozen=True)
class RuleResult:
    misconfig_type: MisconfigVerdict
    severity: Severity | None
    confidence: Confidence
    requires_approval: bool
    evidence: dict[str, Any]


def _result(misconfig_type: MisconfigVerdict, evidence: dict[str, Any], confidence: Confidence = Confidence.HIGH) -> RuleResult:
    return RuleResult(
        misconfig_type=misconfig_type,
        severity=SEVERITY_BY_TYPE.get(misconfig_type),
        confidence=confidence,
        requires_approval=misconfig_type in APPROVAL_REQUIRED_VERDICTS,
        evidence=evidence,
    )


def _compliant(evidence: dict[str, Any] | None = None) -> RuleResult:
    return _result(MisconfigVerdict.COMPLIANT, evidence or {})


def _needs_review(reason: str, **extra: Any) -> RuleResult:
    return _result(MisconfigVerdict.NEEDS_REVIEW, {"reason": reason, **extra}, confidence=Confidence.LOW)


def _contains_wildcard(value: Any) -> bool:
    if value == "*":
        return True
    return isinstance(value, list) and "*" in value


def _port_matches(from_port: Any, to_port: Any, targets: set[int]) -> bool:
    if not isinstance(from_port, int) or not isinstance(to_port, int):
        return False
    return any(from_port <= port <= to_port for port in targets)


def check_s3(finding: Finding) -> RuleResult:
    config = finding.config
    block_keys = ["BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"]
    present = {k: config[k] for k in block_keys if k in config}
    if not present:
        return _needs_review("missing S3 public-access-block fields", missing_fields=block_keys)

    disabled = [k for k, v in present.items() if v is False]
    if disabled:
        return _result(MisconfigVerdict.M01, {"public_access_block_disabled": disabled})

    if "ServerSideEncryptionConfiguration" not in config or config["ServerSideEncryptionConfiguration"] is None:
        return _result(MisconfigVerdict.M02, {"encryption": "no default encryption configured"})

    return _compliant()


def check_security_group(finding: Finding) -> RuleResult:
    config = finding.config
    if "IpPermissions" not in config:
        return _needs_review("missing IpPermissions field")

    offending: list[dict[str, Any]] = []
    for permission in config["IpPermissions"]:
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")
        if not _port_matches(from_port, to_port, RISKY_PORTS):
            continue
        for ip_range in permission.get("IpRanges", []):
            if ip_range.get("CidrIp") == OPEN_CIDR_V4:
                offending.append({"port_range": [from_port, to_port], "cidr": OPEN_CIDR_V4})
        for ip_range in permission.get("Ipv6Ranges", []):
            if ip_range.get("CidrIpv6") == OPEN_CIDR_V6:
                offending.append({"port_range": [from_port, to_port], "cidr": OPEN_CIDR_V6})

    if offending:
        return _result(MisconfigVerdict.M03, {"offending_rules": offending})
    return _compliant()


def _check_root_mfa(config: dict[str, Any]) -> RuleResult:
    mfa_enabled = config.get("RootAccountMFAEnabled")
    if mfa_enabled is None:
        return _needs_review("missing RootAccountMFAEnabled field")
    if mfa_enabled is False:
        return _result(MisconfigVerdict.M05, {"root_mfa_enabled": False})
    return _compliant()


def _check_access_key_age(config: dict[str, Any]) -> RuleResult:
    age_days = config.get("AgeDays")
    if age_days is None:
        last_rotated = config.get("AccessKeyLastRotated")
        if not last_rotated:
            return _needs_review("missing AgeDays/AccessKeyLastRotated field")
        age_days = (date.today() - date.fromisoformat(last_rotated)).days
    if age_days > 90:
        return _result(MisconfigVerdict.M06, {"age_days": age_days})
    return _compliant({"age_days": age_days})


def _check_iam_policy(config: dict[str, Any]) -> RuleResult:
    statements = config.get("PolicyDocument", {}).get("Statement")
    if not statements:
        return _needs_review("missing PolicyDocument.Statement field")

    for statement in statements:
        if (
            statement.get("Effect") == "Allow"
            and _contains_wildcard(statement.get("Action"))
            and _contains_wildcard(statement.get("Resource"))
        ):
            evidence: dict[str, Any] = {"statement": statement}
            if "Condition" in statement:
                # Team decision (see data/DATA_CARD.md): a Condition on a
                # wildcard Allow is not trusted to narrow it, since its
                # strength can't be verified from the finding alone.
                evidence["note"] = "flagged despite Condition; condition strength not verified"
            return _result(MisconfigVerdict.M04, evidence)

    return _compliant()


def check_iam(finding: Finding) -> RuleResult:
    config = finding.config
    if "RootAccountMFAEnabled" in config:
        return _check_root_mfa(config)
    if "AgeDays" in config or "AccessKeyLastRotated" in config:
        return _check_access_key_age(config)
    if "PolicyDocument" in config:
        return _check_iam_policy(config)
    return _needs_review("unrecognised IAM finding shape", config_keys=sorted(config.keys()))


def check_cloudtrail(finding: Finding) -> RuleResult:
    config = finding.config
    if config.get("TrailExists") is False:
        return _result(MisconfigVerdict.M07, {"reason": "no CloudTrail trail configured"})
    if "IsLogging" not in config or "IsMultiRegionTrail" not in config:
        return _needs_review("missing IsLogging/IsMultiRegionTrail field")
    if not config["IsLogging"]:
        return _result(MisconfigVerdict.M07, {"reason": "trail is stopped"})
    if not config["IsMultiRegionTrail"]:
        return _result(MisconfigVerdict.M07, {"reason": "trail is single-region"})
    return _compliant()


def check_rds(finding: Finding) -> RuleResult:
    config = finding.config
    if "PubliclyAccessible" not in config or "StorageEncrypted" not in config:
        return _needs_review("missing PubliclyAccessible/StorageEncrypted field")
    if config["PubliclyAccessible"] is True:
        return _result(MisconfigVerdict.M08, {"publicly_accessible": True})
    if config["StorageEncrypted"] is False:
        return _result(MisconfigVerdict.M09, {"storage_encrypted": False})
    return _compliant()


def check_ebs(finding: Finding) -> RuleResult:
    config = finding.config
    if "Encrypted" not in config:
        return _needs_review("missing Encrypted field")
    if config["Encrypted"] is False:
        return _result(MisconfigVerdict.M10, {"encrypted": False})
    return _compliant()


_HANDLERS: dict[ResourceType, Callable[[Finding], RuleResult]] = {
    ResourceType.S3: check_s3,
    ResourceType.EC2: check_security_group,
    ResourceType.IAM: check_iam,
    ResourceType.CLOUDTRAIL: check_cloudtrail,
    ResourceType.RDS: check_rds,
    ResourceType.EBS: check_ebs,
}


def check_misconfig(finding: Finding) -> RuleResult:
    """Deterministic verdict for one Finding. Never raises."""
    handler = _HANDLERS.get(finding.resource_type)
    if handler is None:
        return _needs_review(f"no rule handler for resource_type {finding.resource_type}")
    try:
        return handler(finding)
    except Exception as exc:  # defensive: a rule bug must not crash the agent loop
        return _needs_review("rule engine raised an exception", error=str(exc))

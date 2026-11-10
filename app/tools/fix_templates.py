"""get_fix_template: the vetted remediation library.

Hard rule 2 (CLAUDE.md): nothing here executes a fix or calls a real AWS
API. Every template is text -- a Terraform snippet and/or AWS CLI
command(s) -- for a human to review and run themselves, plus a note on
what breaks if they do.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Union

from app.schemas.enums import APPROVAL_REQUIRED_VERDICTS, MisconfigVerdict


@dataclass(frozen=True)
class FixTemplate:
    misconfig_type: str
    terraform: str
    cli: str
    side_effects: str
    requires_approval: bool


@dataclass(frozen=True)
class _TemplateText:
    terraform: str
    cli: str
    side_effects: str


_TEMPLATE_TEXT: dict[MisconfigVerdict, _TemplateText] = {
    MisconfigVerdict.M01: _TemplateText(
        terraform="""resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}""",
        cli="""aws s3api put-public-access-block \\
  --bucket <BUCKET_NAME> \\
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true""",
        side_effects=(
            "Any public consumer currently reading from this bucket (anonymous "
            "downloads, public website hosting via ACL) loses access immediately."
        ),
    ),
    MisconfigVerdict.M02: _TemplateText(
        terraform="""resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}""",
        cli="""aws s3api put-bucket-encryption \\
  --bucket <BUCKET_NAME> \\
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'""",
        side_effects=(
            "Only affects objects uploaded after this change; existing objects "
            "are not retroactively encrypted."
        ),
    ),
    MisconfigVerdict.M03: _TemplateText(
        terraform="""resource "aws_security_group_rule" "trusted_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["<TRUSTED_CIDR>"] # replace with the actual trusted range
  security_group_id = aws_security_group.this.id
}""",
        cli="""aws ec2 revoke-security-group-ingress \\
  --group-id <SG_ID> --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress \\
  --group-id <SG_ID> --protocol tcp --port 22 --cidr <TRUSTED_CIDR>""",
        side_effects=(
            "Revokes direct SSH/RDP access from the open CIDR immediately; "
            "anyone relying on that access without a VPN or bastion route is "
            "locked out until they go through the trusted range instead."
        ),
    ),
    MisconfigVerdict.M04: _TemplateText(
        terraform="""resource "aws_iam_policy" "scoped_replacement" {
  name   = "scoped-replacement-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["<REPLACE_WITH_ACTUAL_ACTIONS>"]
      Resource = ["<REPLACE_WITH_ACTUAL_RESOURCE_ARNS>"]
    }]
  })
}""",
        cli="""aws iam create-policy-version \\
  --policy-arn <POLICY_ARN> \\
  --policy-document file://scoped-policy.json \\
  --set-as-default""",
        side_effects=(
            "Removes broad access immediately; any workload depending on the "
            "wildcard permission for an action not explicitly re-added starts "
            "failing with AccessDenied. Every action the identity actually "
            "uses must be identified before narrowing the policy."
        ),
    ),
    MisconfigVerdict.M05: _TemplateText(
        terraform="# Not applicable -- root account MFA cannot be managed via Terraform or the IAM API.",
        cli=(
            "# Root MFA cannot be enabled via the CLI/API; it must be configured by\n"
            "# signing in as the root user and registering a virtual or hardware MFA\n"
            "# device under My Security Credentials > Multi-factor authentication (MFA)."
        ),
        side_effects=(
            "None from this change itself, but losing the MFA device without a "
            "backup locks the root user out of the account entirely, so a backup "
            "method or break-glass procedure must be in place first."
        ),
    ),
    MisconfigVerdict.M06: _TemplateText(
        terraform=(
            "# Not applicable -- access keys are rotated out-of-band via the CLI/console\n"
            "# rather than through Terraform, to avoid downtime while every consumer is updated."
        ),
        cli="""aws iam create-access-key --user-name <USER_NAME>
# deploy the new key to every consumer, then:
aws iam update-access-key --user-name <USER_NAME> --access-key-id <OLD_KEY_ID> --status Inactive
aws iam delete-access-key --user-name <USER_NAME> --access-key-id <OLD_KEY_ID>""",
        side_effects=(
            "Any application or script still using the old key stops working the "
            "moment it is deactivated; the new key must be deployed everywhere "
            "the old one was used before deactivating it."
        ),
    ),
    MisconfigVerdict.M07: _TemplateText(
        terraform="""resource "aws_cloudtrail" "org_trail" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
}""",
        cli="""aws cloudtrail create-trail --name org-trail --s3-bucket-name <LOG_BUCKET> --is-multi-region-trail
aws cloudtrail start-logging --name org-trail""",
        side_effects=(
            "Starts a steady stream of log data to the target S3 bucket, with an "
            "ongoing storage cost; that bucket should have its own lifecycle policy."
        ),
    ),
    MisconfigVerdict.M08: _TemplateText(
        terraform="""resource "aws_db_instance" "this" {
  # ...
  publicly_accessible = false
}""",
        cli="aws rds modify-db-instance --db-instance-identifier <DB_ID> --no-publicly-accessible --apply-immediately",
        side_effects=(
            "Immediately cuts off any client connecting directly over the public "
            "internet; those clients must be moved to connect through a VPN, "
            "bastion, or an app-layer proxy inside the VPC first."
        ),
    ),
    MisconfigVerdict.M09: _TemplateText(
        terraform=(
            "# Not applicable in place -- StorageEncrypted cannot be toggled on an\n"
            "# existing instance. Restore an encrypted copy instead:\n"
            'resource "aws_db_instance" "encrypted_replacement" {\n'
            "  snapshot_identifier = aws_db_snapshot.encrypted_copy.id\n"
            "  storage_encrypted    = true\n"
            "}"
        ),
        cli="""aws rds create-db-snapshot --db-instance-identifier <DB_ID> --db-snapshot-identifier <SNAPSHOT_ID>
aws rds copy-db-snapshot --source-db-snapshot-identifier <SNAPSHOT_ID> --target-db-snapshot-identifier <SNAPSHOT_ID>-encrypted --kms-key-id <KMS_KEY_ID>
aws rds restore-db-instance-from-db-snapshot --db-instance-identifier <DB_ID>-encrypted --db-snapshot-identifier <SNAPSHOT_ID>-encrypted""",
        side_effects=(
            "Requires a maintenance window: the application must cut over to a "
            "new DB instance endpoint, since encryption cannot be enabled on the "
            "original instance in place."
        ),
    ),
    MisconfigVerdict.M10: _TemplateText(
        terraform="""resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}""",
        cli="""aws ec2 enable-ebs-encryption-by-default
aws ec2 create-snapshot --volume-id <VOLUME_ID>
aws ec2 copy-snapshot --source-snapshot-id <SNAPSHOT_ID> --encrypted --source-region <REGION>
# create a new encrypted volume from the encrypted snapshot copy and swap it in""",
        side_effects=(
            "Enabling default encryption only affects new volumes going forward; "
            "an existing unencrypted volume must be replaced via a "
            "snapshot-copy-restore cycle, which needs a brief detach/reattach on "
            "the instance using it."
        ),
    ),
}


def get_fix_template(misconfig_type: Union[MisconfigVerdict, str]) -> FixTemplate | None:
    """Looks up the vetted template for a flagged misconfiguration.

    Returns None for COMPLIANT, NEEDS_REVIEW, or any other value with no
    fix defined -- there is nothing to remediate, so this is not an error.
    requires_approval is derived from APPROVAL_REQUIRED_VERDICTS (the same
    set AgentOutput's validator enforces) so the two can never drift apart.
    """
    if isinstance(misconfig_type, str):
        try:
            misconfig_type = MisconfigVerdict(misconfig_type)
        except ValueError:
            return None

    template = _TEMPLATE_TEXT.get(misconfig_type)
    if template is None:
        return None

    return FixTemplate(
        misconfig_type=misconfig_type.value,
        terraform=template.terraform,
        cli=template.cli,
        side_effects=template.side_effects,
        requires_approval=misconfig_type in APPROVAL_REQUIRED_VERDICTS,
    )

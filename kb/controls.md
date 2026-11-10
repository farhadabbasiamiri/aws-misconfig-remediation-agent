# CIS / AWS FSBP / MITRE ATT&CK Control Reference

This document is the knowledge base `kb/ingest.py` chunks, embeds, and loads
into Chroma for `app/tools/retrieval.py`'s `lookup_controls`. Each `##`
section below is one misconfiguration type and is embedded as a single
chunk, tagged with its resource type, control IDs, and MITRE ATT&CK
techniques.

Control and technique IDs here are a first mapping (see CLAUDE.md); they
must be verified against the CIS Benchmark version the team uses and
against attack.mitre.org before this is treated as authoritative.

## M01 - S3 bucket publicly readable

- Resource: S3
- Controls: AWS FSBP S3.1, S3.2, S3.8; CIS AWS Foundations Benchmark 2.1.x
- MITRE ATT&CK: T1530 (Data from Cloud Storage Object)

An S3 bucket is publicly readable when its account- or bucket-level Block
Public Access settings are disabled and either its ACL or bucket policy
grants read access to `AllUsers` or `AuthenticatedUsers`. This is one of
the most common root causes of real-world cloud data breaches: anyone on
the internet can list and download objects without authenticating.
Remediation enables all four Block Public Access settings
(`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`,
`RestrictPublicBuckets`) and removes any public grant from the bucket
policy or ACL. Verdicts must be based on the bucket's configuration, never
its name or tags, since a bucket can be named misleadingly in either
direction.

## M02 - S3 default encryption missing

- Resource: S3
- Controls: AWS FSBP S3 default encryption control; CIS AWS Foundations
  Benchmark 2.1.x
- MITRE ATT&CK: T1530 (Data from Cloud Storage Object)

A bucket with no default server-side encryption configuration leaves
object-level encryption up to whatever uploaded the object, which is easy
to get wrong. AWS encrypts new S3 objects with SSE-S3 by default since
January 2023, so this control mainly targets legacy buckets created before
that change, or buckets where a compliance requirement calls for SSE-KMS
specifically rather than the default SSE-S3. Remediation sets a default
encryption configuration on the bucket (SSE-S3 or SSE-KMS as required) so
every future object is encrypted at rest regardless of how it is uploaded.

## M03 - SSH or RDP open to the internet

- Resource: EC2 (Security Group)
- Controls: AWS FSBP EC2.13, EC2.53; CIS AWS Foundations Benchmark 5.2, 5.3
- MITRE ATT&CK: T1133 (External Remote Services), T1110 (Brute Force)

A security group rule that allows inbound TCP traffic on port 22 (SSH) or
3389 (RDP) from `0.0.0.0/0` or `::/0` exposes a remote-access port to the
entire internet. Automated scanners and botnets continuously probe for
exactly this and attempt credential-stuffing or brute-force logins within
minutes of exposure. A rule that restricts the same port to a private CIDR
range (for example `10.0.0.0/8`) or a specific known IP is compliant and
must not be flagged — the control is about the source CIDR, not the port
itself. Remediation narrows the rule to a bastion host, VPN range, or
Session Manager / SSM, and removes the open-to-the-world rule.

## M04 - IAM policy with wildcard Action and Resource

- Resource: IAM
- Controls: AWS FSBP IAM.1; CIS AWS Foundations Benchmark 1.16
- MITRE ATT&CK: T1078.004 (Valid Accounts: Cloud Accounts), T1098 (Account
  Manipulation)

An IAM policy statement with `Effect: Allow`, `Action: "*"`, and
`Resource: "*"` grants unrestricted access to every action on every
resource in the account. If the identity holding this policy is ever
compromised — a leaked access key, an over-permissioned CI/CD role, a
vulnerable EC2 instance profile — the attacker inherits full control of the
account. A `Condition` block (for example restricting the source IP) does
not clear this finding: its strength cannot be verified from the policy
document alone, so the team's decision is to flag it regardless and let a
human reviewer judge whether the condition is sufficient. Remediation
scopes the policy down to the specific actions and resource ARNs the
identity actually needs.

## M05 - Root account without MFA

- Resource: IAM (root account)
- Controls: AWS FSBP IAM.9; CIS AWS Foundations Benchmark 1.5
- MITRE ATT&CK: T1078.004 (Valid Accounts: Cloud Accounts), T1110 (Brute
  Force)

The AWS account root user cannot be restricted by any IAM policy, so it is
the single highest-value credential in the account. If multi-factor
authentication is not enabled on it, a leaked or guessed root password is
enough for full, unrestricted account takeover, including billing and the
ability to close the account. Remediation enables a hardware or virtual
MFA device on the root user immediately and moves day-to-day
administration to a named IAM user or role instead.

## M06 - Active access key older than 90 days

- Resource: IAM
- Controls: AWS FSBP IAM.3; CIS AWS Foundations Benchmark 1.14
- MITRE ATT&CK: T1078.004 (Valid Accounts: Cloud Accounts), T1552
  (Unsecured Credentials)

A long-lived IAM access key increases the odds that it has already leaked
into a public GitHub repository, a CI log, or a developer's laptop at some
point without anyone noticing. Regular key rotation limits how long a
leaked credential stays valid even if the leak itself was never detected.
This finding requires human approval before remediation even though its
severity is Medium, because rotating or deactivating a key can break
whatever automation currently depends on it — the fix must be reviewed
before being applied. Remediation rotates the key and updates any service
or script that uses it, then deactivates the old one.

## M07 - CloudTrail missing, stopped, or single-region

- Resource: CloudTrail
- Controls: AWS FSBP CloudTrail.1; CIS AWS Foundations Benchmark 3.1
- MITRE ATT&CK: T1562.008 (Impair Defenses: Disable Cloud Logs)

CloudTrail is the account's audit log of every API call made against it.
An account with no trail configured, a trail that has been stopped, or a
trail that only covers a single region has a blind spot: actions taken
outside that coverage leave no record. Disabling logging is frequently one
of the first things an attacker does after gaining access, specifically to
cover their tracks, which is why MITRE classifies it as a defense-evasion
technique rather than just an operational oversight. Remediation creates
(or restarts) a multi-region trail with log file validation enabled and
delivers logs to a bucket the compromised principal cannot also write to.

## M08 - RDS instance publicly accessible

- Resource: RDS
- Controls: AWS FSBP RDS.2; CIS AWS Foundations Benchmark 2.3.x
- MITRE ATT&CK: T1190 (Exploit Public-Facing Application), T1110 (Brute
  Force)

An RDS instance with `PubliclyAccessible` set to true is reachable directly
from the internet instead of only from within its VPC. Publicly reachable
databases are a frequent target for credential-stuffing, unpatched-CVE
exploitation, and ransomware campaigns that scan for exposed database
ports at scale. Remediation disables public accessibility and, if external
access is genuinely required, puts the database behind a bastion, VPN, or
application-layer proxy instead of exposing it directly.

## M09 - RDS storage not encrypted

- Resource: RDS
- Controls: AWS FSBP RDS.3; CIS AWS Foundations Benchmark 2.3.1
- MITRE ATT&CK: T1537 (Transfer Data to Cloud Account)

An RDS instance with `StorageEncrypted` set to false stores its data, and
any snapshot taken of it, in plaintext at rest. If a snapshot is ever
shared or accidentally made public, the data inside it is immediately
readable by whoever has it, with no additional step required. Most
compliance frameworks (PCI-DSS, HIPAA, SOC 2) treat encryption at rest as a
baseline control auditors explicitly check for. Remediation requires
creating a new encrypted instance from an encrypted snapshot, since
storage encryption cannot be turned on for an existing unencrypted
instance in place.

## M10 - EBS volume not encrypted

- Resource: EBS
- Controls: AWS FSBP EC2.7; CIS AWS Foundations Benchmark 2.2.1
- MITRE ATT&CK: T1537 (Transfer Data to Cloud Account)

An EBS volume with encryption disabled, or an account/region with EBS
default encryption turned off, stores its data in plaintext. The main risk
is a snapshot of that volume being shared or leaked: a plaintext snapshot
can expose everything on the original disk, including credentials or
private keys that happened to be stored on it. Remediation enables
account-level default EBS encryption going forward and migrates existing
unencrypted volumes by creating an encrypted snapshot copy and launching a
replacement volume from it.

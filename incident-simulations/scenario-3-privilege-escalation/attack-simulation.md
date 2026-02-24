# Attack Simulation: IAM Privilege Escalation

**Scenario:** 3 of 3
**Type:** IAM Over-Permissive Policy — Privilege Escalation via Inline Policy
**Date Executed:** 2026-02-14
**Executed By:** Helmey Abdulsalam (lab exercise)

---

## Objective

Simulate a privilege escalation attack where a user or attacker creates an IAM
user with a wildcard admin policy (`Action: *`, `Resource: *`), effectively
granting full AWS account access. The goal is to verify that IAM Access Analyzer
detects the dangerous policy automatically and that remediation restores
least-privilege access.

This scenario differs from Scenarios 1 and 2 in that:
- The threat is **configuration-based**, not behavior-based
- Detection is **proactive** (policy scanner), not reactive (CloudTrail alert)
- The attacker's goal is **persistence and lateral movement**, not data theft

---

## Pre-Attack Setup

### Dangerous Policy Document
Created `admin-policy.json`:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    ]
}
```

This policy grants **full administrator access** — equivalent to the AWS managed
`AdministratorAccess` policy but attached as a custom inline policy to avoid
detection by simple policy name checks.

### Detection Infrastructure Active
| Component            | Configuration                                          |
|----------------------|--------------------------------------------------------|
| CloudTrail           | Management events enabled — captures all IAM API calls |
| IAM Access Analyzer  | `sec-lab-analyzer` — Resource analysis, current account|
| CloudWatch Logs      | All events delivered to `/sec-lab/cloudtrail`          |

---

## Attack Execution

### Step 1 — Create the Victim User
```bash
aws iam create-user --user-name test-overprivileged-user
```
**Result:** User created with ARN `arn:aws:iam::340805528222:user/test-overprivileged-user`

### Step 2 — Attach Dangerous Inline Policy
```bash
aws iam put-user-policy \
    --user-name test-overprivileged-user \
    --policy-name DangerousAdminPolicy \
    --policy-document file://admin-policy.json
```
**Time:** 2026-02-14T02:33:47Z
**Effect:** User now has unrestricted access to ALL AWS services and resources

### Step 3 — Create Access Key (Weaponize)
```bash
aws iam create-access-key --user-name test-overprivileged-user
```
**Access Key ID:** `AKIAU6WMXVKPJ72RS6FT`
**Status:** Active — used in production Feb 23, 2026

### Step 4 — Verify Escalation Worked
```bash
aws iam list-user-policies --user-name test-overprivileged-user
```
**Output confirms:** `DangerousAdminPolicy` is active

---

## Privilege Escalation Impact

With `Action: *` on `Resource: *`, the attacker can:
- Read/write/delete any S3 bucket in the account
- Create/delete IAM users, roles, and policies
- Launch/terminate EC2 instances
- Access secrets in Secrets Manager and SSM Parameter Store
- Exfiltrate data from any AWS service
- Create backdoor admin users for persistence
- Disable CloudTrail logging to cover tracks

This is effectively **full account takeover**.

---

## Real Evidence from CloudTrail (Feb 23, 2026)

After the access key was refreshed on Feb 23, the attacker immediately used
the escalated privileges:

```
2026-02-23T20:28:38Z | CreateAccessKey  | Helmey           ← new key issued
2026-02-23T20:30:13Z | ListUserPolicies | test-overprivileged-user ← attacker active
```

Only **92 seconds** elapsed between key creation and first use — confirming
the credentials were immediately weaponized.

---

## Detection: IAM Access Analyzer

IAM Access Analyzer (`sec-lab-analyzer`) scanned the account and flagged:

| Field         | Value                                        |
|---------------|----------------------------------------------|
| Resource      | `test-overprivileged-user`                   |
| Finding Type  | Over-permissive inline policy                |
| Policy Name   | `DangerousAdminPolicy`                       |
| Issue         | `Action: *` on `Resource: *`                 |
| Risk Level    | HIGH                                         |
| Status        | ACTIVE                                       |
| Detection lag | 30–60 minutes after policy creation          |

---

## Remediation Applied

### Step 1 — Remove Dangerous Policy
```bash
aws iam delete-user-policy \
    --user-name test-overprivileged-user \
    --policy-name DangerousAdminPolicy
```

### Step 2 — Apply Least-Privilege Policy
```bash
aws iam put-user-policy \
    --user-name test-overprivileged-user \
    --policy-name LeastPrivilegePolicy \
    --policy-document file://least-privilege-policy.json
```

Where `least-privilege-policy.json` is:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::sec-lab-confidential-data",
                "arn:aws:s3:::sec-lab-confidential-data/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeSecurityGroups"
            ],
            "Resource": "*"
        }
    ]
}
```

### Step 3 — Deactivate Access Key
```bash
aws iam update-access-key \
    --user-name test-overprivileged-user \
    --access-key-id AKIAU6WMXVKPJ72RS6FT \
    --status Inactive
```

---

## Before vs After

| Dimension       | Before (DangerousAdminPolicy)   | After (LeastPrivilegePolicy)          |
|-----------------|---------------------------------|---------------------------------------|
| Actions allowed | ALL (`*`)                       | `s3:ListBucket`, `s3:GetObject`, 2 EC2 reads |
| Resources       | ALL (`*`)                       | Specific S3 bucket only               |
| Risk level      | CRITICAL                        | LOW                                   |
| Policy type     | Inline (harder to audit)        | Inline with named scoped permissions  |

---

## Key Differences from Scenarios 1 & 2

| Dimension        | Scenario 1 (Honeypot)    | Scenario 2 (Exfiltration) | Scenario 3 (Privesc)       |
|------------------|--------------------------|---------------------------|----------------------------|
| Threat type      | Unauthorized access       | Credential abuse          | Configuration misconfiguration |
| Detection method | EventBridge + Lambda      | CloudWatch burst alarm    | IAM Access Analyzer (proactive) |
| Detection time   | 9 seconds                 | ~5 minutes                | 30–60 minutes              |
| Attacker goal    | Recon / data theft        | Bulk data exfiltration    | Persistence / full takeover|
| Response         | Automated IP block        | Manual key revocation     | Policy replacement         |

---

## Files Generated During Simulation

| File | Description |
|---|---|
| `cloudtrail-evidence/sample-event.json` | CloudTrail `PutUserPolicy` event — the escalation moment |
| `incident-report.md` | Full forensic analysis and remediation documentation |

---

*All credentials shown in this document are from a controlled lab environment.
The access key `AKIAU6WMXVKPJ72RS6FT` has been deactivated.*

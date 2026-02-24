# Incident Report: IAM Privilege Escalation via Dangerous Inline Policy

**Date:** 2026-02-14 (created) / 2026-02-23 (active exploitation)
**Severity:** CRITICAL
**Status:** Detected — Policy Replaced with Least-Privilege
**Analyst:** Helmey Abdulsalam
**Scenario:** 3 of 3

---

## Executive Summary

An IAM user (`test-overprivileged-user`) was created with a custom inline policy
(`DangerousAdminPolicy`) granting unrestricted access to all AWS services and
resources (`Action: *`, `Resource: *`). This constitutes a **privilege escalation**
vulnerability — any entity with access to this user's credentials has full
account administrator access.

IAM Access Analyzer (`sec-lab-analyzer`) detected the policy as a HIGH severity
finding. The dangerous policy was subsequently replaced with a scoped
least-privilege policy.

---

## Incident Timeline

| Time (UTC)               | Event                                         | Actor   |
|--------------------------|-----------------------------------------------|---------|
| 2026-02-14T02:33:00Z     | `CreateUser` — test-overprivileged-user       | Helmey  |
| 2026-02-14T02:33:47Z     | `PutUserPolicy` — DangerousAdminPolicy        | Helmey  |
| 2026-02-14T02:34:10Z     | `CreateAccessKey` — AKIAU6WMXVKPJ72RS6FT      | Helmey  |
| 2026-02-14T~03:30:00Z    | IAM Access Analyzer detects HIGH finding      | Automated |
| 2026-02-23T20:28:38Z     | `CreateAccessKey` — key refreshed             | Helmey  |
| 2026-02-23T20:30:13Z     | `ListUserPolicies` — attacker verifies access | test-overprivileged-user |
| 2026-02-23T22:56:48Z     | `GetUserPolicy` — policy reviewed by analyst  | Helmey  |
| 2026-02-23T~23:00:00Z    | Remediation applied — policy replaced         | Helmey  |

---

## Attacker Profile

| Field          | Value                                                        |
|----------------|--------------------------------------------------------------|
| IAM User       | `test-overprivileged-user`                                   |
| ARN            | `arn:aws:iam::340805528222:user/test-overprivileged-user`    |
| Access Key     | `AKIAU6WMXVKPJ72RS6FT` (Active → Deactivated)               |
| Policy         | `DangerousAdminPolicy` — inline, `Action:*`, `Resource:*`    |
| Created By     | `Helmey` (admin user — simulating insider or compromised admin) |
| Active Period  | 2026-02-14 to 2026-02-23 (~9 days with full admin access)    |

---

## Policy Risk Analysis

### Dangerous Policy (Before)
```json
{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
}
```
**Risk:** Full account takeover. Any action on any resource. Equivalent to root.

### Least-Privilege Policy (After)
```json
{
    "Effect": "Allow",
    "Action": ["s3:ListBucket", "s3:GetObject"],
    "Resource": [
        "arn:aws:s3:::sec-lab-confidential-data",
        "arn:aws:s3:::sec-lab-confidential-data/*"
    ]
}
```
**Risk:** Low. Read-only access to one specific S3 bucket.

---

## IAM Access Analyzer Finding

| Field         | Value                                          |
|---------------|------------------------------------------------|
| Analyzer      | `sec-lab-analyzer`                             |
| Finding type  | Over-permissive policy — external access risk  |
| Resource      | `arn:aws:iam::340805528222:user/test-overprivileged-user` |
| Policy name   | `DangerousAdminPolicy`                         |
| Severity      | HIGH                                           |
| Status        | ACTIVE → RESOLVED after remediation            |

---

## Key Evidence: 92-Second Weaponization

The most critical finding from CloudTrail analysis:

```
20:28:38Z  →  CreateAccessKey by Helmey for test-overprivileged-user
20:30:13Z  →  ListUserPolicies called BY test-overprivileged-user
```

The 92-second gap between key creation and first use confirms the credentials
were immediately handed to an attacker or automated script. The attacker's
first action was `ListUserPolicies` — verifying what permissions they had,
a standard post-exploitation enumeration step.

---

## Containment Actions Taken

1. `DangerousAdminPolicy` deleted from `test-overprivileged-user`
2. `LeastPrivilegePolicy` applied with scoped S3 read-only permissions
3. Access key `AKIAU6WMXVKPJ72RS6FT` deactivated
4. IAM Access Analyzer finding marked as resolved
5. Full timeline documented

---

## Remediation Recommendations

### Immediate
1. Audit all IAM users for inline policies with `Action: *`
2. Rotate all access keys older than 90 days
3. Enable MFA for all IAM users with console access

### Preventive Controls
4. Use AWS Organizations SCPs to deny `iam:PutUserPolicy` for non-admin roles
5. Create a CloudWatch alarm for `PutUserPolicy` and `AttachUserPolicy` events
6. Enforce IAM permission boundaries on all new users
7. Replace inline policies with managed policies for easier auditing

### Detection Improvements
8. Wire IAM Access Analyzer findings to EventBridge → SNS for real-time alerts
9. Enable AWS Config rule `iam-user-no-policies-check` to flag inline policies
10. Schedule weekly IAM credential reports review

---

## Key Learnings

- Wildcard policies (`Action: *`) are the IAM equivalent of a master key —
  they should never exist outside the root account
- Inline policies are harder to audit than managed policies — attackers prefer
  them for this reason
- IAM Access Analyzer is proactive but has a 30–60 minute detection lag —
  CloudTrail alerting on `PutUserPolicy` would have been faster
- The 92-second weaponization window shows how quickly stolen credentials
  are exploited in the real world

---

*Evidence collected: 2026-02-14 to 2026-02-23 | Lab: AWS us-east-1 | Account: 340805528222*

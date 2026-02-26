# Incident Report: Privilege Escalation via Over-Permissive IAM Policy

**Date:** 2026-02-23
**Severity:** CRITICAL
**Status:** Detected — Automated Remediation Applied
**Analyst:** Helmey Abdulsalam
**Scenario:** 3 of 3
**NCA ECC Controls:** 9.1 (Data Protection), 7.1 (Logging), 7.2 (Incident Management), 6.1 (Access Management)
**SAMA CSF Alignment:** CSF-3.1 (Anomaly Detection), CSF-4.2 (Incident Response), CSF-5.1 (Data Classification)

---

## الملخص

في بيئة معملية على منصة AWS، تم رصد محاولة تصعيد صلاحيات عبر إرفاق سياسة IAM خطيرة (DangerousAdminPolicy) بمستخدم غير مصرح له، مما يمنحه صلاحيات إدارية كاملة على الحساب.

تم اكتشاف الحادثة عبر IAM Access Analyzer الذي رصد السياسة المفرطة في الصلاحيات، فيما أطلق EventBridge تلقائيًا دالة Lambda لتصحيح السياسة واستبدالها بصلاحيات محدودة وفق مبدأ الحد الأدنى من الامتيازات، مع إرسال تنبيه فوري عبر SNS.

يُجسّد هذا السيناريو أحد أخطر أنواع التهديدات الداخلية في المؤسسات المالية، حيث يستغل المهاجمون أو الموظفون المخترقون ثغرات في إدارة الهوية والصلاحيات للحصول على وصول غير مشروع.

---

## Executive Summary

An administrator (or misconfigured automation) attached a `DangerousAdminPolicy` to `test-overprivileged-user`, granting unrestricted `*:*` permissions across the AWS account. IAM Access Analyzer continuously scanned policies and flagged this as an overly permissive finding. The detection pipeline — CloudWatch Logs → EventBridge → Lambda — automatically remediated the policy by replacing it with a least-privilege version and notifying the SOC team via SNS.

This is a **CRITICAL severity** scenario because unrestricted IAM permissions represent a complete account compromise risk. An attacker who obtains these credentials gains the ability to create new admin users, disable logging, exfiltrate all data, or destroy infrastructure.

This scenario reflects real-world misconfigurations I have observed in financial environments, where overly broad IAM policies are often created for convenience and left unreviewed — a risk that automated detection and remediation directly addresses.

---

## Detection Performance Metrics

| Metric | Value | Industry Benchmark |
|--------|-------|--------------------|
| **MTTD** (Mean Time to Detect) | < 2 minutes (IAM Access Analyzer continuous scan) | < 5 minutes (typical requirement) |
| **MTTR** (Mean Time to Respond) | < 60 seconds (automated Lambda remediation) | < 15 minutes (best practice) |
| **Detection Method** | IAM Access Analyzer + CloudWatch + EventBridge | Policy-based continuous monitoring |
| **Automation Status** | Fully automated (Lambda policy replacement + SNS) | ✅ Best practice achieved |

---

## Visual Attack Timeline

```text
┌─────────────────────────────────────────────────────────────────┐
│            PRIVILEGE ESCALATION ATTACK TIMELINE                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  T+00s  ──► Admin attaches DangerousAdminPolicy                 │
│            └─► PutUserPolicy on test-overprivileged-user        │
│                                                                 │
│  T+30s  ──► CloudTrail records IAM event                        │
│            └─► PutUserPolicy logged to CloudWatch Logs          │
│                                                                 │
│  T+45s  ──► IAM Access Analyzer flags overly permissive policy  │
│            └─► Finding: Action * on Resource * — CRITICAL       │
│                                                                 │
│  T+60s  ──► EventBridge rule triggers on analyzer finding       │
│            └─► Rule: IAM policy allows * actions                │
│                                                                 │
│  T+65s  ──► Lambda sec-lab-rotate-keys / isolate executes       │
│            ├─► DangerousAdminPolicy detached                    │
│            ├─► least-privilege-policy.json attached             │
│            └─► IAM access key rotation triggered                │
│                                                                 │
│  T+70s  ──► SNS Alert sent to SOC email                         │
│            └─► Subject: CRITICAL — Privilege Escalation Detected│
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
Total Response Time: ~70 seconds | Detection: Automated | Action: Automated
```

---

## Attack Timeline

| # | Time (UTC)           | Event                                            | Notes                                    |
|---|----------------------|--------------------------------------------------|------------------------------------------|
| 1 | 2026-02-23T21:10:00Z | `PutUserPolicy` — DangerousAdminPolicy attached  | Misconfiguration or malicious admin act  |
| 2 | 2026-02-23T21:10:30Z | CloudTrail records IAM policy change             | Logged to CloudWatch Logs                |
| 3 | 2026-02-23T21:10:45Z | IAM Access Analyzer flags policy                 | Finding severity: CRITICAL               |
| 4 | 2026-02-23T21:11:00Z | EventBridge rule matches IAM finding             | Auto-remediation pipeline triggered      |
| 5 | 2026-02-23T21:11:05Z | Lambda `sec-lab-rotate-keys` executes            | Dangerous policy detached, key rotated   |
| 6 | 2026-02-23T21:11:10Z | Lambda `sec-lab-isolate-ec2` evaluates           | Checks for associated EC2 compromise     |
| 7 | 2026-02-23T21:11:10Z | SNS notification sent                            | SOC team alerted via email               |

_All data, identities, and timestamps are generated in a controlled lab environment._

---

## Attacker / Misconfiguration Profile

| Field              | Value                                                                 |
|--------------------|-----------------------------------------------------------------------|
| Source IP          | `203.0.113.77` (RFC 5737 test IP used for lab documentation)         |
| IAM User (target)  | `test-overprivileged-user-[REDACTED]`                                 |
| User ARN           | `arn:aws:iam::123456789012:user/test-overprivileged-user-[REDACTED]`  |
| Dangerous Policy   | `DangerousAdminPolicy` — grants `*:*` on all resources               |
| IAM Action         | `PutUserPolicy` (inline policy attachment)                           |
| Performed By       | `lab-admin-[REDACTED]` (simulated misconfiguration)                  |

> **Note:** All account IDs, ARNs, and IP addresses above are anonymized or replaced with documentation-only values.

---

## Policy Analysis

### DangerousAdminPolicy (Attached — CRITICAL)

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

**Risk:** Grants full unrestricted access to every AWS service and resource in the account. Equivalent to root access.

### least-privilege-policy.json (Auto-Remediation Replacement)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": "arn:aws:s3:::sec-lab-public-data*"
    }
  ]
}
```

**Result:** User restricted to read-only access on public data bucket only.

---

## Containment Actions Taken

- `DangerousAdminPolicy` automatically detached from `test-overprivileged-user-[REDACTED]`.
- `least-privilege-policy.json` automatically attached as replacement.
- IAM access key for affected user rotated via Lambda `sec-lab-rotate-keys`.
- EC2 instances evaluated for potential compromise via Lambda `sec-lab-isolate-ec2`.
- SNS alert sent to SOC email within 70 seconds of policy attachment.
- Full CloudTrail audit trail preserved in CloudWatch Logs.

---

## Remediation Recommendations

| Priority | Recommendation                                                                                          | Implementation Timeline |
|----------|---------------------------------------------------------------------------------------------------------|-------------------------|
| CRITICAL | Enforce SCP (Service Control Policy) at Organizations level to block `*:*` policies account-wide      | Immediate               |
| HIGH     | Enable AWS Config rule `iam-no-inline-policies` to flag inline policy attachments in real time         | 1 week                  |
| HIGH     | Require MFA for all `PutUserPolicy` and `AttachUserPolicy` IAM actions                                 | 1 week                  |
| MEDIUM   | Implement IAM permission boundaries on all non-admin users to cap maximum privilege                    | 2 weeks                 |
| MEDIUM   | Schedule quarterly IAM Access Analyzer reviews and policy cleanup sprints                              | Ongoing                 |
| LOW      | Integrate GuardDuty IAM findings with SIEM for correlated privilege escalation detection               | 3–4 weeks               |

---

## NCA ECC Control Mapping (Saudi Context)

| NCA ECC Control                       | Implementation                                                                                              | Evidence Location          |
|---------------------------------------|-------------------------------------------------------------------------------------------------------------|----------------------------|
| **ECC 9.1 – Data Protection**         | Automated remediation prevents unrestricted data access before it can be exploited                         | Containment section        |
| **ECC 7.1 – Logging and Monitoring**  | CloudTrail IAM events + IAM Access Analyzer findings feed into continuous monitoring pipeline               | Detection Logic section    |
| **ECC 7.2 – Incident Management**     | Fully automated detection, remediation, and notification pipeline with documented playbook                 | This report                |
| **ECC 6.1 – Access Management**       | Least-privilege enforcement via automated policy replacement + IAM Access Analyzer continuous scanning     | Policy Analysis section    |

---

## SAMA Cybersecurity Framework Alignment (Banking Sector)

| SAMA CSF Control                   | Implementation in Lab                                                           |
|------------------------------------|---------------------------------------------------------------------------------|
| **CSF-3.1 – Anomaly Detection**    | IAM Access Analyzer continuously detects overly permissive policies             |
| **CSF-4.2 – Incident Response**    | Automated Lambda remediation replaces dangerous policy within 60 seconds        |
| **CSF-5.1 – Data Classification**  | IAM policies enforce data access boundaries aligned to classification levels    |

---

## MITRE ATT&CK Mapping

| Tactic               | Technique ID | Technique Name                        | Observed Behavior                             |
|----------------------|--------------|---------------------------------------|-----------------------------------------------|
| Privilege Escalation | T1098        | Account Manipulation                  | DangerousAdminPolicy attached to user         |
| Privilege Escalation | T1078.004    | Valid Accounts: Cloud Accounts        | Overprivileged user with stolen/misused creds |
| Defense Evasion      | T1562.001    | Impair Defenses: Disable/Modify Tools | `*:*` policy could disable CloudTrail/GuardDuty |
| Persistence          | T1136.003    | Create Account: Cloud Account         | Admin policy could be used to create backdoor users |

---

## 🔒 Safety & Compliance Disclaimer

This incident report describes a **simulated attack in a private AWS lab account** created solely for training and demonstration purposes.

### Redaction Summary

- All IAM access keys redacted to `AKIA****************[REDACTED]`
- All account IDs replaced with `123456789012` (documentation placeholder)
- All source IPs replaced with RFC 5737 test range addresses
- All ARNs anonymized with `[REDACTED]` suffix
- All user names anonymized with `[REDACTED]` suffix

### Lab Environment Safeguards

- Dedicated AWS account with strict budget cap
- All resources tagged `Environment=Lab`
- No production data or systems involved
- All credentials deactivated post-simulation
- `DangerousAdminPolicy` created and deleted within the lab session only

---

## Lessons Learned & Future Improvements

**Key Learnings**

- Over-permissive IAM policies (`*:*`) represent a complete account compromise risk and must be detected immediately.
- IAM Access Analyzer provides continuous policy scanning — far more effective than periodic manual reviews.
- Automated remediation is essential for CRITICAL severity findings — manual response is too slow.
- Combining multiple Lambda functions (rotate keys + isolate EC2) provides layered automated response.

**Process Improvements Implemented**

- IAM Access Analyzer integrated into continuous monitoring pipeline.
- EventBridge rule template created for IAM policy change detection.
- Automated least-privilege policy replacement documented and reusable.
- Incident playbook created for privilege escalation scenarios.

---

## Analyst Notes

Privilege escalation via over-permissive IAM policies is one of the most dangerous and common misconfigurations in AWS environments. Unlike external attacks, this threat often originates from internal mistakes — developers granting themselves broad access for convenience, or automation scripts applying overly permissive policies.

**Detection Strategy:** Continuous policy scanning (IAM Access Analyzer) combined with event-driven response (EventBridge + Lambda) is far more effective than periodic audits. The goal is to detect and remediate within seconds, not days.

**Exchange Background Relevance:** During my 6+ years at a Yemeni exchange company, I observed how privileged access mismanagement creates significant risk in financial operations. Employees with over-broad system access — even without malicious intent — represent a serious insider threat vector. This lab translates that experience into automated IAM governance controls.

---

## Report Metadata

| Field              | Value                                  |
|--------------------|----------------------------------------|
| Report ID          | `SEC-LAB-IR-2026-003`                  |
| Classification     | `SIMULATION (Lab Environment Only)`    |
| Distribution       | Internal Use / Portfolio Showcase      |
| Retention Period   | 1 year                                 |
| Review Date        | 2027-02-23                             |
| Approved By        | Helmey Abdulsalam                      |

---

_Built as part of **AWS Security Operations Lab** — a hands-on cybersecurity portfolio project. All credentials and data shown are fake and used for simulation purposes only._

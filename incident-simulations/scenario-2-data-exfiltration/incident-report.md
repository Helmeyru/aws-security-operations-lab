# Incident Report: Data Exfiltration from Confidential S3 Bucket

**Date:** 2026-02-23
**Severity:** HIGH
**Status:** Detected — Manual Containment Applied
**Analyst:** Helmey Abdulsalam
**Scenario:** 2 of 3
**NCA ECC Controls:** 9.1 (Data Protection), 7.1 (Logging), 7.2 (Incident Management), 6.1 (Access Management)
**SAMA CSF Alignment:** CSF-3.1 (Anomaly Detection), CSF-4.2 (Incident Response), CSF-5.1 (Data Classification)

---

## الملخص

في بيئة معملية على منصة AWS، قام مهاجم يمتلك بيانات اعتماد مسروقة لمستخدم IAM بتنفيذ عملية سحب جماعي لملفات مالية وبيانات شخصية حساسة من حاوية S3 سرية خلال فترة زمنية قصيرة (حوالي ٣ دقائق).

تم اكتشاف الهجوم من خلال تحليل سجلات CloudWatch Logs باستخدام استعلامات إحصائية أظهرت ارتفاعًا مفاجئًا في عدد عمليات التحميل (٦ تحميلات في دقيقة واحدة).

يوضح هذا السيناريو كيفية اكتشاف سلوك ضار مبني على نمط الاستخدام وليس على عناوين IP فقط، مع توثيق كامل لخطوات التحقيق والاحتواء والتوصيات لتحسين الضوابط الأمنية المستقبلية.

---

## Executive Summary

A threat actor using stolen IAM credentials (`test-exfil-user-[REDACTED]`) performed a systematic bulk download of sensitive financial and PII data from the `sec-lab-confidential-data` S3 bucket over a 3-minute window. The attack was detected via CloudWatch Logs Insights anomaly analysis, where a peak burst of **6 downloads in a single minute** was identified as the primary exfiltration indicator.

Unlike Scenario 1 (honeypot access), this bucket contained legitimately accessible data for this user — making this a compromised-credentials scenario where the access itself was authorized but the pattern was malicious.

This scenario mirrors financial data exfiltration patterns observed in money-exchange operations, where insiders or compromised users with legitimate access perform bulk downloads during short time windows. My 6+ years working with exchange and accounting systems help me recognize these subtle anomalies and translate them into practical detection logic and incident playbooks.

---

## Detection Performance Metrics

| Metric | Value | Industry Benchmark |
|--------|-------|--------------------|
| **MTTD** (Mean Time to Detect) | 47 seconds from first anomalous access | < 5 minutes (typical requirement) |
| **MTTR** (Mean Time to Respond) | 3 minutes (manual containment) | < 15 minutes (best practice) |
| **Detection Method** | CloudWatch Logs Insights burst pattern analysis | Real-time monitoring |
| **Automation Status** | Manual containment | EventBridge → Lambda recommended |

---

## Visual Attack Timeline

```text
┌─────────────────────────────────────────────────────────────────┐
│                 DATA EXFILTRATION ATTACK TIMELINE               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  20:54  ──► Reconnaissance                                      │
│            └─► finance/quarterly-results-q3.txt (1 file)        │
│                                                                 │
│  20:56  ──► Multi-file download begins                          │
│            ├─► finance/quarterly-results-q3.txt                 │
│            └─► finance/quarterly-results-q1.txt                 │
│                                                                 │
│  20:58  ──► Sensitive data targeted                             │
│            ├─► pii/pii-data.txt           (RESTRICTED)          │
│            └─► sensitive/customers.csv    (RESTRICTED)          │
│                                                                 │
│  20:59  ──► ⚠ BURST PATTERN DETECTED                            │
│            ├─► 6 files downloaded in 1 minute                   │
│            ├─► Multiple sensitive folders accessed              │
│            └─► CloudWatch anomaly query triggered               │
│                                                                 │
│  21:00  ──► Containment                                         │
│            └─► IAM access key deactivated                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
Total Duration: ~5 minutes | Total Files: 6 | Unique Folders: 3
```

---

## Attack Timeline

| #  | Time (UTC)               | File Accessed                        | Notes                         |
|----|--------------------------|--------------------------------------|-------------------------------|
| 1  | 2026-02-23T20:54:58Z     | `finance/quarterly-results-q3.txt`   | First access — recon          |
| 2  | 2026-02-23T20:56:49.243Z | `finance/quarterly-results-q3.txt`   | Re-download begins            |
| 3  | 2026-02-23T20:56:49.243Z | `finance/quarterly-results-q1.txt`   | Multi-file download           |
| 4  | 2026-02-23T20:57:33.074Z | `finance/quarterly-results-q3.txt`   | Sync retry                    |
| 5  | 2026-02-23T20:58:14.368Z | `pii/pii-data.txt`                   | PII folder targeted           |
| 6  | 2026-02-23T20:58:14.368Z | `sensitive/customers.csv`            | Sensitive folder targeted     |
| 7  | 2026-02-23T20:59:25.725Z | `finance/quarterly-results-q1.txt`   | BURST BEGINS — 5 files/1 min  |
| 8  | 2026-02-23T20:59:25.725Z | `finance/quarterly-results-q2.txt`   |                               |
| 9  | 2026-02-23T20:59:25.725Z | `finance/quarterly-results-q2.txt`   | Duplicate = sync tool         |
| 10 | 2026-02-23T20:59:25.725Z | `finance/quarterly-results.txt`      |                               |
| 11 | 2026-02-23T20:59:25.725Z | `pii/pii-data.txt`                   |                               |
| 12 | 2026-02-23T20:59:38.646Z | `sensitive/customers.csv`            | Final file — session ends     |

**Total attack duration:** ~5 minutes
**Total GetObject requests:** 12
**Unique files:** 6

_All data, identities, and timestamps are generated in a controlled lab environment and do not represent any real customer information or production systems._

---

## Attacker Profile

| Field            | Value                                                                |
|------------------|----------------------------------------------------------------------|
| Source IP        | `203.0.113.42` (RFC 5737 test IP used for lab documentation)        |
| IAM User         | `test-exfil-user-[REDACTED]`                                        |
| User ARN         | `arn:aws:iam::123456789012:user/test-exfil-user-[REDACTED]`         |
| Access Key       | `AKIA****************[REDACTED]` (lab key, now deactivated)         |
| Tool Used        | `aws s3 sync` (simulated automated bulk download)                   |
| Platform         | AWS CloudShell-equivalent Linux environment (lab only)              |
| Folders Accessed | `finance/`, `pii/`, `sensitive/` — lab folders containing test data |

> **Note:** All account IDs, ARNs, access keys, and IP addresses above are anonymized or replaced with documentation-only values and are not usable in any AWS environment.

---

## Burst Pattern (Primary Detection Signal)

| Minute Window            | Downloads | Status  |
|--------------------------|-----------|---------|
| 2026-02-23T20:59:00.000Z | 6         | ⚠ ALARM |
| 2026-02-23T20:58:00.000Z | 2         | Normal  |
| 2026-02-23T20:57:00.000Z | 1         | Normal  |
| 2026-02-23T20:56:00.000Z | 2         | Normal  |

The spike to 6 downloads in a single minute, combined with access to multiple sensitive folders, is the key anomaly used for alerting and auto-response design.

---

## Files Exfiltrated (Lab Data Only)

| File                               | Classification   | Times Downloaded |
|------------------------------------|------------------|------------------|
| `finance/quarterly-results-q1.txt` | CONFIDENTIAL     | 2                |
| `finance/quarterly-results-q2.txt` | CONFIDENTIAL     | 2                |
| `finance/quarterly-results-q3.txt` | CONFIDENTIAL     | 3                |
| `finance/quarterly-results.txt`    | CONFIDENTIAL     | 1                |
| `pii/pii-data.txt`                 | RESTRICTED (LAB) | 2                |
| `sensitive/customers.csv`          | RESTRICTED (LAB) | 2                |

_All file names and contents are synthetic and created exclusively for training purposes._

---

## Detection Queries Used

### Query 1: File-Level Access Log

```sql
fields @timestamp, eventName, sourceIPAddress, userIdentity.arn, requestParameters.key
| filter eventName = "GetObject"
  and requestParameters.bucketName = "sec-lab-confidential-data"
| sort @timestamp desc
| limit 50
```

### Query 2: Burst Pattern Anomaly (Primary Detection)

```sql
fields @timestamp, sourceIPAddress, userIdentity.arn
| filter eventName = "GetObject"
  and requestParameters.bucketName = "sec-lab-confidential-data"
| stats count() as downloads by bin(1m), sourceIPAddress, userIdentity.arn
| sort downloads desc
```

---

## Containment Actions Taken

- Lab IAM access key for `test-exfil-user-[REDACTED]` deactivated immediately.
- CloudTrail evidence preserved in CloudWatch Logs for post-incident analysis.
- Incident documented with full forensic timeline and detection logic.
- Access patterns reviewed for similar anomalies across other buckets.

---

## Remediation Recommendations

| Priority | Recommendation                                                                                   | Implementation Timeline |
|----------|--------------------------------------------------------------------------------------------------|-------------------------|
| HIGH     | Implement EventBridge → Lambda auto-response for abnormal S3 download bursts (>5 downloads/min) | 1–2 weeks               |
| HIGH     | Restrict access to confidential S3 buckets via VPC endpoints and private IP ranges only         | 1 week                  |
| MEDIUM   | Enforce MFA and device-based conditions for privileged S3 access using IAM and bucket policies  | 2 weeks                 |
| MEDIUM   | Deploy Amazon Macie for automated discovery and classification of PII and sensitive data        | 3–4 weeks               |
| LOW      | Integrate alerts into central SIEM and define playbooks for compromised-credentials scenarios   | Ongoing                 |

---

## NCA ECC Control Mapping (Saudi Context)

| NCA ECC Control                       | Implementation                                                                                                              | Evidence Location            |
|---------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|------------------------------|
| **ECC 9.1 – Data Protection**         | Data in `sec-lab-confidential-data` bucket is classified (CONFIDENTIAL / RESTRICTED) and monitored for anomalous access    | Files Exfiltrated section    |
| **ECC 7.1 – Logging and Monitoring**  | CloudTrail and CloudWatch provide centralized logging and near-real-time monitoring of S3 access activities                 | Detection Queries section    |
| **ECC 7.2 – Incident Management**     | Incident handled with clear detection, analysis, containment, and recommendations reflecting a repeatable process           | Containment & this report    |
| **ECC 6.1 – Access Management**       | Highlights risks of long-term IAM keys and recommends stronger authentication and IAM hygiene                               | Remediation Recommendations  |

> These mappings can be expanded or adjusted to match specific sectoral requirements (e.g., SAMA for banking, NDMO for government).

---

## SAMA Cybersecurity Framework Alignment (Banking Sector)

| SAMA CSF Control                   | Implementation in Lab                                                |
|------------------------------------|----------------------------------------------------------------------|
| **CSF-3.1 – Anomaly Detection**    | CloudWatch burst pattern detection for abnormal download volumes     |
| **CSF-4.2 – Incident Response**    | Documented containment steps and remediation recommendations         |
| **CSF-5.1 – Data Classification**  | CONFIDENTIAL vs RESTRICTED PII classification in bucket structure    |

> SAMA CSF is mandatory for all Saudi banks and financial institutions. This lab demonstrates foundational compliance capabilities.

---

## MITRE ATT&CK Mapping

| Scenario              | Tactic             | Technique ID | Technique Name                          |
|-----------------------|--------------------|--------------|-----------------------------------------|
| Honeypot S3 Access    | Collection         | T1530        | Data from Cloud Storage                 |
| Data Exfiltration     | Exfiltration       | T1537        | Transfer Data to Cloud Account          |
| Privilege Escalation  | Privilege Escalation | T1098      | Account Manipulation                    |

---

## 🔒 Safety & Compliance Disclaimer

This incident report describes a **simulated attack in a private AWS lab account** created solely for training and demonstration purposes.

### Redaction Summary

- All IAM access keys redacted to `AKIA****************[REDACTED]`
- All account IDs replaced with `123456789012` (documentation placeholder)
- All source IPs replaced with `203.0.113.42` (RFC 5737 test range)
- All ARNs anonymized with `[REDACTED]` suffix

### Lab Environment Safeguards

- Dedicated AWS account with strict budget cap
- All resources tagged `Environment=Lab`
- No production data or systems involved
- All credentials deactivated post-simulation

> ⚠ Never commit real credentials to GitHub — even deactivated keys trigger security scanners and can disqualify candidates from Saudi cybersecurity roles. Always use AWS example key format or proper redaction techniques.

---

## Lessons Learned & Future Improvements

**Key Learnings**

- Authorized-but-malicious access requires behavioral detection (not just IP blocking).
- Burst pattern analysis is highly effective for detecting bulk data exfiltration.
- Manual containment is too slow — automation can reduce MTTR from minutes to seconds.
- Data classification (CONFIDENTIAL vs RESTRICTED) enables targeted monitoring.

**Process Improvements Implemented**

- Added CloudWatch metric filter prototype for S3 download bursts.
- Created EventBridge rule template for auto-response (Phase 3).
- Documented incident playbook for compromised-credentials scenarios.
- Integrated NCA ECC and SAMA CSF mapping into all future incident reports.

---

## Analyst Notes

This scenario demonstrates a real-world insider-threat pattern common in financial institutions:

- User has legitimate access to sensitive data.
- Attack occurs during normal business hours (blends with normal activity).
- Bulk download performed rapidly (3-minute window).
- Multiple sensitive folders targeted (`finance/`, `pii/`, `sensitive/`).

**Detection Strategy:** Focus on behavioral anomalies (burst patterns, multi-folder access) rather than only IP reputation or access time.

**Exchange Background Relevance:** During my 6+ years at a Yemeni exchange company, I observed similar patterns where employees with legitimate access performed bulk downloads before leaving the organization. This lab translates those real-world observations into automated detection logic.

---

## Report Metadata

| Field              | Value                                  |
|--------------------|----------------------------------------|
| Report ID          | `SEC-LAB-IR-2026-002`                  |
| Classification     | `SIMULATION (Lab Environment Only)`    |
| Distribution       | Internal Use / Portfolio Showcase      |
| Retention Period   | 1 year                                 |
| Review Date        | 2027-02-23                             |
| Approved By        | Helmey Abdulsalam                      |

---

_Built as part of **AWS Security Operations Lab** — a hands-on cybersecurity portfolio project. All credentials and data shown are fake and used for simulation purposes only._

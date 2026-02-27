# Incident Report: Data Exfiltration Detection

**Date:** 2026-02-23
**Severity:** HIGH
**Status:** Detected — Manual SOC Investigation & Containment
**Analyst:** Helmey Abdulsalam
**Scenario:** 2 of 3
**NCA ECC Controls:** 9.1 (Data Protection), 7.1 (Logging), 7.2 (Incident Management), 6.1 (Access Management)
**SAMA CSF Alignment:** CSF-3.1 (Anomaly Detection), CSF-4.2 (Incident Response), CSF-5.1 (Data Classification)

---

## 🇸🇦 الملخص التنفيذي (بالعربية)

في بيئة معملية على منصة AWS، تم رصد محاولة تهريب بيانات حساسة من حاوية S3 تحتوي على ملفات مالية وبيانات PII.

تم اكتشاف النشاط عبر استعلام CloudWatch Logs Insights الذي كشف عن تنزيل 3 ملفات حساسة خلال 7 ثوانٍ من عنوان IP غير معتاد، مما أطلق تنبيهاً عبر CloudWatch إلى فريق SOC.

على عكس سيناريو Honeypot الذي يتضمن استجابة آلية فورية، اعتمد هذا السيناريو على الفرز اليدوي من قِبل المحلل الأمني قبل اتخاذ إجراءات الاحتواء، وذلك للحدّ من خطر الإيجابيات الكاذبة وتجنّب تعطيل عمليات الأعمال المشروعة.

---

## Executive Summary

An unauthorized bulk download of sensitive data was detected from the `sec-lab-confidential-data` bucket. The threat actor (`exfil-test-user`) downloaded 3 sensitive files — including financial reports and PII data — in 7 seconds from a non-corporate IP address, matching classic data exfiltration behavior patterns.

The detection pipeline used CloudWatch Logs Insights anomaly queries to identify the unusual access pattern. Unlike the honeypot scenario, this detection required **SOC analyst triage** before containment — a deliberate architectural decision aligned with industry best practice for production data environments. The CloudWatch alarm escalated to the SOC team, who confirmed the incident and revoked access within the defined SLA.

---

## Why Manual Response for Data Exfiltration

Unlike honeypot access — which is an unambiguous malicious signal because no legitimate user has any reason to access a decoy bucket — data exfiltration detection carries significantly higher false-positive risk. A legitimate bulk download by an authorized user (e.g., a data analyst running a scheduled export, a backup process, or an engineer syncing files for an audit) could trigger the exact same CloudWatch Logs Insights pattern used for detection.

Automated access revocation on production data buckets carries serious business disruption risk: terminating a legitimate user's access mid-operation could corrupt batch jobs, break dependent pipelines, or violate SLA commitments to business stakeholders. In financial environments especially, a false-positive automated block on a finance team member during month-end close could have significant operational consequences.

SOC best practice for data exfiltration scenarios is therefore: **detection → human triage → confirmed response**, not fully automated remediation. The CloudWatch alarm escalates to the SOC analyst, who reviews the CloudTrail evidence, validates the IP address, checks the user's normal behavior baseline, and makes the containment decision within a defined SLA (target: 15 minutes from alert). This human-in-the-loop model balances security responsiveness with operational resilience.

| Factor | Honeypot Access | Data Exfiltration |
|--------|----------------|-------------------|
| False positive risk | **Zero** — no legitimate access exists | **Medium** — authorized users access the same bucket |
| Automated response safe? | **Yes** — always malicious | **No** — risks disrupting legitimate operations |
| Response model | Fully automated (Lambda) | Detection → SOC triage → confirmed action |
| Containment SLA | < 30 seconds (automated) | < 15 minutes (human-confirmed) |

---

## Detection Performance Metrics

| Metric | Value | Industry Benchmark |
|--------|-------|--------------------|
| **MTTD** (Mean Time to Detect) | < 5 minutes (CloudWatch Logs Insights anomaly) | < 5 minutes (typical requirement) |
| **MTTR** (Mean Time to Respond) | < 15 minutes (SOC analyst confirmed response) | < 15 minutes (best practice) |
| **Detection Method** | CloudWatch Logs Insights + CloudWatch Alarm | Log-based anomaly detection |
| **Response Model** | Manual SOC triage → confirmed containment | Human-in-the-loop (intentional) |

---

## Visual Attack Timeline

```text
┌─────────────────────────────────────────────────────────────────┐
│              DATA EXFILTRATION ATTACK TIMELINE                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  T+00s  ──► Attacker lists confidential bucket                  │
│            └─► ListObjects on sec-lab-confidential-data         │
│                                                                 │
│  T+05s  ──► Download quarterly-results-q1.txt                   │
│            └─► GET /finance/quarterly-results-q1.txt            │
│                                                                 │
│  T+08s  ──► Download quarterly-results-q2.txt                   │
│            └─► GET /finance/quarterly-results-q2.txt            │
│                                                                 │
│  T+12s  ──► Download pii-data.txt                               │
│            └─► GET /pii/pii-data.txt (cross-folder access)      │
│                                                                 │
│  T+14s  ──► Bulk sync of finance folder initiated               │
│            └─► aws s3 sync s3://sec-lab-confidential-data       │
│                                                                 │
│  T+4min ──► CloudWatch Logs Insights anomaly detected           │
│            └─► 3 files in 7 seconds from non-corporate IP       │
│                                                                 │
│  T+5min ──► CloudWatch Alarm triggers → SNS → SOC email         │
│            └─► Subject: HIGH — S3 Data Exfiltration Pattern     │
│                                                                 │
│  T+8min ──► SOC analyst reviews CloudTrail evidence             │
│            └─► IP verified non-corporate; user baseline checked │
│                                                                 │
│  T+12min ──► Analyst confirms — Access revoked                  │
│            └─► exfil-test-user access keys deactivated          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
Total Response Time: ~12 minutes | Detection: Automated | Action: Human-confirmed
```

---

## Attack Timeline

| # | Time (UTC)           | Event                                             | Notes                                   |
|---|----------------------|---------------------------------------------------|-----------------------------------------|
| 1 | 2026-02-23T15:42:10Z | `ListObjects` on confidential bucket              | Reconnaissance — mapping bucket content |
| 2 | 2026-02-23T15:42:15Z | `GetObject` — quarterly-results-q1.txt            | Financial data downloaded               |
| 3 | 2026-02-23T15:42:18Z | `GetObject` — quarterly-results-q2.txt            | Financial data downloaded               |
| 4 | 2026-02-23T15:42:22Z | `GetObject` — pii-data.txt                        | PII data downloaded (cross-folder)      |
| 5 | 2026-02-23T15:42:25Z | `s3 sync` — bulk finance folder download          | Systematic bulk exfiltration            |
| 6 | 2026-02-23T15:45:00Z | CloudWatch Logs Insights anomaly detected         | 3 files in 7s from non-corporate IP     |
| 7 | 2026-02-23T15:45:30Z | CloudWatch Alarm → SNS → SOC email                | Analyst notified                        |
| 8 | 2026-02-23T15:50:00Z | SOC analyst reviews CloudTrail evidence           | IP, user, timing validated              |
| 9 | 2026-02-23T15:54:00Z | Access confirmed malicious — containment executed | exfil-test-user keys deactivated        |

_All data, identities, and timestamps are generated in a controlled lab environment._

---

## Attacker Profile

| Field           | Value                                                                   |
|-----------------|-------------------------------------------------------------------------|
| Source IP       | `203.0.113.99` (RFC 5737 test IP used for lab documentation)            |
| IAM User        | `exfil-test-user-[REDACTED]`                                            |
| User ARN        | `arn:aws:iam::123456789012:user/exfil-test-user-[REDACTED]`             |
| Access Key      | `AKIA****************[REDACTED]` (lab key, now deactivated)             |
| Bucket Accessed | `sec-lab-confidential-data-[REDACTED]`                                  |
| Files Accessed  | `quarterly-results-q1.txt`, `quarterly-results-q2.txt`, `pii-data.txt` |
| User Agent      | `aws-cli/2.x` — automated download, not console browser                 |

> **Note:** All account IDs, ARNs, access keys, and IP addresses above are anonymized or replaced with documentation-only values.

---

## Files Accessed (Sensitive Simulation Data)

| File                        | Folder    | Classification | Content (Simulated)              |
|-----------------------------|-----------|----------------|----------------------------------|
| `quarterly-results-q1.txt`  | `/finance` | CONFIDENTIAL  | Q1 2026 revenue, profit figures  |
| `quarterly-results-q2.txt`  | `/finance` | CONFIDENTIAL  | Q2 2026 revenue, profit figures  |
| `pii-data.txt`              | `/pii`     | CRITICAL — PII | SSN, name, DOB (simulated)       |

_These files contain no real data and are created exclusively for simulation purposes._

---

## Detection Logic Used

### CloudWatch Logs Insights Query (Anomaly Detection)

```sql
fields timestamp, eventName, sourceIPAddress, userIdentity.arn,
       requestParameters.key
| filter eventName = "GetObject"
      and requestParameters.bucketName = "sec-lab-confidential-data-[REDACTED]"
| stats count(*) as download_count by bin(5m), sourceIPAddress, userIdentity.arn
| sort download_count desc
| limit 20
```

**Red Flags Identified:**
- 3 files downloaded in 7 seconds (unusual speed — indicates automated/scripted access)
- Files from different folders accessed together (`/finance` + `/pii` — unusual cross-folder pattern)
- Source IP not in corporate IP range
- AWS CLI user agent — bulk download behavior, not interactive console session

### CloudWatch Metric Filter

```text
Filter Pattern:
{ $.eventName = "GetObject" && $.requestParameters.bucketName = "sec-lab-confidential-data-*" }

Metric: SecurityMetrics/s3-confidential-downloads
Alarm: Triggers on > 5 downloads in 5 minutes → SNS alert to SOC email
```

---

## Indicators of Compromise (IoCs)

| Type        | Value                                                  | Risk |
|-------------|--------------------------------------------------------|------|
| Source IP   | `203.0.113.99` — non-corporate, non-VPC IP address     | HIGH |
| User        | `exfil-test-user-[REDACTED]` — accessed multiple folders in 7s | HIGH |
| User Agent  | `aws-cli/2.x` — scripted download pattern             | MEDIUM |
| Time of Day | Outside business hours                                 | MEDIUM |
| Files       | Cross-folder access (`/finance` + `/pii`) in same session | HIGH |

---

## Containment Actions Taken

- SOC analyst reviewed CloudTrail evidence and confirmed unauthorized access.
- `exfil-test-user-[REDACTED]` access keys deactivated via IAM console.
- Source IP `203.0.113.99` added to S3 bucket policy deny list.
- Full CloudTrail event log preserved for forensic analysis.
- Data classification review initiated for all files in the confidential bucket.

---

## Remediation Recommendations

| Priority | Recommendation                                                                                  | Implementation Timeline |
|----------|-------------------------------------------------------------------------------------------------|-------------------------|
| CRITICAL | Restrict confidential bucket access to VPC Endpoints only (`aws:SourceVpc` condition)         | Immediate               |
| HIGH     | Require MFA for all `GetObject` calls on sensitive buckets                                    | 1 week                  |
| HIGH     | Implement S3 Object Lock for immutable protection of PII and financial records                | 1 week                  |
| MEDIUM   | Deploy S3 Access Points with per-user access policies and IP restrictions                     | 2 weeks                 |
| MEDIUM   | Enable User Entity Behavior Analytics (UEBA) for baseline anomaly scoring                    | 2–3 weeks               |
| LOW      | Implement DLP (Data Loss Prevention) tagging for PII and financial data objects               | Ongoing                 |

---

## NCA ECC Control Mapping (Saudi Context)

| NCA ECC Control                       | Implementation                                                                                    | Evidence Location       |
|---------------------------------------|---------------------------------------------------------------------------------------------------|-------------------------|
| **ECC 9.1 – Data Protection**         | Confidential bucket contains classified data with IAM-based access controls                      | Files Accessed section  |
| **ECC 7.1 – Logging and Monitoring**  | CloudTrail S3 Data Events + CloudWatch Logs Insights enable full access visibility               | Detection Logic section |
| **ECC 7.2 – Incident Management**     | Documented detection-to-response pipeline with SOC analyst triage and defined SLA               | This report             |
| **ECC 6.1 – Access Management**       | IAM user access keys deactivated upon confirmed incident; VPC endpoint restriction recommended  | Containment section     |

---

## SAMA Cybersecurity Framework Alignment (Banking Sector)

| SAMA CSF Control                   | Implementation in Lab                                                               |
|------------------------------------|-------------------------------------------------------------------------------------|
| **CSF-3.1 – Anomaly Detection**    | CloudWatch Logs Insights detects anomalous download velocity and cross-folder access |
| **CSF-4.2 – Incident Response**    | Human-in-the-loop triage ensures confirmed incidents before containment action      |
| **CSF-5.1 – Data Classification**  | PII and financial data stored in segregated folders with distinct classification labels |

---

## MITRE ATT&CK Mapping

| Tactic       | Technique ID | Technique Name                       | Observed Behavior                          |
|--------------|--------------|--------------------------------------|--------------------------------------------|
| Collection   | T1530        | Data from Cloud Storage              | Bulk GetObject from S3 confidential bucket |
| Exfiltration | T1537        | Transfer Data to Cloud Account       | AWS CLI sync to external session           |
| Discovery    | T1619        | Cloud Storage Object Discovery       | ListObjects to map bucket contents         |
| Initial Access | T1078      | Valid Accounts                       | Legitimate IAM keys used for unauthorized bulk access |

---

## 🔒 Safety & Compliance Disclaimer

This incident report describes a **simulated attack in a private AWS lab account** created solely for training and demonstration purposes.

### Redaction Summary

- All IAM access keys redacted to `AKIA****************[REDACTED]`
- All account IDs replaced with `123456789012` (documentation placeholder)
- All source IPs replaced with RFC 5737 test range addresses
- All ARNs anonymized with `[REDACTED]` suffix
- Bucket name suffix redacted

### Lab Environment Safeguards

- Dedicated AWS account with strict budget cap
- All resources tagged `Environment=Lab`
- No production data or systems involved
- All credentials deactivated post-simulation
- Simulated data files contain no real PII or financial information

---

## Lessons Learned & Future Improvements

**Key Learnings**

- CloudWatch Logs Insights provides powerful anomaly detection but requires tuned queries — default metrics alone are insufficient for exfiltration detection.
- Cross-folder access in a single session is a high-fidelity exfiltration indicator worth building a dedicated detection rule for.
- Human-in-the-loop triage is the correct model for production data — preventing both false-positive disruption and unnecessary automation risk.
- CloudTrail data events must be explicitly enabled on S3 buckets — they are not on by default.

**Process Improvements Implemented**

- CloudWatch anomaly query documented and saved for reuse across environments.
- Detection-to-triage-to-response SLA established: alert → analyst review → action within 15 minutes.
- Logs preserved in CloudWatch for post-incident forensic reconstruction.
- Remediation recommendations prioritized by business impact and implementation complexity.

---

## Analyst Notes

Data exfiltration via legitimate IAM credentials is one of the hardest attack types to detect because the access itself looks authorized. The key detection signals are behavioral: unusual velocity, cross-resource access patterns, non-standard source IPs, and automated user agents. CloudWatch Logs Insights enables these behavioral queries against CloudTrail data — combining the auditability of CloudTrail with the analytical power of a query engine.

**Exchange Background Relevance:** In financial operations, insider data exfiltration is a top risk vector. Employees with legitimate read access to customer or financial records can exfiltrate data without triggering traditional access controls. The behavioral detection approach modeled here — anomaly velocity + cross-folder pattern + IP analysis — directly maps to detection strategies I would apply in a real exchange environment to protect customer and transaction data.

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

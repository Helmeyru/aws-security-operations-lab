# Incident Report: Honeypot S3 Bucket Access

**Date:** 2026-02-23
**Severity:** MEDIUM
**Status:** Detected — Automated Containment Applied
**Analyst:** Helmey Abdulsalam
**Scenario:** 1 of 3
**NCA ECC Controls:** 9.1 (Data Protection), 7.1 (Logging), 7.2 (Incident Management), 6.1 (Access Management)
**SAMA CSF Alignment:** CSF-3.1 (Anomaly Detection), CSF-4.2 (Incident Response), CSF-5.1 (Data Classification)

---

##الملخص

في بيئة معملية على منصة AWS، تمكن مهاجم مجهول من الوصول إلى حاوية S3 مصيدة (Honeypot) تحتوي على ملفات وهمية مصممة لاستدراج المهاجمين وكشف نشاطهم.

تم رصد الحادثة فور وصول المهاجم إلى الحاوية عبر CloudTrail، الذي سجّل حدث GetObject وأرسله إلى EventBridge، مما أطلق تلقائيًا دالة Lambda لحظر عنوان IP المهاجم وإرسال تنبيه فوري عبر SNS.

يُبرز هذا السيناريو قيمة تقنية Honeypot كأداة استخباراتية أمنية مبكرة تكشف النشاط الاستطلاعي قبل أن يتطور إلى هجوم حقيقي.

---

## Executive Summary

An unknown threat actor accessed the `sec-lab-honeypot` S3 bucket, which was intentionally seeded with decoy files designed to attract and expose unauthorized reconnaissance activity. The access was detected immediately via CloudTrail S3 Data Events, triggering an automated response pipeline: EventBridge matched the access pattern, Lambda executed IP blocking via S3 bucket policy, and SNS delivered an alert to the SOC email.

The honeypot bucket serves as an early-warning system — any access to it is inherently suspicious since no legitimate user has a business reason to access it. This zero-false-positive detection method is highly effective for identifying credential compromise and insider reconnaissance.

This scenario reflects techniques used in financial institutions to detect insider threats and compromised credentials — a pattern I observed during my 6+ years in exchange operations, where early detection is critical before sensitive data is reached.

---

## Detection Performance Metrics

| Metric | Value | Industry Benchmark |
|--------|-------|--------------------|
| **MTTD** (Mean Time to Detect) | < 10 seconds (event-driven) | < 5 minutes (typical requirement) |
| **MTTR** (Mean Time to Respond) | < 30 seconds (automated Lambda) | < 15 minutes (best practice) |
| **Detection Method** | CloudTrail S3 Data Event → EventBridge rule | Real-time event-driven |
| **Automation Status** | Fully automated (Lambda + SNS) | ✅ Best practice achieved |

---

## Visual Attack Timeline

```text
┌─────────────────────────────────────────────────────────────────┐
│                  HONEYPOT ACCESS ATTACK TIMELINE                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  T+00s  ──► Attacker accesses honeypot bucket                   │
│            └─► GET s3://sec-lab-honeypot/leaked-credentials.txt │
│                                                                 │
│  T+02s  ──► CloudTrail records GetObject event                  │
│            └─► S3 Data Event logged to CloudWatch Logs          │
│                                                                 │
│  T+05s  ──► EventBridge rule matches honeypot access pattern    │
│            └─► Rule: bucket = sec-lab-honeypot + GetObject      │
│                                                                 │
│  T+08s  ──► Lambda function triggered                           │
│            ├─► honeypot-auto-block-ip executes                  │
│            └─► S3 bucket policy updated (Deny aws:SourceIp)     │
│                                                                 │
│  T+12s  ──► SNS Alert sent to SOC email                         │
│            └─► Subject: ALERT — Honeypot Bucket Accessed        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
Total Response Time: ~12 seconds | Detection: Automated | Action: Automated
```

---

## Attack Timeline

| # | Time (UTC)           | Event                                      | Notes                              |
|---|----------------------|--------------------------------------------|------------------------------------|
| 1 | 2026-02-23T20:30:15Z | `GetObject` on `sec-lab-honeypot` bucket   | First and only access — recon      |
| 2 | 2026-02-23T20:30:17Z | CloudTrail records S3 Data Event           | Logged to CloudWatch Logs          |
| 3 | 2026-02-23T20:30:20Z | EventBridge rule triggers                  | Pattern matched: honeypot access   |
| 4 | 2026-02-23T20:30:23Z | Lambda `honeypot-auto-block-ip` executes   | IP added to bucket deny policy     |
| 5 | 2026-02-23T20:30:27Z | SNS notification sent                      | SOC team alerted via email         |

_All data, identities, and timestamps are generated in a controlled lab environment._

---

## Attacker Profile

| Field            | Value                                                                |
|------------------|----------------------------------------------------------------------|
| Source IP        | `203.0.113.55` (RFC 5737 test IP used for lab documentation)        |
| IAM User         | Unknown — unauthenticated or stolen key access                      |
| User ARN         | `arn:aws:iam::123456789012:user/[REDACTED]`                         |
| Access Key       | `AKIA****************[REDACTED]` (lab key, now deactivated)         |
| Files Accessed   | `leaked-credentials.txt`, `customer-data.sql` (decoy files)         |
| Bucket           | `sec-lab-honeypot-[REDACTED]` (intentionally public decoy bucket)   |

> **Note:** All account IDs, ARNs, access keys, and IP addresses above are anonymized or replaced with documentation-only values.

---

## Files Accessed (Decoy Files Only)

| File                     | Classification  | Purpose                            |
|--------------------------|-----------------|------------------------------------|
| `leaked-credentials.txt` | DECOY (LAB)     | Attract credential-harvesting bots |
| `customer-data.sql`      | DECOY (LAB)     | Simulate database leak scenario    |

_These files contain no real data and are created exclusively to trigger detection._

---

## Detection Logic Used

### EventBridge Rule (Honeypot Trigger)

```json
{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["GetObject"],
    "requestParameters": {
      "bucketName": ["sec-lab-honeypot-REDACTED"]
    }
  }
}
```

### Lambda Auto-Response: `honeypot-auto-block-ip`

```python
# Extracts attacker IP from event
# Updates S3 bucket policy to deny that specific IP
# Publishes SNS alert to SOC email
```

---

## Containment Actions Taken

- Attacker IP automatically blocked via S3 bucket policy (`Deny aws:SourceIp`).
- SNS alert sent to SOC email within 12 seconds of access.
- CloudTrail event preserved in CloudWatch Logs for forensic analysis.
- No sensitive data was exposed (all files in honeypot are decoys).

---

## Remediation Recommendations

| Priority | Recommendation                                                                                    | Implementation Timeline |
|----------|---------------------------------------------------------------------------------------------------|-------------------------|
| HIGH     | Extend auto-block to also revoke IAM access key if identity is known                             | 1 week                  |
| HIGH     | Add GuardDuty integration to correlate honeypot access with other threat signals                 | 1–2 weeks               |
| MEDIUM   | Deploy additional honeypot buckets in other regions for broader coverage                         | 2 weeks                 |
| MEDIUM   | Enrich SNS alert with geolocation and ASN data for faster triage                                | 2–3 weeks               |
| LOW      | Rotate decoy file names periodically to avoid pattern recognition by sophisticated attackers     | Ongoing                 |

---

## NCA ECC Control Mapping (Saudi Context)

| NCA ECC Control                       | Implementation                                                                                        | Evidence Location          |
|---------------------------------------|-------------------------------------------------------------------------------------------------------|----------------------------|
| **ECC 9.1 – Data Protection**         | Honeypot bucket contains only decoy files — no real data exposed at any point                        | Files Accessed section     |
| **ECC 7.1 – Logging and Monitoring**  | CloudTrail S3 Data Events feed into CloudWatch Logs for real-time monitoring                         | Detection Logic section     |
| **ECC 7.2 – Incident Management**     | Fully automated detection and response pipeline with documented playbook                             | Containment section        |
| **ECC 6.1 – Access Management**       | Lambda auto-response immediately restricts attacker access via bucket policy update                  | Containment section        |

---

## SAMA Cybersecurity Framework Alignment (Banking Sector)

| SAMA CSF Control                   | Implementation in Lab                                                     |
|------------------------------------|---------------------------------------------------------------------------|
| **CSF-3.1 – Anomaly Detection**    | Any access to honeypot bucket is inherently anomalous — zero false positives |
| **CSF-4.2 – Incident Response**    | Fully automated Lambda response with SNS alerting within 12 seconds      |
| **CSF-5.1 – Data Classification**  | Decoy files clearly marked and isolated from real data in separate bucket |

---

## MITRE ATT&CK Mapping

| Tactic               | Technique ID | Technique Name                  | Observed Behavior                        |
|----------------------|--------------|---------------------------------|------------------------------------------|
| Reconnaissance       | T1592        | Gather Victim Host Information  | Attacker accessed decoy credentials file |
| Collection           | T1530        | Data from Cloud Storage         | GetObject on honeypot S3 bucket          |
| Initial Access       | T1078        | Valid Accounts                  | Access via potentially stolen credentials|

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

---

## Lessons Learned & Future Improvements

**Key Learnings**

- Honeypot buckets provide zero-false-positive detection — any access is a confirmed threat signal.
- Event-driven architecture (CloudTrail → EventBridge → Lambda) enables sub-30-second automated response.
- Decoy file naming matters — files named `leaked-credentials.txt` attract more opportunistic attackers.
- Automated containment significantly outperforms manual response in speed and consistency.

**Process Improvements Implemented**

- Automated IP blocking via Lambda reduces MTTR to under 30 seconds.
- SNS alerting ensures SOC team is notified even outside business hours.
- Detection logic documented and reusable for other bucket types.

---

## Analyst Notes

The honeypot technique is particularly valuable in financial environments where distinguishing legitimate from malicious access is difficult. By creating a bucket that no legitimate user should ever touch, any access event becomes an unambiguous threat indicator — eliminating alert fatigue caused by false positives.

**Exchange Background Relevance:** In exchange operations, dormant or legacy accounts are often targeted by insiders. A honeypot approach — placing monitored decoy resources in expected locations — mirrors strategies I would apply to detect unauthorized access to financial systems.

---

## Report Metadata

| Field              | Value                                  |
|--------------------|----------------------------------------|
| Report ID          | `SEC-LAB-IR-2026-001`                  |
| Classification     | `SIMULATION (Lab Environment Only)`    |
| Distribution       | Internal Use / Portfolio Showcase      |
| Retention Period   | 1 year                                 |
| Review Date        | 2027-02-23                             |
| Approved By        | Helmey Abdulsalam                      |

---

_Built as part of **AWS Security Operations Lab** — a hands-on cybersecurity portfolio project. All credentials and data shown are fake and used for simulation purposes only._

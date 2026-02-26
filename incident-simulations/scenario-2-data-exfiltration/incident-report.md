# Incident Report: Data Exfiltration from Confidential S3 Bucket

**Date:** 2026-02-23
**Severity:** HIGH
**Status:** Detected — Manual Containment Applied
**Analyst:** Helmey Abdulsalam
**Scenario:** 2 of 3

---

## Executive Summary

A threat actor using stolen IAM credentials (`test-exfil-user`) performed a systematic
bulk download of sensitive financial and PII data from the `sec-lab-confidential-data`
S3 bucket over a 3-minute window. The attack was detected via CloudWatch Logs Insights
anomaly analysis. A peak burst of **6 downloads in a single minute** was identified as
the primary exfiltration indicator.

Unlike Scenario 1 (honeypot access), this bucket contained legitimately accessible data
for this user — making this a compromised-credentials scenario where the access itself
was authorized but the pattern was malicious.

---

## Attack Timeline

| # | Time (UTC)               | File Accessed                        | Notes                         |
|---|--------------------------|--------------------------------------|-------------------------------|
| 1 | 2026-02-23T20:54:58Z     | `finance/quarterly-results-q3.txt`   | First access — recon          |
| 2 | 2026-02-23T20:56:49.243Z | `finance/quarterly-results-q3.txt`   | Re-download begins            |
| 3 | 2026-02-23T20:56:49.243Z | `finance/quarterly-results-q1.txt`   | Multi-file download           |
| 4 | 2026-02-23T20:57:33.074Z | `finance/quarterly-results-q3.txt`   | Sync retry                    |
| 5 | 2026-02-23T20:58:14.368Z | `pii/pii-data.txt`                   | PII folder targeted           |
| 6 | 2026-02-23T20:58:14.368Z | `sensitive/customers.csv`            | Sensitive folder targeted     |
| 7 | 2026-02-23T20:59:25.725Z | `finance/quarterly-results-q1.txt`   | BURST BEGINS — 5 files/1 min  |
| 8 | 2026-02-23T20:59:25.725Z | `finance/quarterly-results-q2.txt`   |                               |
| 9 | 2026-02-23T20:59:25.725Z | `finance/quarterly-results-q2.txt`   | Duplicate = sync tool         |
|10 | 2026-02-23T20:59:25.725Z | `finance/quarterly-results.txt`      |                               |
|11 | 2026-02-23T20:59:25.725Z | `pii/pii-data.txt`                   |                               |
|12 | 2026-02-23T20:59:38.646Z | `sensitive/customers.csv`            | Final file — session ends     |

**Total attack duration:** ~5 minutes | **Total GetObject requests:** 12 | **Unique files:** 6

---

## Attacker Profile

| Field            | Value                                                        |
|------------------|--------------------------------------------------------------|
| Source IP        | `3X.X.X.X` (AWS CloudShell us-east-1)                    |
| IAM User         | `test-exfil-user`                                            |
| User ARN         | `arn:aws:iam::*:user/test-exfil-user`             |
| Access Key       | `AKIAU6WMXVKPGQRLXCVQ` (long-term key)                       |
| Tool Used        | `aws s3 sync` (automated bulk download)                      |
| Platform         | AWS CloudShell Linux (amzn2023)                              |
| Folders Accessed | `finance/`, `pii/`, `sensitive/` — all 3 sensitive dirs      |

---

## Burst Pattern (Primary Detection Signal)

| Minute Window            | Downloads | Status  |
|--------------------------|-----------|---------|
| 2026-02-23T20:59:00.000Z | 6         | ALARM |
| 2026-02-23T20:58:00.000Z | 2         | Normal  |
| 2026-02-23T20:57:00.000Z | 1         | Normal  |
| 2026-02-23T20:56:00.000Z | 2         | Normal  |

---

## Files Exfiltrated

| File                              | Classification | Times Downloaded |
|-----------------------------------|----------------|------------------|
| `finance/quarterly-results-q1.txt`| CONFIDENTIAL   | 2                |
| `finance/quarterly-results-q2.txt`| CONFIDENTIAL   | 2                |
| `finance/quarterly-results-q3.txt`| CONFIDENTIAL   | 3                |
| `finance/quarterly-results.txt`   | CONFIDENTIAL   | 1                |
| `pii/pii-data.txt`                | RESTRICTED PII | 2                |
| `sensitive/customers.csv`         | RESTRICTED PII | 2                |

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

### Query 2: Burst Pattern Anomaly
```sql
fields @timestamp, sourceIPAddress, userIdentity.arn
| filter eventName = "GetObject"
  and requestParameters.bucketName = "sec-lab-confidential-data"
| stats count() as downloads by bin(1m), sourceIPAddress, userIdentity.arn
| sort downloads desc
```

---

## Containment Actions Taken

1. `test-exfil-user` access key `******CVQ` deactivated manually
2. CloudTrail evidence preserved in CloudWatch Logs
3. Incident documented with full forensic timeline

---

## Remediation Recommendations

1. Wire EventBridge → Lambda auto-response for bulk download detection
2. Restrict bucket access to VPC endpoint only
3. Enforce MFA for sensitive bucket access via bucket policy condition
4. Deploy Amazon Macie for automated PII classification
5. Set download volume threshold: auto-revoke key after >5 downloads/min

---

*Evidence collected: 2026-02-23 | Lab environment: AWS us-east-1 | Account: 340805528222*

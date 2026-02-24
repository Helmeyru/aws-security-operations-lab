# Incident Report: Honeypot S3 Access

**Date:** 2026-02-23
**Severity:** HIGH
**Status:** Resolved — IP Automatically Blocked
**Analyst:** Helmey Abdulsalam

---

## Incident Summary

An external threat actor used a stolen IAM access key (`test-exfil-user`) to download
honeypot files from the S3 bucket. The automated response system detected and blocked
the attacker's IP within **9 seconds** of the first file access.

---

## Attack Timeline

| Time (UTC)           | Event | Evidence |
|---|---|---|
| 2026-02-23 00:24:16Z | Attacker downloads `leaked-credentials.txt` | CloudTrail GetObject |
| 2026-02-23 00:24:28Z | Attacker downloads `customer-data.sql` | CloudTrail GetObject |
| 2026-02-23 00:34:16Z | Second download of `leaked-credentials.txt` | CloudTrail GetObject |
| 2026-02-23 00:34:25Z | Lambda fires — IP blocked via bucket policy | Lambda CloudWatch logs |
| 2026-02-23 00:34:25Z | SNS alert sent to security team | Email received |

**Total detection-to-block time: 9 seconds**

---

## Attacker Forensic Profile

| Field | Value |
|---|---|
| Source IP | `193.160.245.168` |
| IAM User | `test-exfil-user` |
| Access Key | `AKIAU6WMXVKPN2X2P3NP` |
| User Agent | `aws-cli/1.44.15` on **Windows 11 x64** |
| OS | Windows 11 (amd64) |
| Auth Method | SigV4 / AuthHeader |
| TLS Version | TLSv1.3 |
| Bytes transferred | 135 bytes (`leaked-credentials.txt`) + 138 bytes (`customer-data.sql`) |

The attacker operated **manually** from a Windows machine using AWS CLI — not an automated bot.
The 10-minute gap between access #2 and access #3 suggests manual review of downloaded content.

---

## CloudTrail Evidence (Raw — Row 1)

```json
{
  "eventTime": "2026-02-23T00:34:16Z",
  "eventName": "GetObject",
  "sourceIPAddress": "193.160.245.168",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::340805528222:user/test-exfil-user",
    "accessKeyId": "AKIAU6WMXVKPN2X2P3NP"
  },
  "requestParameters": {
    "bucketName": "sec-lab-honeypot-1771026055",
    "key": "leaked-credentials.txt"
  },
  "additionalEventData": {
    "bytesTransferredOut": 135,
    "AuthenticationMethod": "AuthHeader"
  }
}

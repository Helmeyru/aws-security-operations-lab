# Attack Simulation: Honeypot S3 Access

**Scenario:** 1 of 3
**Type:** Compromised IAM Credentials + Honeypot File Access
**Date Executed:** 2026-02-23
**Executed By:** Helmey Abdulsalam (lab exercise)

---

## Objective

Simulate an attacker who obtains leaked IAM credentials and uses them to access
sensitive-looking files in an S3 bucket. The goal is to trigger the automated
detection and response pipeline and verify it blocks the attacker's IP within seconds.

---

## Pre-Attack Setup

### Honeypot Bucket Contents
The following files were uploaded to `sec-lab-honeypot-1771026055` to act as bait.
The filenames were chosen to look highly valuable to an attacker:

```bash
# Create enticing decoy files
echo "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE" > leaked-credentials.txt
echo "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" >> leaked-credentials.txt
echo "DATABASE_PASSWORD=SuperSecretPassword123!" >> leaked-credentials.txt

echo "CUSTOMER_DATABASE_EXPORT_2026" > customer-data.sql
echo "INSERT INTO users VALUES (1,'john','password123','SSN:123-45-6789');" >> customer-data.sql
echo "INSERT INTO users VALUES (2,'jane','password456','SSN:987-65-4321');" >> customer-data.sql

# Upload to honeypot bucket
aws s3 cp leaked-credentials.txt s3://sec-lab-honeypot-1771026055/
aws s3 cp customer-data.sql s3://sec-lab-honeypot-1771026055/
```

All credentials and data above are **fake** — for simulation only.

### Bucket Listing at Attack Time
```
2026-02-14 02:45:37     29  config.env
2026-02-14 02:45:04     33  credentials.txt
2026-02-14 22:08:12    138  customer-data.sql
2026-02-14 02:45:30     50  database-backup.sql
2026-02-14 22:08:12    135  leaked-credentials.txt
```

### IAM User Used as Attacker
| Field | Value |
|---|---|
| Username | `test-exfil-user` |
| Access Key ID | `AKIAU6WMXVKPN2X2P3NP` |
| Permissions | `s3:GetObject`, `s3:ListBucket` on honeypot bucket |
| Purpose | Simulates an attacker who found leaked credentials |

---

## Detection Infrastructure Active During Attack

| Component | Configuration |
|---|---|
| CloudTrail | S3 data events enabled on `sec-lab-honeypot-1771026055` |
| EventBridge Rule | Matches `GetObject` on honeypot bucket via CloudTrail |
| Lambda | `honeypot-auto-block-ip` — extracts IP and updates bucket policy |
| SNS Topic | `sec-lab-honeypot-alerts` — email notification on trigger |

---

## Attack Execution

The attack was executed from a **Windows 11 machine** using AWS CLI,
configured with the `test-exfil-user` access key.
This simulates an attacker who found the credentials in a public GitHub repo or pastebin.

### Step 1 — Reconnaissance (List the bucket)
```bash
aws s3 ls s3://sec-lab-honeypot-1771026055/
```

### Step 2 — First Exfiltration Wave
```bash
aws s3 cp s3://sec-lab-honeypot-1771026055/leaked-credentials.txt ./
aws s3 cp s3://sec-lab-honeypot-1771026055/customer-data.sql ./
```
**Time:** 2026-02-23T00:24:16Z — 2026-02-23T00:24:28Z

### Step 3 — Return Visit (Re-download)
The attacker returned ~10 minutes later to download the credentials file again,
suggesting they reviewed the content and wanted a second copy:
```bash
aws s3 cp s3://sec-lab-honeypot-1771026055/leaked-credentials.txt ./
```
**Time:** 2026-02-23T00:34:16Z — **this triggered the Lambda successfully**

---

## Automated Response Triggered

The return visit at `00:34:16Z` fired the EventBridge rule and Lambda:

```
00:34:16Z  →  GetObject on leaked-credentials.txt
00:34:16Z  →  CloudTrail records event with sourceIPAddress: 193.160.245.168
00:34:16Z  →  EventBridge matches rule pattern
00:34:25Z  →  Lambda executes (9 seconds after access)
00:34:25Z  →  S3 Bucket Policy updated: Deny for 193.160.245.168/32
00:34:25Z  →  SNS alert sent to security team email
```

**Detection-to-block time: 9 seconds**

### Bucket Policy Deny Statement Added Automatically
```json
{
  "Sid": "DenyAttackerIP-193-160-245-168",
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": [
    "arn:aws:s3:::sec-lab-honeypot-1771026055",
    "arn:aws:s3:::sec-lab-honeypot-1771026055/*"
  ],
  "Condition": {
    "IpAddress": {
      "aws:SourceIp": "193.160.245.168/32"
    }
  }
}
```

---

## Verification — Attacker is Blocked

After the Lambda ran, any further access attempt from `193.160.245.168` returns:

```
An error occurred (AccessDenied) when calling the ListObjectsV2 operation:
Access Denied
```

---

## What Was NOT Used (Architecture Decision)

The original lab design used:
```
CloudWatch Metric Filter → CloudWatch Alarm → EventBridge → Lambda
```

This was **replaced** with:
```
CloudTrail → EventBridge (direct) → Lambda
```

**Reason:** Direct EventBridge consumption of CloudTrail events is faster (sub-10s),
simpler (fewer failure points), and delivers the full CloudTrail event payload —
including `sourceIPAddress` — directly to Lambda without polling.

The EC2 Security Group blocking approach in the original code was also **removed**
because Security Groups protect EC2 network interfaces only and have zero effect
on S3 API access. The correct control is the S3 Bucket Policy `aws:SourceIp` condition.

---

## Tools and Environment

| Component | Details |
|---|---|
| Attacker OS | Windows 11 x64 |
| Attacker tool | `aws-cli/1.44.15`, `Botocore/1.42.25`, `Python 3.12.6` |
| Auth method | SigV4 / AuthHeader |
| TLS version | TLSv1.3 / TLS_AES_128_GCM_SHA256 |
| Defender tooling | AWS CloudTrail, EventBridge, Lambda (Python 3.12), S3 Bucket Policy, SNS |

---

## Files Generated During Simulation

| File | Description |
|---|---|
| `cloudtrail-evidence/sample-event.json` | Raw CloudTrail event from the successful block |
| `incident-report.md` | Full forensic analysis and SOC response documentation |

---

*All credentials, IPs, and personal data shown in this document are simulated for lab purposes.*

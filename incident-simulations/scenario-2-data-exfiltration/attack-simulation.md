# Attack Simulation: Bulk S3 Data Exfiltration

**Scenario:** 2 of 3
**Type:** Compromised IAM Credentials + Bulk Download of Confidential Data
**Date Executed:** 2026-02-23
**Executed By:** Helmey Abdulsalam (lab exercise)

---

## Objective

Simulate an attacker who has obtained long-term IAM access keys and uses them
from AWS CloudShell to perform a bulk `s3 sync` of a confidential S3 bucket.
The goal is to verify that the CloudWatch Logs anomaly detection pipeline
identifies the burst download pattern and fires an alert.

Unlike Scenario 1 (honeypot — unauthorized access), this user had legitimate
`s3:GetObject` permissions on the bucket. This simulates a **compromised
credentials** or **insider threat** scenario where the access itself is
authorized but the behavior is malicious.

---

## Pre-Attack Setup

### Confidential Bucket Contents

The following files were pre-loaded into `sec-lab-confidential-data` to
represent realistic sensitive corporate data:

```bash
# Finance data
echo "Q1 Revenue: $4,200,000 | Expenses: $3,100,000 | Net: $1,100,000" > quarterly-results-q1.txt
echo "Q2 Revenue: $4,800,000 | Expenses: $3,400,000 | Net: $1,400,000" > quarterly-results-q2.txt
echo "Q3 Revenue: $5,100,000 | Expenses: $3,600,000 | Net: $1,500,000" > quarterly-results-q3.txt
echo "Annual Revenue: $18,900,000 | Total Expenses: $13,500,000"        > quarterly-results.txt

aws s3 cp quarterly-results-q1.txt s3://sec-lab-confidential-data/finance/
aws s3 cp quarterly-results-q2.txt s3://sec-lab-confidential-data/finance/
aws s3 cp quarterly-results-q3.txt s3://sec-lab-confidential-data/finance/
aws s3 cp quarterly-results.txt    s3://sec-lab-confidential-data/finance/

# PII data
echo "Name,Email,SSN,DOB" > pii-data.txt
echo "John Smith,john@example.com,123-45-6789,1985-03-12" >> pii-data.txt
echo "Jane Doe,jane@example.com,987-65-4321,1990-07-24"   >> pii-data.txt

aws s3 cp pii-data.txt s3://sec-lab-confidential-data/pii/

# Sensitive customer data
printf "id,name,email,plan
1,Acme Corp,acme@corp.com,Enterprise
" > customers.csv
printf "2,Globex,globex@corp.com,Pro
3,Initech,init@corp.com,Basic
" >> customers.csv

aws s3 cp customers.csv s3://sec-lab-confidential-data/sensitive/
```

All data above is **fake** — for simulation only.

### Bucket Structure at Attack Time
```
finance/quarterly-results-q1.txt   (54 bytes)
finance/quarterly-results-q2.txt   (54 bytes)
finance/quarterly-results-q3.txt   (54 bytes)
finance/quarterly-results.txt      (48 bytes)
pii/pii-data.txt                   (136 bytes)
sensitive/customers.csv            (150 bytes)
```

### IAM User Used as Attacker
| Field          | Value                                         |
|----------------|-----------------------------------------------|
| Username       | `test-exfil-user`                             |
| Access Key ID  | `AKIAU6WMXVKPGQRLXCVQ`                        |
| Permissions    | `s3:GetObject`, `s3:ListBucket` on confidential bucket |
| Purpose        | Simulates attacker with stolen long-term keys |

---

## Detection Infrastructure Active During Attack

| Component              | Configuration                                              |
|------------------------|------------------------------------------------------------|
| CloudTrail             | S3 data events enabled on `sec-lab-confidential-data`      |
| CloudWatch Logs        | All events delivered to `/sec-lab/cloudtrail`              |
| CloudWatch Alarm       | `data-exfiltration-anomaly` — fires if >5 downloads/5 min  |
| SNS Topic              | `sec-lab-honeypot-alerts` — email notification on trigger  |

**Note:** Unlike Scenario 1, no EventBridge → Lambda auto-block was wired to
this bucket. Detection was alerting-only, requiring manual response.

---

## Attack Execution

The attack was executed from **AWS CloudShell (us-east-1)** using the attacker's
long-term access key configured via `aws configure`.

This simulates an attacker who exfiltrated credentials (e.g., from a GitHub
leak, phishing, or exposed `.env` file) and is running commands from a cloud
environment to avoid geo-IP detection.

### Step 1 — Configure Stolen Credentials in CloudShell
```bash
aws configure set aws_access_key_id AKIAU6WMXVKPGQRLXCVQ
aws configure set aws_secret_access_key <stolen-secret-key>
aws configure set region us-east-1
```

### Step 2 — Reconnaissance (List the bucket)
```bash
aws s3 ls s3://sec-lab-confidential-data/ --recursive
```

### Step 3 — Bulk Exfiltration via `s3 sync`
```bash
aws s3 sync s3://sec-lab-confidential-data/ ./exfil/
```

**Time:** 2026-02-23T20:54:58Z — 2026-02-23T20:59:38Z

The `s3 sync` command recursively downloads all objects. It produced:
- 11 total `GetObject` API calls
- 6 unique files downloaded
- Peak burst of **6 downloads in a single minute** (20:59Z window)
- Duplicate downloads of q2, q3, pii-data, customers.csv — sync tool signature

---

## `s3 sync` Forensic Fingerprint

The use of `aws s3 sync` leaves a distinctive pattern visible in CloudTrail:

1. **Identical timestamps** — multiple files downloaded at `20:59:25.725Z`
   simultaneously, which is impossible for a human clicking manually
2. **Duplicate downloads** — `s3 sync` re-downloads files if checksums differ
   or on retry, creating duplicate `GetObject` events for the same key
3. **userAgent field** — contains `md/command#s3.sync` explicitly identifying
   the tool used:
   ```
   aws-cli/2.33.23 ... exec-env/CloudShell ... md/command#s3.sync
   ```
4. **sourceIPAddress** — `3.86.208.137` resolves to AWS CloudShell us-east-1,
   not a corporate office IP — attacker used cloud infrastructure

---

## Attack Timeline

| Time (UTC)               | Event                              | Downloads |
|--------------------------|------------------------------------|-----------|
| 2026-02-23T20:54:58Z     | First GetObject — q3.txt           | 1         |
| 2026-02-23T20:56:49.243Z | q3.txt + q1.txt                    | 2         |
| 2026-02-23T20:57:33.074Z | q3.txt re-download                 | 1         |
| 2026-02-23T20:58:14.368Z | pii-data.txt + customers.csv       | 2         |
| 2026-02-23T20:59:25.725Z | q1, q2, q2, results, pii, (burst)  | 5         |
| 2026-02-23T20:59:38.646Z | customers.csv (final file)         | 1         |

**Total:** 11 GetObject calls | 6 unique files | 3-minute window

---

## Detection Result

The `data-exfiltration-anomaly` CloudWatch alarm fired on the 6-download burst
in the 20:59Z minute window, exceeding the threshold of >5 downloads per minute.

| Metric              | Value                        |
|---------------------|------------------------------|
| Detection method    | CloudWatch Logs Insights     |
| Alarm threshold     | >5 downloads in 1 minute     |
| Peak observed       | 6 downloads in 1 minute      |
| Time to detection   | ~5 minutes (manual query)    |
| Response action     | Manual key deactivation      |

---

## Key Difference from Scenario 1

| Dimension           | Scenario 1 (Honeypot)        | Scenario 2 (Exfiltration)        |
|---------------------|------------------------------|----------------------------------|
| Access legitimacy   | Unauthorized                 | Authorized but abused            |
| Detection method    | EventBridge + Lambda (auto)  | CloudWatch Alarm (alerting only) |
| Response time       | 9 seconds (automated)        | ~5 minutes (manual)              |
| Tool used           | `aws s3 cp` (manual)         | `aws s3 sync` (automated bulk)   |
| Attacker platform   | Windows 11 local machine     | AWS CloudShell (Linux)           |
| Files accessed      | 2 honeypot decoy files       | 6 real sensitive files           |

---

## Files Generated During Simulation

| File | Description |
|---|---|
| `cloudtrail-evidence/sample-event.json` | Real CloudTrail GetObject event from the exfiltration |
| `incident-report.md` | Full forensic analysis and SOC response documentation |

---

*All credentials, financial figures, and PII shown in this document are
simulated for lab purposes only.*

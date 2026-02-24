# Attack Simulation: Bulk S3 Data Exfiltration

**Scenario:** 2 of 3
**Type:** Compromised IAM Credentials + Bulk Download of Confidential Data
**Date Executed:** 2026-02-23
**Executed By:** Helmey Abdulsalam (lab exercise)

---

## Objective

Simulate an attacker who obtained long-term IAM access keys and uses them from
AWS CloudShell to perform a bulk `s3 sync` of a confidential S3 bucket.
The goal is to verify that the CloudWatch Logs anomaly detection pipeline
identifies the burst download pattern and fires an alert.

Unlike Scenario 1 (honeypot — unauthorized access), this user had legitimate
`s3:GetObject` permissions on the bucket. This simulates a **compromised
credentials** or **insider threat** scenario where the access is authorized
but the behavior is malicious.

---

## Pre-Attack Setup

### Confidential Bucket Contents
```bash
echo "Q1 Revenue: $4,200,000 | Expenses: $3,100,000 | Net: $1,100,000" > quarterly-results-q1.txt
echo "Q2 Revenue: $4,800,000 | Expenses: $3,400,000 | Net: $1,400,000" > quarterly-results-q2.txt
echo "Q3 Revenue: $5,100,000 | Expenses: $3,600,000 | Net: $1,500,000" > quarterly-results-q3.txt
echo "Annual Revenue: $18,900,000 | Total Expenses: $13,500,000"        > quarterly-results.txt

aws s3 cp quarterly-results-q1.txt s3://sec-lab-confidential-data/finance/
aws s3 cp quarterly-results-q2.txt s3://sec-lab-confidential-data/finance/
aws s3 cp quarterly-results-q3.txt s3://sec-lab-confidential-data/finance/
aws s3 cp quarterly-results.txt    s3://sec-lab-confidential-data/finance/

printf "Name,Email,SSN\nJohn Smith,john@example.com,123-45-6789\n" > pii-data.txt
aws s3 cp pii-data.txt s3://sec-lab-confidential-data/pii/

printf "id,name,plan\n1,Acme Corp,Enterprise\n2,Globex,Pro\n" > customers.csv
aws s3 cp customers.csv s3://sec-lab-confidential-data/sensitive/
```
All data is **fake** — for simulation only.

### IAM User Used as Attacker
| Field         | Value                                                  |
|---------------|--------------------------------------------------------|
| Username      | `test-exfil-user`                                      |
| Access Key ID | `AKIAU6WMXVKPGQRLXCVQ`                                 |
| Permissions   | `s3:GetObject`, `s3:ListBucket` on confidential bucket |
| Purpose       | Simulates attacker with stolen long-term keys          |

---

## Detection Infrastructure Active During Attack

| Component          | Configuration                                            |
|--------------------|----------------------------------------------------------|
| CloudTrail         | S3 data events enabled on `sec-lab-confidential-data`    |
| CloudWatch Logs    | All events delivered to `/sec-lab/cloudtrail`            |
| CloudWatch Alarm   | `data-exfiltration-anomaly` — fires if >5 downloads/min  |
| SNS Topic          | `sec-lab-honeypot-alerts` — email on trigger             |

**No EventBridge → Lambda auto-block** was configured for this bucket.
Detection was alerting-only, requiring manual response.

---

## Attack Execution

Executed from **AWS CloudShell (us-east-1)** using the attacker's long-term
access key. This simulates credentials stolen from a GitHub leak or phishing.

### Step 1 — Configure Stolen Credentials
```bash
aws configure set aws_access_key_id AKIAU6WMXVKPGQRLXCVQ
aws configure set aws_secret_access_key <stolen-secret-key>
aws configure set region us-east-1
```

### Step 2 — Reconnaissance
```bash
aws s3 ls s3://sec-lab-confidential-data/ --recursive
```

### Step 3 — Bulk Exfiltration via `s3 sync`
```bash
aws s3 sync s3://sec-lab-confidential-data/ ./exfil/
```
**Time:** 2026-02-23T20:54:58Z — 2026-02-23T20:59:38Z

---

## `aws s3 sync` Forensic Fingerprint

The userAgent field in CloudTrail explicitly identifies the tool:
```
aws-cli/2.33.23 ... exec-env/CloudShell ... md/command#s3.sync
```

Three IOCs in one field:
1. `exec-env/CloudShell` — attacker used AWS cloud infrastructure, not local machine
2. `md/command#s3.sync` — automated bulk sync, not manual file access
3. Identical timestamps on multiple files — impossible for human interaction

---

## Automated Response Triggered

The `data-exfiltration-anomaly` CloudWatch alarm fired on the 6-download burst
in the 20:59Z minute window.

| Metric           | Value                      |
|------------------|----------------------------|
| Alarm threshold  | >5 downloads per minute    |
| Peak observed    | 6 downloads in 1 minute    |
| Time to detect   | ~5 minutes (manual query)  |
| Response action  | Manual key deactivation    |

---

## Files Generated During Simulation

| File | Description |
|---|---|
| `cloudtrail-evidence/sample-event.json` | Real CloudTrail GetObject event |
| `incident-report.md` | Full forensic analysis and SOC response |

---

*All credentials, financial figures, and PII are simulated for lab purposes only.*

# IAM Policies

This folder documents the IAM policies used in the **AWS Security Operations Lab**, including both intentionally dangerous policies for attack simulations and secure least‑privilege replacements.

## Policies Overview

| File | Purpose | Used In Scenario |
|---|---|---|
| `admin-policy.json` | Intentionally over‑permissive inline policy (`Action: "*"`, `Resource: "*"`). Simulates full admin access misuse. | Scenario 3 – Privilege Escalation |
| `least-privilege-policy.json` | Secure replacement policy that grants only required S3 and EC2 read‑only permissions. | Scenario 3 – Privilege Escalation |
| `s3-honeypot-read-policy.json` | Read access to honeypot bucket only, used for testing credential theft and honeypot access. | Scenario 1 – Compromised Credentials |
| `confidential-bucket-read-policy.json` | Read access to confidential S3 bucket, used for exfiltration tests. | Scenario 2 – Data Exfiltration |

---

## Dangerous Policy — `admin-policy.json`

Used to simulate a badly designed admin‑style inline policy:

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

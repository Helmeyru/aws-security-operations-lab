# Incident Simulations

This folder contains three end-to-end attack simulations for the **AWS Security Operations Lab**. Each scenario shows how an attacker behaves, how your detections fire, and how you respond using automated playbooks.

## Scenarios Overview

| ID | Name | Primary Service | Detection Path | Main Playbook |
|---|---|---|---|---|
| 1 | Compromised IAM Credentials (Honeypot) | S3 Honeypot Bucket | CloudTrail S3 Data Events → Metric Filter → CloudWatch Alarm → EventBridge → Lambda / SNS | playbook-1-compromised-credentials.md |
| 2 | Data Exfiltration Attempt | S3 Confidential Bucket | CloudTrail S3 Data Events → CloudWatch Logs Insights / Anomaly Alarm → SNS | playbook-2-data-exfiltration.md |
| 3 | Privilege Escalation | IAM User & Policies | IAM Access Analyzer Finding → Manual / EventBridge → Policy Remediation | playbook-3-privilege-escalation.md |

---

## Scenario 1 — Compromised IAM Credentials (Honeypot)

**Goal:** Detect and respond when stolen IAM credentials are used to access fake, high-value data in an S3 honeypot bucket.

**Attacker Actions**
- Use exposed credentials for `test-exfil-user` or a similar low-privilege IAM user.
- List and download files from the honeypot bucket `sec-lab-honeypot-*`.

**Detection Pipeline**
- CloudTrail logs S3 **GetObject** data events for the honeypot bucket.
- CloudWatch Logs metric filter `honeypot-file-access` increments `HoneypotDetection/sensitive-files-accessed`.
- CloudWatch Alarm `honeypot-file-access-alarm` fires on any value > 0.
- EventBridge rule and/or SNS sends an alert to the `sec-lab-security-alerts` topic.
- (Optional) Lambda `sec-lab-rotate-keys` automatically rotates the compromised user's access keys.

**Artifacts in this repo**
- `scenario-1-compromised-credentials/` – markdown report, screenshots, queries.
- `playbooks/playbook-1-compromised-credentials.md` – step-by-step response playbook.

---

## Scenario 2 — Data Exfiltration Attempt (Confidential S3 Bucket)

**Goal:** Detect bulk download of sensitive files from the confidential S3 bucket using valid but abused IAM credentials.

**Attacker Actions**
- Use `exfil-test-user` with legitimate S3 read permissions.
- Rapidly download multiple files from `sec-lab-confidential-data-*` (financial reports, PII files).
- Optionally run `aws s3 sync` to pull an entire prefix.

**Detection Pipeline**
- CloudTrail S3 data events capture every **GetObject** from the confidential bucket.
- CloudWatch Logs Insights queries identify unusual download bursts, source IPs, and users.
- Optional metric filter + alarm count downloads per minute (exfil volume / rate).
- SNS notifications alert the SOC when thresholds are exceeded.

**Artifacts in this repo**
- `scenario-2-data-exfiltration/` – incident write-up, evidence, queries.
- `playbooks/playbook-2-data-exfiltration.md` – response playbook including containment and investigation steps.

---

## Scenario 3 — Privilege Escalation (Over-Permissive IAM Policy)

**Goal:** Detect and remediate an overly permissive IAM policy that effectively gives a user administrator-level access.

**Attacker / Misconfiguration Actions**
- Attach `DangerousAdminPolicy` to `test-overprivileged-user` with `Action: "*"` and `Resource: "*"`.

**Detection Pipeline**
- CloudTrail records IAM write events like `PutUserPolicy`.
- IAM Access Analyzer scans the new policy and generates a HIGH severity finding.
- The security engineer reviews the finding and replaces the dangerous policy with `LeastPrivilegePolicy`.
- (Optional future enhancement) EventBridge rule triggers Lambda to auto-remediate and send SNS alert.

**Artifacts in this repo**
- `scenario-3-privilege-escalation/` – analysis of the Access Analyzer finding and remediation.
- `playbooks/playbook-3-privilege-escalation.md` – response playbook for privilege escalation.

---

## How to Use These Scenarios

1. **Re-run the simulations** in your AWS account, following the step-by-step guide.
2. **Capture evidence** (screenshots, CloudWatch queries, CloudTrail snippets) into each scenario folder.
3. **Follow the playbooks** to practice incident response for each attack type.
4. **Iterate and improve** detection rules, alarms, and automated responses based on what you learn.

These scenarios together demonstrate a full security operations lifecycle: detection, triage, investigation, containment, eradication, recovery, and lessons learned.

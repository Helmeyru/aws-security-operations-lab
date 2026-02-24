
***

## 3) `playbooks/README.md`

```markdown
# Incident Response Playbooks

This folder contains incident response playbooks for each attack scenario in the **AWS Security Operations Lab**. Each playbook is a step-by-step guide for triage, containment, investigation, eradication, recovery, and lessons learned.

## Playbooks

| File | Scenario | Description |
|---|---|---|
| `playbook-1-compromised-credentials.md` | Scenario 1 – Compromised IAM Credentials (Honeypot) | Respond when stolen IAM credentials are used to access honeypot S3 files. |
| `playbook-2-data-exfiltration.md` | Scenario 2 – Data Exfiltration Attempt | Respond to bulk downloads of sensitive data from the confidential S3 bucket. |
| `playbook-3-privilege-escalation.md` | Scenario 3 – Privilege Escalation | Respond when an IAM user receives an overly permissive admin-style policy. |

## What Each Playbook Includes

Each playbook follows the same structure:

1. **Overview** – scenario description, severity, and detection sources.
2. **Triage** – how to quickly confirm the alert and scope.
3. **Containment** – immediate actions (disable keys, block IP, remove policy).
4. **Investigation** – CloudWatch Logs Insights queries and evidence to collect.
5. **Eradication & Recovery** – how to fix root cause and safely restore access.
6. **Post‑Incident** – documentation and improvements to make afterward.

## How to Use These Playbooks

- During the lab, open the relevant playbook as soon as an alert fires.
- Follow the steps in order and paste queries/commands into AWS CloudShell.
- Capture screenshots and notes into the matching `incident-simulations/*` folder.
- Re‑use the structure as a template for real-world incidents or other labs.

These playbooks are a key part of your portfolio: they show not only that you can build detections, but also that you can **run an incident from start to finish** like a SOC analyst.

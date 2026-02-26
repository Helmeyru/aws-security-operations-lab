# AWS Security Operations Lab

> **A production-grade cloud security monitoring and automated incident response platform built entirely in AWS.**

[![AWS](https://img.shields.io/badge/AWS-Cloud%20Security-FF9900?logo=amazonaws&logoColor=white)](https://aws.amazon.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-Educational-green)](#)
[![Status](https://img.shields.io/badge/Status-Complete-brightgreen)](#)

---

## Project Overview

| Field | Details |
|---|---|
| **Author** | Helmey Abdulsalam ([@Helmeyru](https://github.com/Helmeyru)) |
| **Duration** | ~25 hours |
| **Region** | us-east-1 (N. Virginia) |
| **Skills** | Cloud Security · Incident Response · IAM · Lambda · EventBridge · CloudTrail |
| **Status** | Complete — all scenarios executed and documented with real evidence |

This lab simulates a realistic AWS environment under attack and demonstrates the full
detection-to-response pipeline: **CloudTrail → EventBridge → Lambda → S3 Bucket Policy / EC2 Isolation → SNS Alert**.

---
## 🇸🇦 ملخص قصير (للمراجعين في السعودية)

هذا المشروع عبارة عن مختبر عملي لأمن السحابة على AWS يحاكي هجمات حقيقية
(وصول إلى Honeypot، تهريب بيانات من S3، وتصعيد صلاحيات عبر IAM) مع اكتشاف
آلي واستجابة تلقائية باستخدام CloudTrail و EventBridge و Lambda و SNS.
يهدف المختبر إلى عرض مهاراتي في بناء قدرات SOC على AWS وفق ضوابط NCA و SAMA.



## Architecture

```
┌─────────────────── AWS Account ─────────────────────────────────────┐
│                                                                     │
│   ┌── VPC (10.0.0.0/16) ──────────────────────────────────────┐     │
│   │  Public Subnet       Private Subnet      DB Subnet        │     │
│   │  Web Server (EC2)    App Server (EC2)     RDS MySQL       │     │
│   │  IGW route           Local only           Private only    │     │
│   └───────────────────────────────────────────────────────────┘     │
│                                                                     │
│   ┌── S3 Buckets ──────────────────────────────────────────────┐    │
│   │  sec-lab-honeypot-*            ← Honeypot trap files       │    │
│   │  sec-lab-confidential-data-*   ← Sensitive data simulation │    │
│   │  sec-lab-cloudtrail-logs-*     ← Audit log storage         │    │
│   └────────────────────────────────────────────────────────────┘    │
│                                                                     │
│   ┌── Detection Pipeline ──────────────────────────────────────┐    │
│   │  CloudTrail (S3 Data Events + Management Events)           │    │
│   │       ↓                                                    │    │
│   │  EventBridge (direct CloudTrail event matching)            │    │
│   │       ↓                                                    │    │
│   │  Lambda Incident Responder                                 │    │
│   │       ↓                    ↓                               │    │
│   │  S3 Bucket Policy Deny    SNS Alert → Email                │    │
│   └────────────────────────────────────────────────────────────┘    │
│                                                                     │
│   ┌── Additional Controls ─────────────────────────────────────┐    │
│   │  VPC Flow Logs → CloudWatch Logs                           │    │
│   │  AWS Config (s3-bucket-public-read-prohibited, etc.)       │    │
│   │  CloudWatch Metric Filters + Alarms (root usage,unauth API)│    │
│   │  IAM Access Analyzer (privilege escalation detection)      │    │
│   └────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

> A visual diagram is available at [`infrastructure/diagrams/architecture.jpg`](infrastructure/diagrams/architecture.jpg).

---

## Attack Scenarios & Results

### Scenario 1 — Honeypot S3 Access (Automated Block)
- **Attacker:** IAM user with simulated stolen access key
- **Files accessed:** `leaked-credentials.txt`, `customer-data.sql`
- **Detection-to-block time: 9 seconds**
- **Automated response:** Lambda wrote `aws:SourceIp` Deny rule to S3 bucket policy
- [View Full Incident Report](incident-simulations/scenario-1-honeypot-access/incident-report.md)

### Scenario 2 — Data Exfiltration Detection
- **Method:** Bulk S3 downloads from `sec-lab-confidential-data` bucket
- **Detection:** CloudWatch Logs Insights anomaly query (multiple GetObject in short window)
- **Evidence:** CloudTrail records showing 3 files in 7 seconds from non-corporate IP
- [View Full Incident Report](incident-simulations/scenario-2-data-exfiltration/incident-report.md)

### Scenario 3 — Privilege Escalation Detection
- **Issue:** IAM user with `Action: "*", Resource: "*"` over-permissive inline policy
- **Detection:** IAM Access Analyzer found the overly permissive inline policy
- **Remediation:** Replaced with scoped least-privilege policy
- [View Full Incident Report](incident-simulations/scenario-3-privilege-escalation/incident-report.md)

---

## Detection Capabilities

| Threat | Detection Method | Response |
|---|---|---|
| Honeypot file access | EventBridge → Lambda | IP blocked via S3 Bucket Policy |
| Data exfiltration | CloudWatch Logs Insights | Manual investigation + access revocation |
| Root account activity | CloudWatch Metric Filter + Alarm | SNS alert |
| Unauthorized API calls | CloudWatch Metric Filter | SNS alert |
| Security group changes | EventBridge Rule | SNS alert |
| Compromised EC2 | GuardDuty + EventBridge | Lambda EC2 isolation |
| Over-privileged IAM | IAM Access Analyzer | Policy remediation |

---

## Repository Structure

```
aws-security-operations-lab/
├── README.md                          ← This file
├── SECURITY.md                        ← Responsible disclosure policy
├── .gitignore
│
├── lambda-functions/
│   ├── honeypot-incident-responder/   ← Blocks attacker IP via S3 bucket policy
│   ├── ec2-isolate/                   ← Moves compromised EC2 to quarantine SG
│   └── iam-key-rotation/              ← Deactivates and rotates compromised IAM keys
│
├── iam-policies/                      ← Least-privilege IAM policies (JSON)
├── eventbridge-rules/                 ← Event pattern JSONs for all detection rules
├── cloudwatch-metrics/                ← Metric filters, alarm configs, Insights queries
│
├── incident-simulations/
│   ├── scenario-1-honeypot-access/    ← Simulated attack + CloudTrail evidence
│   ├── scenario-2-data-exfiltration/
│   └── scenario-3-privilege-escalation/
│
├── infrastructure/
│   └── diagrams/                      ← Architecture diagrams
│
└── playbooks/                         ← SOC response procedures
```

---

## Key Technical Decisions

**Why EventBridge instead of CloudWatch Metric Filter → Alarm?**
EventBridge consumes CloudTrail events directly with sub-10-second latency.
The Metric Filter → Alarm chain adds delay and complexity with no benefit for this use case.

**Why S3 Bucket Policy instead of EC2 Security Group?**
EC2 Security Groups protect network interfaces on EC2 instances only.
S3 is a managed service accessed via AWS APIs — the only way to block an IP from S3
is via the bucket policy `aws:SourceIp` condition key.

**Why inline IAM policy for Lambda?**
The Lambda role permissions are purpose-built for one specific bucket and one SNS topic.
Inline policies are automatically deleted with the role and cannot be accidentally reused.

---

## Verified Performance

| Metric | Result |
|---|---|
| Detection-to-block latency | **9 seconds** (CloudTrail → EventBridge → Lambda → S3 Policy) |
| False positive risk | Low — EventBridge rule scoped to specific bucket and event |
| IAM permissions scope | 3 actions only: `s3:GetBucketPolicy`, `s3:PutBucketPolicy`, `sns:Publish` |
| Idempotency | Duplicate blocks prevented via SID-based policy check |

---

## Skills Demonstrated

`AWS Lambda` `Amazon EventBridge` `AWS CloudTrail` `Amazon S3` `IAM Least Privilege`
`CloudWatch Logs Insights` `AWS Config` `VPC Design` `EC2 Security Groups`
`Incident Response` `Forensic Log Analysis` `Python (boto3)` `SOC Automation`
`Threat Detection` `IAM Access Analyzer` `SNS Alerting`

---

## Future Enhancements

- [ ] Terraform/CloudFormation IaC for full lab deployment
- [ ] Slack webhook integration for real-time SOC alerts
- [ ] AWS WAF IP set integration for CloudFront-fronted resources
- [ ] GuardDuty threat intelligence feed integration
- [ ] MITRE ATT\&CK mapping for each scenario
- [ ] Security dashboard in CloudWatch

---

## Security Notice

All credentials, IP addresses, bucket names, and account IDs shown in this repository
are either **example values** or **have been rotated/decommissioned** after the lab.
No real credentials are present. See [`SECURITY.md`](SECURITY.md) for the responsible disclosure policy.

---

*Built as a hands-on cybersecurity portfolio project demonstrating real-world SOC automation skills.*

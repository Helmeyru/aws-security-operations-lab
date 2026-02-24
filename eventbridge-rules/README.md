# EventBridge Detection Rules

This folder documents the Amazon EventBridge rules used in the **AWS Security Operations Lab**. These rules connect CloudTrail, GuardDuty, and CloudWatch with automated responders such as Lambda functions and SNS alerts.

## Rules Overview

| Rule Name | Status (Lab) | Trigger Source | Target | Purpose |
|---|---|---|---|---|
| `Detect-SG-Changes` | Enabled | CloudTrail EC2 API events | SNS topic `sec-lab-security-alerts` | Alert on security group modifications (ingress/egress changes). |
| `GuardDuty-Isolate-Instance` | Enabled (if GuardDuty available) | GuardDuty findings | Lambda `sec-lab-isolate-ec2` | Automatically isolate compromised EC2 instances. |
| `honeypot-auto-response-rule` | Disabled (safe default) | CloudTrail S3 GetObject on honeypot bucket | Lambda `sec-lab-rotate-keys` | Auto-rotate IAM keys when honeypot files are accessed. |
| `honeypot-s3-getobject-trigger` | Enabled | CloudTrail S3 data events on honeypot bucket | Lambda / logging | Trigger investigation whenever honeypot bucket is touched. |

---

## Detect-SG-Changes

**Goal:** Alert whenever security group rules are created or modified (common attacker technique to open backdoors).

**Event Pattern (simplified):**
```json
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": [
      "AuthorizeSecurityGroupIngress",
      "RevokeSecurityGroupIngress",
      "AuthorizeSecurityGroupEgress",
      "RevokeSecurityGroupEgress",
      "ModifySecurityGroupRules"
    ]
  }
}

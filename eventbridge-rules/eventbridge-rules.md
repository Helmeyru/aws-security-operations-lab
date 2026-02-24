# EventBridge Detection Rules — AWS Security Operations Lab

## Overview
| Field | Details |
|---|---|
| Account ID | 340805528222 |
| Region | us-east-1 |
| Event Bus | default |
| Author | Helmey Al-Showafi |
| Last Updated | 2026-02-24 |
| Total Rules | 4 |

---

## Rule 1: Detect-SG-Changes
**Status:** Enabled  
**Description:** Alert on security group modifications for incident response

### Purpose
Detects any modification to EC2 security groups — a common attacker technique
to open new ports or disable firewall rules for persistence or lateral movement.

### Event Pattern
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
      "ModifySecurityGroupRules",
      "CreateSecurityGroup",
      "DeleteSecurityGroup"
    ]
  }
}
```

### Target
- **Type:** SNS Topic
- **ARN:** `arn:aws:sns:us-east-1:340805528222:sec-lab-security-alerts`

### Create via CLI
```bash
aws events put-rule \
  --name "Detect-SG-Changes" \
  --event-pattern '{
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
  }' \
  --state ENABLED \
  --description "Alert on security group modifications for incident response" \
  --event-bus-name default \
  --region us-east-1

# Add SNS target
aws events put-targets \
  --rule "Detect-SG-Changes" \
  --targets "Id=SNSTarget,Arn=arn:aws:sns:us-east-1:340805528222:sec-lab-security-alerts" \
  --region us-east-1
```

### SOC Use Case
| Scenario | Triggered Event |
|---|---|
| Attacker opens port 22 to 0.0.0.0/0 | AuthorizeSecurityGroupIngress |
| Attacker removes outbound restrictions | RevokeSecurityGroupEgress |
| New SG created for lateral movement | CreateSecurityGroup |

---

## Rule 2: GuardDuty-Isolate-Instance
**Status:** Enabled  
**Description:** Automatically isolates EC2 instances on high-severity GuardDuty findings

### Purpose
Triggers automated EC2 isolation Lambda when GuardDuty detects high-severity
threats such as port scanning, SSH brute force, or cryptocurrency mining.

### Event Pattern
```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [4, 4.0, 4.5, 5, 5.0, 6, 6.0, 7, 7.0, 7.5, 8, 8.0, 8.5, 9, 9.0, 10],
    "type": [
      "UnauthorizedAccess:EC2/SSHBruteForce",
      "Recon:EC2/Portscan",
      "CryptoCurrency:EC2/BitcoinTool.B",
      "Backdoor:EC2/C&CActivity.B",
      "Trojan:EC2/DropPoint"
    ]
  }
}
```

### Target
- **Type:** Lambda Function
- **ARN:** `arn:aws:lambda:us-east-1:340805528222:function:sec-lab-isolate-ec2`

### Create via CLI
```bash
aws events put-rule \
  --name "GuardDuty-Isolate-Instance" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [4, 5, 6, 7, 8, 8.5, 9, 10]
    }
  }' \
  --state ENABLED \
  --event-bus-name default \
  --region us-east-1

# Add Lambda target
aws events put-targets \
  --rule "GuardDuty-Isolate-Instance" \
  --targets "Id=LambdaTarget,Arn=arn:aws:lambda:us-east-1:340805528222:function:sec-lab-isolate-ec2" \
  --region us-east-1
```

### SOC Use Case
| GuardDuty Finding | Severity | Response |
|---|---|---|
| SSH Brute Force | 5.0 | Auto-isolate instance |
| Port Scan | 5.0 | Auto-isolate instance |
| Bitcoin Mining Tool | 7.0 | Auto-isolate instance |
| C&C Activity | 8.0 | Auto-isolate instance |

---

## Rule 3: honeypot-auto-response-rule
**Status:** Disabled  
**Description:** Automatically responds when honeypot files are accessed

### Purpose
Triggers automated key rotation Lambda when a user accesses honeypot files
in the S3 honeypot bucket. Currently disabled — enable during active monitoring.

### Event Pattern
```json
{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["GetObject"],
    "requestParameters": {
      "bucketName": ["sec-lab-honeypot-1771026055"]
    }
  }
}
```

### Target
- **Type:** Lambda Function
- **ARN:** `arn:aws:lambda:us-east-1:340805528222:function:sec-lab-rotate-keys`

### Create via CLI
```bash
aws events put-rule \
  --name "honeypot-auto-response-rule" \
  --event-pattern '{
    "source": ["aws.s3"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["GetObject"],
      "requestParameters": {
        "bucketName": ["sec-lab-honeypot-1771026055"]
      }
    }
  }' \
  --state DISABLED \
  --description "Automatically responds when honeypot files are accessed" \
  --event-bus-name default \
  --region us-east-1

# Add Lambda target
aws events put-targets \
  --rule "honeypot-auto-response-rule" \
  --targets "Id=LambdaRotateKeys,Arn=arn:aws:lambda:us-east-1:340805528222:function:sec-lab-rotate-keys" \
  --region us-east-1

# To enable when ready
aws events enable-rule --name "honeypot-auto-response-rule" --region us-east-1
```

### Why Disabled?
This rule auto-rotates keys on any honeypot access. Keep disabled until you
have confirmed the Lambda is tested and working — otherwise legitimate testing
will trigger unwanted key rotations.

---

## Rule 4: honeypot-s3-getobject-trigger
**Status:** Enabled  
**Description:** Triggers Lambda when honeypot S3 bucket is accessed

### Purpose
A broader honeypot trigger that fires on ANY S3 data event (GetObject, PutObject,
DeleteObject) against the honeypot bucket, feeding into forensic logging.

### Event Pattern
```json
{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["GetObject", "PutObject", "DeleteObject", "ListObjects"],
    "requestParameters": {
      "bucketName": ["sec-lab-honeypot-1771026055"]
    }
  }
}
```

### Target
- **Type:** Lambda Function or CloudWatch Logs
- **ARN:** `arn:aws:lambda:us-east-1:340805528222:function:sec-lab-rotate-keys`

### Create via CLI
```bash
aws events put-rule \
  --name "honeypot-s3-getobject-trigger" \
  --event-pattern '{
    "source": ["aws.s3"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["GetObject", "PutObject", "DeleteObject", "ListObjects"],
      "requestParameters": {
        "bucketName": ["sec-lab-honeypot-1771026055"]
      }
    }
  }' \
  --state ENABLED \
  --description "Triggers Lambda when honeypot S3 bucket is accessed" \
  --event-bus-name default \
  --region us-east-1
```

---

## Rules Summary

| Rule Name | Status | Trigger | Target | Scenario |
|---|---|---|---|---|
| Detect-SG-Changes | Enabled | EC2 SG modification | SNS Alert | All scenarios |
| GuardDuty-Isolate-Instance | Enabled | GuardDuty finding ≥4 | Lambda isolate-ec2 | Scenario 1, 2 |
| honeypot-auto-response-rule | Disabled | S3 GetObject honeypot | Lambda rotate-keys | Scenario 1 |
| honeypot-s3-getobject-trigger | Enabled | S3 any action honeypot | Lambda rotate-keys | Scenario 1 |

---

## Verify All Rules via CLI
```bash
aws events list-rules \
  --event-bus-name default \
  --region us-east-1 \
  --query "Rules[*].{Name:Name,State:State,Description:Description}" \
  --output table
```

## Test a Rule Manually
```bash
# Send a test event to verify Detect-SG-Changes fires
aws events put-events \
  --entries '[{
    "Source": "aws.ec2",
    "DetailType": "AWS API Call via CloudTrail",
    "Detail": "{"eventName": "AuthorizeSecurityGroupIngress"}",
    "EventBusName": "default"
  }]' \
  --region us-east-1
```

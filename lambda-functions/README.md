# Lambda Functions — Detection & Automated Response

This folder contains all three Lambda functions used for automated incident response in the **AWS Security Operations Lab**.

## Functions Overview

| Function | Runtime | Trigger | What It Does | Scenario |
|---|---|---|---|---|
| `honeypot-auto-block-ip` | Python 3.12 | EventBridge → S3 GetObject on honeypot bucket | Extracts attacker IP from CloudTrail event, blocks it via S3 bucket policy Deny, sends SNS alert with full forensic details. | Scenario 1 – Compromised Credentials |
| `sec-lab-rotate-keys` | Python 3.12 | EventBridge → GuardDuty IAM credential finding | Lists active IAM access keys for a user, creates a new key, deactivates the old compromised key. | Scenario 1 & 2 |
| `sec-lab-isolate-ec2` | Python 3.12 | EventBridge → GuardDuty EC2 finding or manual test | Moves a compromised EC2 instance into a quarantine security group with zero ingress/egress. | Scenario 2 |

---

## Folder Structure

```text
lambda-functions/
  README.md
  honeypot-auto-block-ip/
    lambda_function.py
    policy-honeypot-auto-block-ip.json
    event-test-eventbridge.json
  sec-lab-rotate-keys/
    lambda_function.py
    policy-iam-rotate-keys.json
    event-test-guardduty.json
    event-test-cloudtrail.json
  sec-lab-isolate-ec2/
    lambda_function.py
    policy-ec2-isolate.json
    event-test-simple.json
    event-test-guardduty.json
```

---

## honeypot-auto-block-ip

### Purpose
The most advanced Lambda in this lab. Triggered automatically when any user runs `GetObject` against the honeypot S3 bucket. It extracts the attacker's IP from the CloudTrail event, writes a Deny statement to the bucket policy, and notifies the SOC team via SNS.

### Architecture flow
```
Attacker accesses sec-lab-honeypot-* (GetObject)
    ↓
CloudTrail captures S3 Data Event
    ↓
EventBridge rule honeypot-s3-getobject-trigger fires
    ↓
Lambda honeypot-auto-block-ip invoked
    ↓
    ├── Extracts sourceIPAddress from CloudTrail event
    ├── Appends Deny statement to S3 bucket policy (aws:SourceIp)
    │   (idempotent — uses SID-based deduplication)
    └── Sends SNS alert with:
            - Attacker IP
            - File accessed
            - Identity ARN
            - Actions taken
            - Investigation query
            - Next steps
```

### Environment variables
None — S3 bucket name and SNS topic ARN are hard‑coded constants in the function.

| Constant | Value |
|---|---|
| `S3_BUCKET_NAME` | `sec-lab-honeypot-1771026055` |
| `SNS_TOPIC_ARN` | `arn:aws:sns:us-east-1:340805528222:sec-lab-honeypot-alerts` |
| `LAMBDA_ROLE_ARN` | `arn:aws:iam::340805528222:role/service-role/honeypot-auto-block-ip-role-32ecb3cd` |

### Required IAM permissions (execution role `honeypot-auto-block-ip-role-32ecb3cd`)

See `policy-honeypot-auto-block-ip.json`:
- `s3:GetBucketPolicy` on the honeypot bucket
- `s3:PutBucketPolicy` on the honeypot bucket
- `sns:Publish` on `sec-lab-honeypot-alerts`
- `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`

### Key design details
- **Idempotent blocking** — uses a unique Sid `DenyAttackerIP-X-X-X-X` per IP so the same IP is never blocked twice.
- **Self‑preservation** — always includes an `AllowLambdaAutoResponder` statement so the function can still update the policy after the first block.
- **Service principal rejection** — rejects non‑routable values like `s3.amazonaws.com` using IPv4 regex validation before attempting a block.
- **Error handling** — if the Lambda itself fails, it sends a separate error alert via SNS so you are always notified.

### EventBridge rule to connect (honeypot-s3-getobject-trigger)
```json
{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["s3.amazonaws.com"],
    "eventName": ["GetObject"],
    "requestParameters": {
      "bucketName": ["sec-lab-honeypot-1771026055"]
    }
  }
}
```

### Sample SNS alert output
```
HONEYPOT ALERT — AUTOMATED RESPONSE EXECUTED

Attacker IP   : 86.62.30.104
File Accessed : s3://sec-lab-honeypot-1771026055/leaked-credentials.txt
Identity ARN  : arn:aws:iam::340805528222:user/test-exfil-user
Event Time    : 2026-02-24T22:03:36Z
Response Time : 2026-02-24 22:03:40 UTC

ACTIONS TAKEN:
  [+] Attacker IP blocked via S3 Bucket Policy (aws:SourceIp Deny)
  [+] Security team notified via SNS

INVESTIGATION QUERY (CloudWatch Logs Insights):
  fields @timestamp, eventName, sourceIPAddress, userIdentity.arn
  | filter eventName = "GetObject" and requestParameters.bucketName = "sec-lab-honeypot-1771026055"
  | sort @timestamp desc
  | limit 20

NEXT STEPS:
  1. Review CloudTrail for additional API calls from this IP
  2. Check if the accessed file exposes real credentials
  3. Rotate any credentials that may have been exposed
  4. Disable IAM user if access key was stolen
```

---

## sec-lab-rotate-keys

### Purpose
Rotates compromised IAM access keys when a GuardDuty credential finding is raised or a honeypot access is detected. Creates a new key and deactivates the old active key.

### Architecture flow
```
GuardDuty IAM finding OR honeypot trigger
    ↓
EventBridge rule fires
    ↓
Lambda sec-lab-rotate-keys invoked
    ↓
    ├── Extracts userName from event['detail']['resource']['accessKeyDetails']['userName']
    ├── Lists all access keys for the user
    ├── Creates new access key
    └── Deactivates old Active key
```

### Environment variables
None required.

### Required IAM permissions (execution role)
See `policy-iam-rotate-keys.json`:
- `iam:ListAccessKeys`
- `iam:CreateAccessKey`
- `iam:UpdateAccessKey`

### Notes
- AWS only allows **two** access keys per IAM user. If two already exist, `CreateAccessKey` will fail — delete one first.
- The new secret access key is returned in the Lambda response but not stored. In production, write it to AWS Secrets Manager.

---

## sec-lab-isolate-ec2

### Purpose
Automatically isolates a compromised EC2 instance by replacing its security groups with the quarantine security group (`sec-lab-quarantine-sg`), which has no inbound or outbound rules.

### Architecture flow
```
GuardDuty EC2 finding (SSH brute force, port scan, crypto mining)
    ↓
EventBridge rule GuardDuty-Isolate-Instance fires
    ↓
Lambda sec-lab-isolate-ec2 invoked
    ↓
    ├── Extracts instance_id from event
    └── Calls ec2.modify_instance_attribute()
            → replaces ALL security groups with quarantine SG
            → instance loses all network access immediately
```

### Environment variables

| Variable | Description | Example |
|---|---|---|
| `QUARANTINE_SG_ID` | The SG ID for the quarantine group (no ingress/egress). | `sg-0123456789abcdef0` |

### Required IAM permissions (execution role)
See `policy-ec2-isolate.json`:
- `ec2:DescribeInstances`
- `ec2:ModifyInstanceAttribute`

### Notes
- This is destructive — the instance loses **all** network access immediately upon isolation.
- Verify `QUARANTINE_SG_ID` is correct before enabling the EventBridge rule in production.
- Always test with `event-test-simple.json` first using a non‑critical instance.

---

## Testing All Three Functions

### honeypot-auto-block-ip
```bash
# Trigger naturally by accessing the honeypot bucket
aws s3 cp s3://sec-lab-honeypot-1771026055/leaked-credentials.txt .

# Or use event-test-eventbridge.json in the Lambda console Test tab
```

### sec-lab-rotate-keys
```bash
# In Lambda console, use event-test-guardduty.json
# then verify old key is Inactive:
aws iam list-access-keys --user-name test-rotation-user
```

### sec-lab-isolate-ec2
```bash
# In Lambda console, use event-test-simple.json with a test instance ID
# then verify the security group was replaced:
aws ec2 describe-instances \
  --instance-ids i-0123456789abcdef0 \
  --query "Reservations[*].Instances[*].SecurityGroups"
```

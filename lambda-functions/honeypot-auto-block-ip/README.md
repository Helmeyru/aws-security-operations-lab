# Lambda: honeypot-incident-responder

## Purpose
Automatically blocks an attacker's IP when they access honeypot files in the S3 honeypot bucket.
Triggered by EventBridge which directly consumes CloudTrail S3 data events.

## Architecture
```
Attacker GetObject on honeypot bucket
    → CloudTrail S3 Data Event
    → EventBridge Rule (pattern match on bucket + GetObject)
    → This Lambda
    → S3 Bucket Policy Deny (aws:SourceIp)
    → SNS Alert
```

## Why S3 Bucket Policy (not Security Group)?
EC2 Security Groups protect EC2 network interfaces only.
S3 is a managed AWS service accessed directly over the internet.
The **only** mechanism to block an IP from S3 is the bucket policy `aws:SourceIp` condition.

## Configuration
Update these constants at the top of `lambda_function.py`:

| Constant | Description |
|---|---|
| `S3_BUCKET_NAME` | The honeypot S3 bucket name |
| `SNS_TOPIC_ARN` | SNS topic ARN for alerts |
| `LAMBDA_ROLE_ARN` | Full ARN of this Lambda's execution role |

> **Important:** `LAMBDA_ROLE_ARN` must include the `service-role/` prefix if the role was auto-created by Lambda Console.

## IAM Execution Role (Least Privilege)
See: [../../iam-policies/honeypot-lambda-least-privilege.json](../../iam-policies/honeypot-lambda-least-privilege.json)

Permissions required:
- `s3:GetBucketPolicy` on the honeypot bucket
- `s3:PutBucketPolicy` on the honeypot bucket
- `sns:Publish` on the alerts topic
- `logs:CreateLogGroup/Stream/PutLogEvents`

## EventBridge Rule Pattern
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

## Idempotency
Each block uses a unique SID: `DenyAttackerIP-<ip-with-dashes>`.
If the same IP triggers the rule twice, the second execution detects the existing SID and skips — no duplicate policies.

## Verified Performance
- Detection-to-block latency: **9 seconds** (real test, 2026-02-23)
- Attacker: `193.160.245.168` using `test-exfil-user` credentials

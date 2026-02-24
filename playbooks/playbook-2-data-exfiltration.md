# Playbook 2: Data Exfiltration Response

## Overview
| Field | Details |
|---|---|
| Playbook ID | PB-002 |
| Severity | CRITICAL |
| Detection Source | CloudWatch Anomaly Alarm, CloudTrail S3 Data Events |
| Author | Helmey Al-Showafi |
| Last Updated | 2026-02-24 |

## Indicators of Compromise (IOCs)
- 10+ S3 GetObject calls within 5 minutes from one user
- Downloads from multiple folders in the same session
- Source IP outside corporate IP range
- Unusual access time (off-hours)
- High bytesTransferredOut volume (>100 KB per event)
- Bulk sync using aws s3 sync command

## Phase 1 — Triage (0–5 minutes)
### Confirm the alert
```bash
# Check the triggered alarm
aws cloudwatch describe-alarms \
  --alarm-names "s3-bulk-download-alarm" \
  --query "MetricAlarms[*].{Name:AlarmName,State:StateValue,Reason:StateReason}"

# Quick CloudTrail lookup for the user
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<username> \
  --max-results 30 \
  --output json
```

## Phase 2 — Containment (5–15 minutes)
```bash
# Immediately deactivate access keys
aws iam update-access-key \
  --user-name <username> \
  --access-key-id <key-id> \
  --status Inactive

# Deny access to confidential bucket via bucket policy
cat > /tmp/deny-user-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": {
        "AWS": "arn:aws:iam::<account-id>:user/<username>"
      },
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::sec-lab-confidential-data-xxx",
        "arn:aws:s3:::sec-lab-confidential-data-xxx/*"
      ]
    }
  ]
}
EOF

aws s3api put-bucket-policy \
  --bucket sec-lab-confidential-data-xxx \
  --policy file:///tmp/deny-user-policy.json
```

## Phase 3 — Investigation (15–60 minutes)
### Full Download Timeline
```sql
fields timestamp, eventName, sourceIPAddress,
       userIdentity.arn, requestParameters.key,
       additionalEventData.bytesTransferredOut
| filter eventName = "GetObject"
    and requestParameters.bucketName = "sec-lab-confidential-data-xxx"
| sort timestamp asc
| limit 100
```

### Calculate Total Data Exfiltrated
```sql
fields additionalEventData.bytesTransferredOut
| filter eventName = "GetObject"
    and userIdentity.userName = "<username>"
| stats sum(additionalEventData.bytesTransferredOut) as TotalBytesOut
```

### Evidence Collection
```bash
# Export full CloudTrail evidence to file
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<username> \
  --output json > evidence-exfil-$(date +%Y%m%d-%H%M%S).json

echo "Evidence saved: $(wc -l < evidence-exfil-*.json) lines"
```

### Red Flags Checklist
| IOC | Finding |
|---|---|
| Files downloaded | List all from query |
| Time span | Start and end timestamps |
| Total bytes out | Sum from query |
| Source IP | Document IP + geolocation |
| Access pattern | Sequential vs. random files |
| User agent | CLI vs. console vs. script |

## Phase 4 — Eradication (1–2 hours)
```bash
# Remove user's permissions entirely
aws iam delete-user-policy \
  --user-name <username> \
  --policy-name ConfidentialBucketRead

# Rotate S3 bucket encryption key
aws s3api put-bucket-encryption \
  --bucket sec-lab-confidential-data-xxx \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
```

## Phase 5 — Recovery
- Assess what data was exfiltrated — classify sensitivity level
- Notify affected parties if PII was involved (GDPR/compliance obligations)
- Re-enable bucket access only with MFA-required condition
- Rekey any exposed credentials found in downloaded files

## Phase 6 — Post-Incident (within 24 hours)
- File incident report with data classification
- Notify compliance/legal team if regulated data (PII, financial) was accessed
- Implement S3 Access Points with VPC-only restrictions
- Review and tighten IAM policies for all S3 users
- Add bulk-download detection rule permanently to CloudWatch

## Key Lessons
- Speed matters — keys should be disabled in under 5 minutes
- bytesTransferredOut is a powerful exfiltration indicator
- Bucket policies can block a specific user faster than IAM policy changes
- Always preserve evidence before making changes

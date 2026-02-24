# Playbook 1: Compromised IAM Credentials Response

## Overview
| Field | Details |
|---|---|
| Playbook ID | PB-001 |
| Severity | HIGH |
| Detection Source | S3 Honeypot Alarm, CloudTrail, GuardDuty |
| Author | Helmey Al-Showafi |
| Last Updated | 2026-02-24 |

## Indicators of Compromise (IOCs)
- Access to honeypot S3 files (leaked-credentials.txt, customer-data.sql)
- API calls from unusual geographic location or IP
- Multiple failed authentication attempts
- Unusual access patterns outside business hours
- User agent strings from unexpected tools (curl, python scripts)

## Phase 1 — Triage (0–5 minutes)
### Identify the affected user
```bash
# Get user details
aws iam get-user --user-name <username>

# List all policies attached
aws iam list-user-policies --user-name <username>
aws iam list-attached-user-policies --user-name <username>

# List all active access keys
aws iam list-access-keys --user-name <username>

# Check recent activity in CloudTrail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<username> \
  --max-results 20 \
  --output json
```

## Phase 2 — Containment (5–15 minutes)
### Disable compromised access keys immediately
```bash
# Deactivate key
aws iam update-access-key \
  --user-name <username> \
  --access-key-id <key-id> \
  --status Inactive

# Force password reset on next login
aws iam update-login-profile \
  --user-name <username> \
  --password-reset-required

# Revoke all active sessions
aws iam delete-login-profile --user-name <username>
```

## Phase 3 — Investigation (15–60 minutes)
### CloudWatch Logs Insights — Full Activity Timeline
```sql
fields timestamp, eventName, sourceIPAddress, userAgent, errorCode
| filter userIdentity.arn like "<username>"
| sort timestamp desc
| limit 1000
```

### CloudWatch Logs Insights — Honeypot File Access
```sql
fields timestamp, eventName, sourceIPAddress, userIdentity.arn,
       requestParameters.key
| filter eventName = "GetObject"
    and requestParameters.bucketName = "sec-lab-honeypot-1771026055"
| sort timestamp desc
| limit 20
```

### Evidence to Collect
- Source IP addresses
- Files accessed and timestamps
- User agent strings
- Data volume transferred (bytesTransferredOut)
- Geographic location of source IP

## Phase 4 — Eradication (1–2 hours)
```bash
# Remove all inline policies
aws iam delete-user-policy \
  --user-name <username> \
  --policy-name <policy-name>

# Detach managed policies
aws iam detach-user-policy \
  --user-name <username> \
  --policy-arn <policy-arn>

# Apply least-privilege replacement policy
aws iam put-user-policy \
  --user-name <username> \
  --policy-name LeastPrivilegePolicy \
  --policy-document file://least-privilege-policy.json

# Delete compromised access key entirely
aws iam delete-access-key \
  --user-name <username> \
  --access-key-id <key-id>
```

## Phase 5 — Recovery
- Issue new access keys only if user is legitimate and verified
- Require MFA before re-enabling access
- Notify user via out-of-band channel (phone/in-person)
- Monitor user activity closely for 72 hours after recovery

## Phase 6 — Post-Incident (within 24 hours)
- Document full attack timeline
- Update honeypot alarm thresholds if needed
- Add attacker IP to network block list
- Brief security team on findings
- Update this playbook with lessons learned

## Key Lessons
- Honeypot files are highly effective — any access = confirmed compromise
- CloudTrail data events must be enabled on S3 to capture GetObject calls
- Keys should be disabled within minutes, not hours

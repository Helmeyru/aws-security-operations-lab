# Playbook 3: Privilege Escalation Response

## Overview
| Field | Details |
|---|---|
| Playbook ID | PB-003 |
| Severity | HIGH → CRITICAL |
| Detection Source | IAM Access Analyzer, CloudTrail IAM Events |
| Author | Helmey Al-Showafi |
| Last Updated | 2026-02-24 |

## Indicators of Compromise (IOCs)
- IAM policy with Action: "*" and Resource: "*"
- IAM Access Analyzer finding status: ACTIVE, severity: HIGH
- New inline policy attached outside normal change process
- User performing actions outside their job function
- CloudTrail showing IAM write events from unexpected user
- PutUserPolicy / AttachUserPolicy events from low-privilege user

## Phase 1 — Triage (0–5 minutes)
### Identify the overprivileged user
```bash
# List all inline policies on the user
aws iam list-user-policies --user-name <username>

# Get the actual policy document
aws iam get-user-policy \
  --user-name <username> \
  --policy-name <policy-name>

# Check Access Analyzer findings
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:us-east-1:<account-id>:analyzer/sec-lab-analyzer \
  --filter '{"status": {"eq": ["ACTIVE"]}}'
```

### Check What the User Has Done with Elevated Access
```sql
fields timestamp, eventName, sourceIPAddress,
       userIdentity.arn, requestParameters
| filter userIdentity.userName = "test-overprivileged-user"
| sort timestamp desc
| limit 100
```

## Phase 2 — Containment (5–15 minutes)
```bash
# Option A — Remove the dangerous policy immediately
aws iam delete-user-policy \
  --user-name <username> \
  --policy-name DangerousAdminPolicy

# Option B — If broader compromise suspected, disable all keys first
aws iam update-access-key \
  --user-name <username> \
  --access-key-id <key-id> \
  --status Inactive

# Verify policies are removed
aws iam list-user-policies --user-name <username>
aws iam list-attached-user-policies --user-name <username>
```

## Phase 3 — Investigation (15–60 minutes)
### Audit All Actions Taken with Elevated Privileges
```sql
fields timestamp, eventName, sourceIPAddress,
       userIdentity.arn, requestParameters, errorCode
| filter userIdentity.userName = "<username>"
    and ispresent(errorCode) = false
| sort timestamp asc
| limit 500
```

### Check for Persistence Mechanisms
```bash
# Did the user create any new users?
aws iam list-users --query \
  "Users[?CreateDate>='2026-02-01'].{User:UserName,Created:CreateDate}"

# Did the user create any new access keys for other users?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --output json

# Did the user modify any policies?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutUserPolicy \
  --output json

# Did the user create any new roles?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole \
  --output json
```

### Policy Risk Assessment
| Policy Element | Before (Dangerous) | After (Safe) |
|---|---|---|
| Action | "*" (all actions) | s3:ListBucket, s3:GetObject |
| Resource | "*" (all resources) | Specific bucket ARN only |
| EC2 Access | Full | ec2:Describe* only |
| IAM Access | Full admin | None |
| Risk Level | CRITICAL | LOW |

## Phase 4 — Eradication (1–2 hours)
```bash
# Step 1: Remove dangerous policy
aws iam delete-user-policy \
  --user-name <username> \
  --policy-name DangerousAdminPolicy

# Step 2: Create least-privilege policy file
cat > /tmp/least-privilege-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:s3:::sec-lab-confidential-data-xxx",
        "arn:aws:s3:::sec-lab-confidential-data-xxx/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups"
      ],
      "Resource": "*"
    }
  ]
}
EOF

# Step 3: Attach least-privilege policy
aws iam put-user-policy \
  --user-name <username> \
  --policy-name LeastPrivilegePolicy \
  --policy-document file:///tmp/least-privilege-policy.json

# Step 4: Verify fix
aws iam get-user-policy \
  --user-name <username> \
  --policy-name LeastPrivilegePolicy

# Step 5: Archive Access Analyzer finding as resolved
aws accessanalyzer update-findings \
  --analyzer-arn arn:aws:access-analyzer:us-east-1:<account-id>:analyzer/sec-lab-analyzer \
  --status ARCHIVED \
  --ids "<finding-id>"
```

## Phase 5 — Recovery
- Re-enable user access only after least-privilege policy is confirmed
- Require manager approval for any future policy changes
- Enable CloudTrail alerts on all IAM write events for this user
- Schedule quarterly IAM access review

## Phase 6 — Post-Incident (within 24 hours)
- Document before/after policy for compliance record
- Run IAM Access Analyzer scan across all users
- Implement SCP (Service Control Policy) if using AWS Organizations
- Add IAM policy change detection to EventBridge permanently
- Update onboarding process to prevent future over-permissioning

## Key Lessons
- Wildcard policies (Action: *, Resource: *) are never acceptable in production
- IAM Access Analyzer runs continuously — findings appear within 60 minutes
- Always check for persistence: new users, new keys, new roles created
- Least-privilege is not optional — enforce it at the SCP level if possible

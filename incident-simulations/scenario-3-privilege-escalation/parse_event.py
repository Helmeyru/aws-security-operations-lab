import json

with open("sample-event.json") as f:
    event = json.load(f)

print("=" * 50)
print("CloudTrail Event Analysis")
print("=" * 50)
print(f"Event Time     : {event['eventTime']}")
print(f"Event Name     : {event['eventName']}")
print(f"Event Source   : {event['eventSource']}")
print(f"User           : {event['userIdentity']['userName']}")
print(f"User ARN       : {event['userIdentity']['arn']}")
print(f"Account ID     : {event['userIdentity']['accountId']}")
print(f"Source IP      : {event['sourceIPAddress']}")
print(f"AWS Region     : {event['awsRegion']}")
print(f"Read Only      : {event['readOnly']}")
print(f"Event Category : {event['eventCategory']}")
print()
print("Resources Accessed:")
for r in event.get("resources", []):
    print(f"  - Type : {r['type']}")
    print(f"    ARN  : {r.get('ARN') or r.get('ARNPrefix')}")
print()

# --- Threat Detection Logic ---
alerts = []

SUSPICIOUS_IPS = []  # add known bad IPs here
HIGH_RISK_ACTIONS = ["DeleteBucket", "PutBucketPolicy", "DeleteObject",
                     "PutUserPolicy", "CreateAccessKey", "AttachUserPolicy"]

if event["sourceIPAddress"] in SUSPICIOUS_IPS:
    alerts.append("ALERT: Activity from known suspicious IP!")

if event["eventName"] in HIGH_RISK_ACTIONS:
    alerts.append(f"ALERT: High-risk action detected: {event['eventName']}")

if not event.get("readOnly", True):
    alerts.append("WARNING: This is a WRITE operation — review carefully.")

bytes_out = event.get("additionalEventData", {}).get("bytesTransferredOut", 0)
if bytes_out > 100000:
    alerts.append(f"WARNING: Large data transfer detected — {bytes_out} bytes out.")

if alerts:
    print("Threat Detection Results:")
    for a in alerts:
        print(f"  {a}")
else:
    print("Threat Detection: No high-risk indicators found.")

print("=" * 50)
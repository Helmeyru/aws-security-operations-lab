import boto3
import json
import logging
import re
from datetime import datetime, timezone
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client("s3")
sns_client = boto3.client("sns")

# ── Configuration ──────────────────────────────────────────────────────────────
S3_BUCKET_NAME  = "sec-lab-honeypot-1771026055"
SNS_TOPIC_ARN   = "arn:aws:sns:us-east-1:340805528222:sec-lab-honeypot-alerts"
LAMBDA_ROLE_ARN = "arn:aws:iam::340805528222:role/service-role/honeypot-auto-block-ip-role-32ecb3cd"
# ───────────────────────────────────────────────────────────────────────────────


def lambda_handler(event, context):
    """
    Triggered by EventBridge when a GetObject call is made on the honeypot bucket.
    EventBridge rule pattern:
    {
      "source": ["aws.s3"],
      "detail-type": ["AWS API Call via CloudTrail"],
      "detail": {
        "eventSource": ["s3.amazonaws.com"],
        "eventName": ["GetObject"],
        "requestParameters": { "bucketName": ["sec-lab-honeypot-1771026055"] }
      }
    }
    """
    logger.info(f"Received EventBridge event: {json.dumps(event)}")

    try:
        attacker_ip = extract_attacker_ip(event)
        if not attacker_ip:
            logger.error("Could not determine attacker IP — aborting.")
            return {"statusCode": 400, "body": "No attacker IP found"}

        logger.info(f"Attacker IP identified: {attacker_ip}")

        already_blocked = block_ip_in_bucket_policy(attacker_ip)

        if not already_blocked:
            send_alert(attacker_ip, event)
            logger.info(f"IP {attacker_ip} successfully blocked via bucket policy.")
        else:
            logger.info(f"IP {attacker_ip} was already blocked — skipping notification.")

        return {"statusCode": 200, "body": f"Blocked: {attacker_ip}"}

    except Exception as e:
        logger.error(f"Lambda execution failed: {str(e)}", exc_info=True)
        send_error_alert(str(e))
        return {"statusCode": 500, "body": str(e)}


def extract_attacker_ip(event):
    """
    Extract sourceIPAddress from the CloudTrail event delivered via EventBridge.
    The full CloudTrail record is available in event["detail"].
    Rejects AWS service principal names (e.g., "s3.amazonaws.com").
    """
    detail = event.get("detail", {})
    ip = detail.get("sourceIPAddress")
    if ip and _is_valid_ipv4(ip):
        logger.info(f"Extracted IP from event detail: {ip}")
        return ip
    if ip:
        logger.warning(f"sourceIPAddress is a service principal, not an IP: {ip}")
    return None


def _is_valid_ipv4(value):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value))


def block_ip_in_bucket_policy(attacker_ip: str) -> bool:
    """
    Appends a Deny statement for attacker_ip to the honeypot bucket policy.
    Uses SID-based idempotency to prevent duplicate blocks.
    Returns True if already blocked, False if newly added.
    """
    cidr = f"{attacker_ip}/32"
    deny_sid = f"DenyAttackerIP-{attacker_ip.replace('.', '-')}"

    try:
        response = s3_client.get_bucket_policy(Bucket=S3_BUCKET_NAME)
        policy = json.loads(response["Policy"])
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            logger.info("No existing bucket policy — creating fresh.")
            policy = {"Version": "2012-10-17", "Statement": []}
        else:
            raise

    statements = policy.get("Statement", [])

    for stmt in statements:
        if stmt.get("Sid") == deny_sid:
            logger.info(f"IP {attacker_ip} already blocked.")
            return True

    # Preserve Lambda role access so future policy updates still work
    lambda_allow_sid = "AllowLambdaAutoResponder"
    if lambda_allow_sid not in {s.get("Sid") for s in statements}:
        statements.append({
            "Sid": lambda_allow_sid,
            "Effect": "Allow",
            "Principal": {"AWS": LAMBDA_ROLE_ARN},
            "Action": ["s3:GetBucketPolicy", "s3:PutBucketPolicy"],
            "Resource": f"arn:aws:s3:::{S3_BUCKET_NAME}"
        })

    statements.append({
        "Sid": deny_sid,
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
            f"arn:aws:s3:::{S3_BUCKET_NAME}",
            f"arn:aws:s3:::{S3_BUCKET_NAME}/*"
        ],
        "Condition": {"IpAddress": {"aws:SourceIp": cidr}}
    })

    policy["Statement"] = statements
    s3_client.put_bucket_policy(Bucket=S3_BUCKET_NAME, Policy=json.dumps(policy))
    logger.info(f"Bucket policy updated — {attacker_ip} blocked.")
    return False


def send_alert(attacker_ip: str, event: dict):
    detail = event.get("detail", {})
    event_time    = detail.get("eventTime", get_utc_now())
    accessed_key  = detail.get("requestParameters", {}).get("key", "unknown")
    user_identity = detail.get("userIdentity", {}).get("arn", "unknown")

    message = (
        f"HONEYPOT ALERT — AUTOMATED RESPONSE EXECUTED\n\n"
        f"Attacker IP   : {attacker_ip}\n"
        f"File Accessed : s3://{S3_BUCKET_NAME}/{accessed_key}\n"
        f"Identity ARN  : {user_identity}\n"
        f"Event Time    : {event_time}\n"
        f"Response Time : {get_utc_now()}\n\n"
        f"ACTIONS TAKEN:\n"
        f"  [+] Attacker IP blocked via S3 Bucket Policy (aws:SourceIp Deny)\n"
        f"  [+] Security team notified via SNS\n\n"
        f"INVESTIGATION QUERY (CloudWatch Logs Insights):\n"
        f'  fields @timestamp, eventName, sourceIPAddress, userIdentity.arn\n'
        f'  | filter eventName = "GetObject" and requestParameters.bucketName = "{S3_BUCKET_NAME}"\n'
        f"  | sort @timestamp desc\n"
        f"  | limit 20\n\n"
        f"NEXT STEPS:\n"
        f"  1. Review CloudTrail for additional API calls from this IP\n"
        f"  2. Check if the accessed file exposes real credentials\n"
        f"  3. Rotate any credentials that may have been exposed\n"
        f"  4. Disable IAM user if access key was stolen\n"
    )

    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[HONEYPOT AUTO-RESPONSE] Attacker {attacker_ip} Blocked",
        Message=message
    )
    logger.info("Alert notification sent via SNS.")


def send_error_alert(error_message: str):
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="[HONEYPOT ERROR] Auto-response Lambda failed",
        Message=(
            f"Honeypot Lambda execution failed.\n\n"
            f"Error: {error_message}\n"
            f"Time : {get_utc_now()}\n\n"
            f"Manual intervention required."
        )
    )


def get_utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

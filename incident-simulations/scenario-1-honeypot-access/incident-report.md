# Incident Report: Compromised IAM Credentials Detection via Honeypot

## Executive Summary
**Incident ID:** INC-2026-001  
**Date Detected:** February 15, 2026  
**Severity:** HIGH  
**Detection Method:** CloudWatch Alarm - S3 Honeypot File Access  
**Status:** Investigated & Contained

A security incident was simulated where an attacker with compromised IAM credentials accessed decoy files (honeypot) in an S3 bucket. The detection mechanism successfully identified the unauthorized access within minutes, triggering automated alerts to the security team.

---

## 1. Attack Simulation Details

### 1.1 Honeypot Files Created
| File Name | Contents | Purpose |
|-----------|----------|---------|
| `leaked-credentials.txt` | Fake AWS credentials & DB password | Simulate credential theft |
| `customer-data.sql` | Mock customer PII data (SSNs) | Simulate data exfiltration |

### 1.2 Deployment Commands
```bash
# Create honeypot files with enticing names
echo "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE" > leaked-credentials.txt
echo "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" >> leaked-credentials.txt
echo "DATABASE_PASSWORD=SuperSecretPassword123!" >> leaked-credentials.txt

echo "CUSTOMER_DATABASE_EXPORT_2026" > customer-data.sql
echo "INSERT INTO users VALUES (1,'john','password123','SSN:123-45-6789');" >> customer-data.sql
echo "INSERT INTO users VALUES (2,'jane','password456','SSN:987-65-4321');" >> customer-data.sql

# Upload to honeypot bucket
aws s3 cp leaked-credentials.txt s3://sec-lab-honeypot-1771026055/
aws s3 cp customer-data.sql s3://sec-lab-honeypot-1771026055/
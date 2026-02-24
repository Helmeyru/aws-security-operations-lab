# Security Policy

## Responsible Disclosure

This repository contains educational security content.
All credentials, access keys, IP addresses, and sensitive data shown are **fake and used for simulation only**.

If you discover any real credentials accidentally committed, please:
1. Do NOT use or share them
2. Open a private issue or email the repository owner immediately

## What Is Safe to Commit

- IAM policy JSON files (no secrets, just permission structures)
- EventBridge event pattern JSON files
- Lambda function Python code (no hardcoded keys)
- Incident reports with sanitized/fake data
- Architecture diagrams

## What Must Never Be Committed

- Real AWS Access Key IDs (`AKIA...`)
- Real AWS Secret Access Keys
- `.pem` key pair files
- `.env` files
- Real customer data or PII

## Note on Example Credentials

Any credentials shown in this repo (e.g., `AKIAIOSFODNN7EXAMPLE`) are AWS documentation
example keys and are non-functional by design.

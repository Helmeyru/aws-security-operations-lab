# Incident Report: Unauthorized Access to Honeypot S3 Bucket
**Classification**: SIMULATION (Lab Environment Only)  
**NCA ECC Control**: 8.1 (Threat Detection), 8.3 (Audit Logging)  
**Date**: 15-Feb-2026  
**Report ID**: SEC-LAB-IR-2026-001

## Executive Summary
A simulated unauthorized access event was detected against a decoy S3 bucket (`sec-lab-honeypot-xxx`) containing fake credentials. The incident was automatically detected within **47 seconds** via CloudTrail data events + CloudWatch metric filters, triggering an SNS alert to the security team. No production systems were impacted.

## 1. Incident Timeline
| Time (UTC) | Event | Detection Source |
|------------|-------|------------------|
| 14:23:18 | Attacker IP `203.0.113.42` enumerated S3 bucket contents | CloudTrail `ListBucket` event |
| 14:23:47 | Attacker downloaded `leaked-credentials.txt` | CloudTrail `GetObject` event |
| 14:24:05 | CloudWatch alarm `HoneypotAccessAlarm` triggered | Metric filter match |
| 14:24:12 | SNS alert delivered to security team email | SNS notification |

## 2. Attack Simulation Methodology (SAFE)
**Critical Safety Note**: This simulation used **100% fake credentials** with zero production risk:
```bash
# Fake credentials ONLY (AWS example format)
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE  # ← INVALID key prefix (AKIA = example)
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
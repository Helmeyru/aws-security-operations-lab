# CloudWatch Metrics, Filters & Alarms — AWS Security Operations Lab

## Overview
| Field | Details |
|---|---|
| Account ID | 340805528222 |
| Region | us-east-1 |
| Log Group | /sec-lab/cloudtrail |
| Author | Helmey Al-Showafi |
| Last Updated | 2026-02-24 |

---

## Metric Filters

Metric filters extract data from CloudWatch log streams and publish
custom metrics to CloudWatch whenever a matching pattern is found.

---

### Filter 1: root-account-usage

**Namespace:** `SecurityMetrics`  
**Metric Name:** `root-usage-count`  
**Purpose:** Detects any API activity performed by the AWS root account —
always a critical security event in production.

#### Filter Pattern
```
{ $.userIdentity.type = "Root" }
```

#### Create via CLI
```bash
aws logs put-metric-filter \
  --log-group-name /sec-lab/cloudtrail \
  --filter-name "root-account-usage" \
  --filter-pattern '{ $.userIdentity.type = "Root" }' \
  --metric-transformations \
    metricName=root-usage-count,metricNamespace=SecurityMetrics,metricValue=1,defaultValue=0 \
  --region us-east-1
```

#### Verify
```bash
aws logs describe-metric-filters \
  --log-group-name /sec-lab/cloudtrail \
  --filter-name-prefix "root-account-usage" \
  --region us-east-1
```

---

### Filter 2: unauthorized-api-calls

**Namespace:** `SecurityMetrics`  
**Metric Name:** `unauthorized-api-count`  
**Purpose:** Detects AccessDenied and UnauthorizedOperation errors — a sign
of credential misuse, privilege escalation attempts, or misconfigured permissions.

#### Filter Pattern
```
{ $.errorCode = "AccessDenied" || $.errorCode = "UnauthorizedOperation" }
```

#### Create via CLI
```bash
aws logs put-metric-filter \
  --log-group-name /sec-lab/cloudtrail \
  --filter-name "unauthorized-api-calls" \
  --filter-pattern '{ $.errorCode = "AccessDenied" || $.errorCode = "UnauthorizedOperation" }' \
  --metric-transformations \
    metricName=unauthorized-api-count,metricNamespace=SecurityMetrics,metricValue=1,defaultValue=0 \
  --region us-east-1
```

---

### Filter 3: honeypot-file-access

**Namespace:** `HoneypotDetection`  
**Metric Name:** `sensitive-files-accessed`  
**Purpose:** Detects access to honeypot decoy files. Any match = confirmed
unauthorized access — highly reliable signal with near-zero false positives.

#### Filter Pattern
```
{ $.eventName = "GetObject" &&
  $.requestParameters.bucketName = "sec-lab-honeypot-1771026055" }
```

#### Create via CLI
```bash
aws logs put-metric-filter \
  --log-group-name /sec-lab/cloudtrail \
  --filter-name "honeypot-file-access" \
  --filter-pattern '{ $.eventName = "GetObject" && $.requestParameters.bucketName = "sec-lab-honeypot-1771026055" }' \
  --metric-transformations \
    metricName=sensitive-files-accessed,metricNamespace=HoneypotDetection,metricValue=1,defaultValue=0 \
  --region us-east-1
```

---

### Filter 4: console-login-failures

**Namespace:** `SecurityMetrics`  
**Metric Name:** `console-login-failure-count`  
**Purpose:** Detects failed console login attempts — useful for detecting
brute-force or credential stuffing attacks.

#### Filter Pattern
```
{ $.eventName = "ConsoleLogin" && $.errorMessage = "Failed authentication" }
```

#### Create via CLI
```bash
aws logs put-metric-filter \
  --log-group-name /sec-lab/cloudtrail \
  --filter-name "console-login-failures" \
  --filter-pattern '{ $.eventName = "ConsoleLogin" && $.errorMessage = "Failed authentication" }' \
  --metric-transformations \
    metricName=console-login-failure-count,metricNamespace=SecurityMetrics,metricValue=1,defaultValue=0 \
  --region us-east-1
```

---

## CloudWatch Alarms

---

### Alarm 1: root-usage (🔴 ALARM)

**Current Status:** IN ALARM  
**Metric:** `SecurityMetrics/root-usage-count`  
**Condition:** `root-usage-count > 0 for 1 datapoint within 5 minutes`  
**Notification:** SNS topic `sec-lab-security-alerts`

#### What This Alarm Means
Root account was used in your environment between 21:00–23:30 UTC on
2026-02-23. Root account usage is a critical security event — the root
account should never be used for day-to-day operations.

#### Create via CLI
```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "root-usage" \
  --alarm-description "Alert when root account performs any API action" \
  --metric-name root-usage-count \
  --namespace SecurityMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 0 \
  --comparison-operator GreaterThanThreshold \
  --alarm-actions arn:aws:sns:us-east-1:340805528222:sec-lab-security-alerts \
  --ok-actions arn:aws:sns:us-east-1:340805528222:sec-lab-security-alerts \
  --treat-missing-data notBreaching \
  --region us-east-1
```

#### Investigate Root Activity
```sql
fields timestamp, eventName, sourceIPAddress, userIdentity.arn
| filter userIdentity.type = "Root"
| sort timestamp desc
| limit 50
```

---

### Alarm 2: unauthorized-api-call-alarm (✅ OK)

**Current Status:** OK  
**Metric:** `SecurityMetrics/unauthorized-api-count`  
**Condition:** `unauthorized-api-count > 0 for 1 datapoint within 30 seconds`  
**Notification:** SNS topic `sec-lab-security-alerts`

#### What This Alarm Means
Fires whenever any API call returns AccessDenied or UnauthorizedOperation.
Currently OK — no unauthorized calls in the recent window.

#### Create via CLI
```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "unauthorized-api-call-alarm" \
  --alarm-description "Alert on AccessDenied or UnauthorizedOperation API calls" \
  --metric-name unauthorized-api-count \
  --namespace SecurityMetrics \
  --statistic Sum \
  --period 30 \
  --evaluation-periods 1 \
  --threshold 0 \
  --comparison-operator GreaterThanThreshold \
  --alarm-actions arn:aws:sns:us-east-1:340805528222:sec-lab-security-alerts \
  --ok-actions arn:aws:sns:us-east-1:340805528222:sec-lab-security-alerts \
  --treat-missing-data notBreaching \
  --region us-east-1
```

#### Investigate Unauthorized Calls
```sql
fields timestamp, eventName, sourceIPAddress, userIdentity.arn, errorCode
| filter errorCode = "AccessDenied" or errorCode = "UnauthorizedOperation"
| sort timestamp desc
| limit 100
```

---

### Alarm 3: honeypot-file-access-alarm

**Metric:** `HoneypotDetection/sensitive-files-accessed`  
**Condition:** `sensitive-files-accessed > 0 for 1 datapoint within 1 minute`

#### Create via CLI
```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "honeypot-file-access-alarm" \
  --alarm-description "Alert when any honeypot file is accessed - confirmed compromise" \
  --metric-name sensitive-files-accessed \
  --namespace HoneypotDetection \
  --statistic Sum \
  --period 60 \
  --evaluation-periods 1 \
  --threshold 0 \
  --comparison-operator GreaterThanThreshold \
  --alarm-actions arn:aws:sns:us-east-1:340805528222:sec-lab-security-alerts \
  --treat-missing-data notBreaching \
  --region us-east-1
```

---

## Check All Alarms Status
```bash
aws cloudwatch describe-alarms \
  --region us-east-1 \
  --query "MetricAlarms[*].{Name:AlarmName,State:StateValue,Metric:MetricName,Threshold:Threshold}" \
  --output table
```

## Check All Metric Filters
```bash
aws logs describe-metric-filters \
  --log-group-name /sec-lab/cloudtrail \
  --region us-east-1 \
  --query "metricFilters[*].{Filter:filterName,Pattern:filterPattern,Metric:metricTransformations[0].metricName}" \
  --output table
```

---

## Metrics & Alarms Summary

| Metric Filter | Namespace | Metric Name | Alarm Name | Current State |
|---|---|---|---|---|
| root-account-usage | SecurityMetrics | root-usage-count | root-usage | 🔴 ALARM |
| unauthorized-api-calls | SecurityMetrics | unauthorized-api-count | unauthorized-api-call-alarm | ✅ OK |
| honeypot-file-access | HoneypotDetection | sensitive-files-accessed | honeypot-file-access-alarm | ✅ OK |
| console-login-failures | SecurityMetrics | console-login-failure-count | console-login-failure-alarm | ✅ OK |

---

## Key Notes
- The `root-usage` alarm is currently **IN ALARM** — investigate root account
  activity between 21:00–23:30 UTC on 2026-02-23 using the query above.
- All alarms notify via SNS topic `sec-lab-security-alerts`.
- `unauthorized-api-call-alarm` uses a 30-second period for near-real-time detection.
- Honeypot alarm has zero false positives — any trigger is a confirmed incident.

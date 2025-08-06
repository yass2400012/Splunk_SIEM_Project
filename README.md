# Splunk SIEM Project: DNS Log Analysis & Risk-Based Alerting with MITRE ATT&CK


## Introduction

This project demonstrates how to use Splunk Enterprise Security (ES) and Splunk Security Essentials (SSE) to perform two critical security functions:

• Analyzing DNS Logs – Detecting anomalies, suspicious queries, and potential malicious domains.
• Risk-Based Alerting (RBA) with MITRE ATT&CK Mapping – Assigning risk scores to attacker techniques such as PowerShell, Mimikatz, and WMIexec, and aligning detections with the MITRE ATT&CK framework.

These exercises showcase SIEM configuration, log analysis, and adversary detection workflows that SOC analysts use in real-world environments.

## 🔎 DNS Log Analysis in Splunk

### 1. Search DNS Events
```spl
index=* sourcetype=dns_sample
```

### 🔹 Search DNS Events
![Search DNS Events](project-screenshots/Search%20DNS%20Events.PNG)

### 2. Extract Relevant Fields Using Regex
```spl
index=* sourcetype=dns_sample | regex _raw="(?i)\\b(dns|domain|query|response|port 53)\\b"
```

### 🔹 Extract Relevant Fields Using Regex
![Extract Relevant Fields](project-screenshots/Extract%20Relevant%20Fields%20Using%20Regex.PNG)

### 3. Identify Anomalies (Query Spikes)
```spl
index=* sourcetype=dns_sample | stats count by fqdn
```

### 4. Top Queried Domains and Source IPs
```spl
index=* sourcetype=dns_sample | top fqdn, src_ip
```
### 🔹 Extracting DNS Log Fields in Splunk
![Extracting DNS Log Fields](project-screenshots/Extracting%20DNS%20Log%20Fields%20in%20Splunk.PNG)

### 5. Investigate Suspicious Domains
```spl
index=* sourcetype=dns_sample fqdn="maliciousdomain.com"
```
### 🔹 Investigate Suspicious Domains
![Investigate Suspicious Domains](project-screenshots/Investigate%20Suspicious%20Domains.PNG)

## Part 2: Risk-Based Alerting (RBA) with MITRE ATT&CK

## Step 1: Build Custom RBA Detections

Correlation searches were created in Splunk SSE with added risk scoring fields:

### 2. Extract Relevant Fields Using Regex
```spl
index=windows EventCode=4104
| eval risk_object=user
| eval risk_score=20
| eval mitre_technique="T1059 - Command and Scripting Interpreter"
| table _time, user, host, risk_object, risk_score, mitre_technique
```

Examples configured:

• PowerShell Execution (T1059) → risk_score=20
• Credential Dumping – Mimikatz (T1003) → risk_score=30
• Remote Execution – WMIexec (T1047) → risk_score=40
• High-Risk User Alert (score ≥ 60)

Screenshot: Risk Rules with Custom Content in Splunk SSE


## Step 2: MITRE ATT&CK Mapping
Each detection was mapped to MITRE ATT&CK tactics and techniques for adversary emulation.

MITRE ATT&CK Framework

| Technique ID | Technique Name                    | Tactic            | Status  |
| ------------ | --------------------------------- | ----------------- | ------- |
| T1059        | Command and Scripting Interpreter | Execution         | Covered |
| T1003        | Credential Dumping (Mimikatz)     | Credential Access | Covered |
| T1047        | WMIexec                           | Lateral Movement  | Covered |

## Step 3: Coverage Analysis
Using the MITRE ATT&CK Benchmark dashboard, I validated coverage and visualized detection alignment.

Screenshot: MITRE ATT&CK Benchmark

• 10 Techniques selected
• Coverage shown via potential detections
• Identified improvements for better coverage


## Step 4: Security Essentials Overview
The SSE Overview Dashboard provided high-level visibility:
• of datasources configured
• of detections created
• Top MITRE ATT&CK tactics covered
• Use cases by Security Data Journey

📸 Screenshot: Overview SSE


## Skills Demonstrated

| Skill                         | Description                                                    |
| ----------------------------- | -------------------------------------------------------------- |
| **SIEM Configuration**        | Built Splunk ES lab with custom inputs and Security Essentials |
| **Log Analysis**              | Parsed DNS logs to identify threat indicators                  |
| **Regex Filtering**           | Extracted fields from raw logs                                 |
| **Threat Hunting**            | Investigated suspicious domains and anomalies                  |
| **Risk-Based Alerting (RBA)** | Implemented correlation searches with dynamic risk scoring     |
| **MITRE ATT\&CK Mapping**     | Mapped detections to adversary techniques                      |
| **Framework Alignment**       | Evaluated coverage using MITRE ATT\&CK Benchmark               |


## Conclusion
This project provided hands-on experience with Splunk SIEM, from DNS log analysis to risk-based alerting aligned with MITRE ATT&CK.
Through configuring detections, assigning risk scores, and benchmarking ATT&CK coverage, I gained practical skills in:
• Security monitoring
• Detection engineering
• Threat hunting workflows

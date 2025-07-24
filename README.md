# Project: Analyzing DNS Log Files Using Splunk SIEM


## Introduction

DNS (Domain Name System) logs are crucial for understanding network activity and identifying potential security threats. **Splunk SIEM (Security Information and Event Management)** provides powerful capabilities for analyzing DNS logs and detecting anomalies or malicious activities.

This project demonstrates the process of uploading, parsing, and analyzing DNS logs using **Splunk**.

---

## 🔎 DNS Log Analysis in Splunk

### 1. Search DNS Events
```spl
index=* sourcetype=dns_sample
```

### 2. Extract Relevant Fields Using Regex
```spl
index=* sourcetype=dns_sample | regex _raw="(?i)\\b(dns|domain|query|response|port 53)\\b"
```

### 3. Identify Anomalies (Query Spikes)
```spl
index=* sourcetype=dns_sample | stats count by fqdn
```

### 4. Top Queried Domains and Source IPs
```spl
index=* sourcetype=dns_sample | top fqdn, src_ip
```

### 5. Investigate Suspicious Domains
```spl
index=* sourcetype=dns_sample fqdn="maliciousdomain.com"
```


## Sample Queries Breakdown

➤ Search all DNS log entries
```spl
source="dns.log" host="yass" sourcetype="dns"
```

➤ Get count of each FQDN
```spl
source="dns.log" host="yass" sourcetype="dns"
| rex field=_raw "^(?<timestamp>\S+)\s+\S+\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+(?<dest_ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\S+\s+(?<fqdn>[^\s]+)\s+\S+\s+\S+\s+\S+\s+(?<query_type>[^\s]+)\s+\S+\s+(?<response_code>[^\s]+)"
| table timestamp, src_ip, dest_ip, fqdn, query_type, response_code
```

➤ Top 10 IPs querying suspicious domains
```spl
source="dns_sample_with_malicious.log" host="yass" sourcetype="dns_sample_with_malicious"
```


## Skills Demonstrated

| Skill              | Description                                     |
| ------------------ | ----------------------------------------------- |
| SIEM Configuration | Set up Splunk inputs, source types, and indexes |
| Log Analysis       | Parsed DNS logs for threat indicators           |
| Regex Filtering    | Extracted keywords from raw logs                |
| Threat Hunting     | Identified anomalies and unusual domains        |
| Query Development  | Created SPL searches for insight                |

Analyzing DNS log files using Splunk SIEM enables security analysts to:
Understand DNS activity
Detect malicious behavior
Investigate suspicious traffic


## 📸 Screenshots

### 🔹 Search DNS Events
![Search DNS Events](project-screenshots/Search%20DNS%20Events.PNG)

### 🔹 Extract Relevant Fields Using Regex
![Extract Relevant Fields](project-screenshots/Extract%20Relevant%20Fields%20Using%20Regex.PNG)

### 🔹 Extracting DNS Log Fields in Splunk
![Extracting DNS Log Fields](project-screenshots/Extracting%20DNS%20Log%20Fields%20in%20Splunk.PNG)

### 🔹 Investigate Suspicious Domains
![Investigate Suspicious Domains](project-screenshots/Investigate%20Suspicious%20Domains.PNG)


## Conclusion
Working with DNS log files in Splunk to understand how DNS activity can reveal signs of suspicious or malicious behavior. provided hands-on experience with log analysis, regex filtering, and using Splunk search queries—skills.

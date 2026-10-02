# Part 050: SIEM Rules และ SQL Injection Detection

## ภาพรวม

Blue Team: สร้าง SIEM rules, Sigma rules, และ log analysis สำหรับตรวจจับ SQL injection

**ขั้นตอนที่ 801-820**

---

## 801. Sigma Rules สำหรับ SQL Injection

```yaml
# sigma-sqli-basic.yml
title: SQL Injection Attempt in Web Logs
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
description: Detects SQL injection patterns in web application logs
author: Security Team
date: 2024-01-01
tags:
  - attack.initial_access
  - attack.t1190
  - attack.injection
logsource:
  category: webserver
detection:
  keywords:
    - "' OR "
    - "UNION SELECT"
    - "UNION ALL SELECT"
    - "1=1--"
    - "DROP TABLE"
    - "xp_cmdshell"
    - "SLEEP("
    - "WAITFOR DELAY"
    - "information_schema"
    - "sys.tables"
  condition: keywords
falsepositives:
  - Legitimate SQL queries in application logs
level: high
```

---

## 802. Kibana/Elasticsearch Detection

```json
{
  "query": {
    "bool": {
      "should": [
        {"match_phrase": {"message": "UNION SELECT"}},
        {"match_phrase": {"message": "OR 1=1"}},
        {"match_phrase": {"message": "xp_cmdshell"}},
        {"match_phrase": {"message": "SLEEP("}},
        {"match_phrase": {"message": "WAITFOR DELAY"}}
      ],
      "minimum_should_match": 1
    }
  }
}
```

---

## 803. Splunk SPL Rules

```
# Splunk SPL query สำหรับ SQL injection
index=web_logs
| where match(uri_query, "(?i)(union select|' or |xp_cmdshell|sleep\\(|waitfor delay)")
| table _time, src_ip, http_method, uri, uri_query, status
| sort -_time

# Alert เมื่อมีหลาย requests จาก IP เดียว
index=web_logs
| eval is_sqli=if(match(uri_query,"(?i)(union.{0,20}select|sleep\\(|waitfor)"),1,0)
| where is_sqli=1
| stats count as attempts by src_ip
| where attempts > 5
| sort -attempts
```

---

## 804. Python Log Analyzer

```python
import re
from collections import defaultdict
from datetime import datetime

SQLI_PATTERNS = [
    (r"(?i)union\s+(?:all\s+)?select", "UNION SELECT"),
    (r"(?i)xp_cmdshell", "xp_cmdshell"),
    (r"(?i)sleep\s*\(\d+\)", "SLEEP()"),
    (r"(?i)waitfor\s+delay", "WAITFOR DELAY"),
    (r"(?i)information_schema", "information_schema"),
    (r"(?i)load_file\s*\(", "LOAD_FILE"),
    (r"(?i)into\s+outfile", "INTO OUTFILE"),
]

class SQLILogAnalyzer:
    def __init__(self):
        self.alerts = []
        self.ip_counts = defaultdict(int)
    
    def analyze_line(self, line: str) -> list:
        findings = []
        for pattern, name in SQLI_PATTERNS:
            if re.search(pattern, line):
                findings.append(name)
        return findings
    
    def parse_nginx_log(self, log_path: str):
        pattern = r'(\d+\.\d+\.\d+\.\d+).*\[([^\]]+)\].*"(\w+) ([^"]+) HTTP/\d\.\d" (\d+)'
        
        with open(log_path) as f:
            for line in f:
                match = re.search(pattern, line)
                if not match:
                    continue
                
                ip, timestamp, method, path, status = match.groups()
                findings = self.analyze_line(path)
                
                if findings:
                    self.ip_counts[ip] += 1
                    self.alerts.append({
                        'ip': ip,
                        'timestamp': timestamp,
                        'method': method,
                        'path': path[:200],
                        'status': status,
                        'patterns': findings
                    })
    
    def report(self):
        print(f"[*] Total alerts: {len(self.alerts)}")
        print(f"[*] Unique attacking IPs: {len(self.ip_counts)}")
        print("\nTop attackers:")
        for ip, count in sorted(self.ip_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"  {ip}: {count} attempts")
        return self.alerts

# Usage
analyzer = SQLILogAnalyzer()
# analyzer.parse_nginx_log('/var/log/nginx/access.log')
# alerts = analyzer.report()
```

---

## 805. Real-time Alerting

```python
import smtplib
import requests
from email.mime.text import MIMEText
from datetime import datetime

class AlertManager:
    def __init__(self, slack_webhook=None, email_config=None):
        self.slack_webhook = slack_webhook
        self.email_config = email_config
    
    def send_slack(self, message: str):
        if not self.slack_webhook:
            return
        payload = {
            "text": f":warning: *SQL Injection Alert*\n```{message}```",
            "username": "SecBot"
        }
        requests.post(self.slack_webhook, json=payload, timeout=5)
    
    def alert(self, event: dict):
        message = (
            f"Time: {datetime.now().isoformat()}\n"
            f"IP: {event.get('ip')}\n"
            f"Path: {event.get('path', '')[:100]}\n"
            f"Patterns: {', '.join(event.get('patterns', []))}"
        )
        self.send_slack(message)
```

---

## สรุป

SIEM Detection:
- **Sigma rules** - portable detection rules
- **Kibana/Splunk** - query-based detection
- **Python analyzer** - custom log parsing
- **Real-time alerts** - Slack, Email notifications
- **IP tracking** - พบ attackers จากจำนวน attempts

---

*Part 050 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

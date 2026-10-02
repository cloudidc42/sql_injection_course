# Part 043: Database Monitoring และ Detection

## ภาพรวม

การตรวจจับและติดตาม SQL Injection attacks สำหรับ Blue Team

**ขั้นตอนที่ 661-680**

---

## 661. Database Audit Logging

```sql
-- MySQL - Enable query logging
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/general.log';

-- MySQL - Error log
SHOW VARIABLES LIKE 'log_error';

-- MySQL - Slow query log
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;

-- PostgreSQL - pg_audit extension
SHARED_PRELOAD_LIBRARIES = 'pgaudit'
pgaudit.log = 'all'

-- MSSQL - Audit
CREATE SERVER AUDIT MyAudit
TO FILE (FILEPATH = 'C:\Audit\');

CREATE SERVER AUDIT SPECIFICATION MyAuditSpec
FOR SERVER AUDIT MyAudit
ADD (FAILED_LOGIN_GROUP),
ADD (SUCCESSFUL_LOGIN_GROUP);

ALTER SERVER AUDIT MyAudit WITH (STATE = ON);
```

---

## 662. Detection Patterns

```python
import re
from datetime import datetime

# SQL Injection patterns
SQLI_PATTERNS = [
    r"'\s*(OR|AND)\s*'?\s*\d+\s*=\s*\d+",  # ' OR 1=1
    r"UNION\s+(?:ALL\s+)?SELECT",             # UNION SELECT
    r"--\s*$",                                 # SQL comment
    r"/\*.*?\*/",                              # block comment
    r"DROP\s+TABLE",                           # DROP TABLE
    r"DELETE\s+FROM",                          # DELETE
    r"EXEC\s*\(",                              # EXEC(
    r"xp_cmdshell",                            # xp_cmdshell
    r"SLEEP\s*\(",                             # SLEEP(
    r"WAITFOR\s+DELAY",                        # WAITFOR DELAY
]

def detect_sqli(query: str) -> list:
    findings = []
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, query, re.IGNORECASE):
            findings.append(pattern)
    return findings

def analyze_log_file(log_path: str):
    alerts = []
    with open(log_path) as f:
        for line_num, line in enumerate(f, 1):
            detections = detect_sqli(line)
            if detections:
                alerts.append({
                    'line': line_num,
                    'query': line.strip(),
                    'patterns': detections,
                    'timestamp': datetime.now().isoformat()
                })
    return alerts
```

---

## 663. Real-time Monitoring

```python
import mysql.connector
import threading
import time

class MySQLMonitor:
    def __init__(self, host, user, password, database):
        self.conn = mysql.connector.connect(
            host=host, user=user, password=password, database=database
        )
        self.patterns = [
            'union select', 'or 1=1', "' or '",
            'xp_cmdshell', 'sleep(', 'waitfor delay'
        ]
        self.alerts = []
    
    def check_processlist(self):
        """Monitor active queries"""
        cursor = self.conn.cursor()
        cursor.execute("SHOW PROCESSLIST")
        processes = cursor.fetchall()
        cursor.close()
        
        for proc in processes:
            query = str(proc[7]).lower() if proc[7] else ''
            for pattern in self.patterns:
                if pattern in query:
                    alert = {
                        'time': time.time(),
                        'process_id': proc[0],
                        'user': proc[1],
                        'host': proc[2],
                        'query': query,
                        'pattern': pattern
                    }
                    self.alerts.append(alert)
                    print(f"[ALERT] SQLi attempt from {proc[2]}: {query[:100]}")
    
    def monitor(self, interval: float = 1.0):
        """Continuously monitor"""
        print(f"[*] Monitoring MySQL for SQL injection...")
        while True:
            try:
                self.check_processlist()
                time.sleep(interval)
            except KeyboardInterrupt:
                break
            except Exception as e:
                time.sleep(interval)

# Usage
monitor = MySQLMonitor('localhost', 'monitor_user', 'pass', 'mydb')
monitor.monitor()
```

---

## 664. IDS/IPS Configuration (ModSecurity)

```apache
# ModSecurity SQL Injection Rules
<IfModule mod_security2.c>
    SecRuleEngine On
    
    # OWASP CRS SQL Injection rules (942xxx)
    Include /etc/modsecurity/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
    
    # Custom sensitive rule
    SecRule ARGS "(?i:union.+select|select.+from|insert.+into|delete.+from|drop.+table)" \
        "id:9001,phase:2,deny,status:403,msg:'SQL Injection Attack'"
    
    SecRule REQUEST_HEADERS:User-Agent "(?i:sqlmap|havij|netsparker)" \
        "id:9002,phase:1,deny,status:403,msg:'Known SQL Injection Tool'"
IfModule>
```

---

## 665. SIEM Integration

```python
import json
import requests
import hashlib
from datetime import datetime

class SIEMLogger:
    def __init__(self, siem_url, api_key):
        self.siem_url = siem_url
        self.api_key = api_key
    
    def send_alert(self, event: dict):
        payload = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'sql_injection_attempt',
            'severity': 'high',
            'details': event
        }
        
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        try:
            r = requests.post(
                f'{self.siem_url}/api/alerts',
                json=payload,
                headers=headers,
                timeout=5
            )
            return r.status_code == 200
        except Exception:
            return False

# ใช้ middleware ใน Flask
from flask import Flask, request, abort

app = Flask(__name__)
logger = SIEMLogger('http://siem.example.com', 'API_KEY')

@app.before_request
def check_sqli():
    for param, value in request.args.items():
        if detect_sqli(value):
            logger.send_alert({
                'ip': request.remote_addr,
                'path': request.path,
                'param': param,
                'payload': value
            })
            abort(403)
```

---

## สรุป

Database Monitoring:
- **Audit Logging** - บันทึกทุก query
- **Pattern Detection** - ตรวจสอบ SQL injection patterns
- **Real-time Monitor** - PROCESSLIST monitoring
- **IDS/WAF** - ModSecurity OWASP CRS
- **SIEM** - ส่ง alerts ไปยัง security team

---

*Part 043 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

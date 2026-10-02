# Part 068: Database Forensics หลัง SQL Injection

## ภาพรวม

การทำ forensics หลังจากถูก SQL injection

**ขั้นตอนที่ 1091-1105**

---

## 1091. ขั้นตอน Incident Response

```
1. Contain  - แยก system ออกจาก network
2. Identify - ระบุ scope ของการโจมตี
3. Preserve - เก็บรักษา evidence
4. Analyze  - วิเคราะห์วิธีการโจมตี
5. Eradicate - ลบรอย compromise
6. Recover  - ฟื้นระบบ
7. Report   - ทำรายงาน

SQL Injection Indicators of Compromise (IoC):
- ERROR messages ใน logs (syntax error, unclosed quotation)
- UNION SELECT ใน web logs
- ปริมาณข้อมูล DB ลดลงอย่างผิดปกติ (data exfiltration)
- Webshell files ใน web directories
- New admin accounts ใน DB
- พรีว response times ผิดปกติ (time-based attacks)
```

---

## 1092. Log Analysis

```python
import re
import gzip
from pathlib import Path
from datetime import datetime

class ForensicLogAnalyzer:
    SQLI_PATTERNS = [
        r"UNION\s+(ALL\s+)?SELECT",
        r"'\s*(OR|AND)\s+'?\s*\d+\s*=\s*\d+",
        r"SLEEP\(\d+\)",
        r"WAITFOR\s+DELAY",
        r"xp_cmdshell",
        r"LOAD_FILE",
        r"INTO\s+OUTFILE",
        r"information_schema",
        r"EXTRACTVALUE\(",
        r"BENCHMARK\(",
    ]
    
    def __init__(self):
        self.events = []
    
    def analyze_log(self, log_path: str):
        p = Path(log_path)
        opener = gzip.open if p.suffix == '.gz' else open
        
        with opener(log_path, 'rt', errors='replace') as f:
            for lineno, line in enumerate(f, 1):
                for pattern in self.SQLI_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        self.events.append({
                            'line': lineno,
                            'content': line.strip()[:200],
                            'pattern': pattern,
                        })
                        break
    
    def get_timeline(self) -> list:
        """Extract timestamps and sort by time"""
        dated = []
        ts_pattern = r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})'
        
        for event in self.events:
            match = re.search(ts_pattern, event['content'])
            if match:
                try:
                    ts = datetime.strptime(match.group(1), '%d/%b/%Y:%H:%M:%S')
                    dated.append({**event, 'timestamp': ts})
                except ValueError:
                    pass
        
        return sorted(dated, key=lambda x: x['timestamp'])
    
    def get_attacker_ips(self) -> dict:
        ip_counts = {}
        ip_pattern = r'^(\d+\.\d+\.\d+\.\d+)'
        
        for event in self.events:
            match = re.match(ip_pattern, event['content'])
            if match:
                ip = match.group(1)
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        return dict(sorted(ip_counts.items(), key=lambda x: -x[1]))

# การใช้ (forensic mode):
analyzer = ForensicLogAnalyzer()
analyzer.analyze_log('/var/log/apache2/access.log')
print("Attack timeline:")
for e in analyzer.get_timeline()[:10]:
    print(f"  {e.get('timestamp')} - {e['content'][:80]}")
print("\nAttacker IPs:", analyzer.get_attacker_ips())
```

---

## 1093. Database การตรวจสอบ

```sql
-- MySQL: ดู user ที่ถูกสร้างใหม่
-- (attacker อาจสร้าง backdoor user)
SELECT User, Host, Password, Create_priv, Super_priv, 
       Grant_priv, account_locked
FROM mysql.user
ORDER BY Create_time DESC;  -- user ใหม่สุด

-- ดู stored procedures ที่สงสัย
-- (attacker อาจชักทำ backdoor เป็น stored proc)
SELECT ROUTINE_SCHEMA, ROUTINE_NAME, ROUTINE_TYPE, CREATED, LAST_ALTERED
FROM information_schema.ROUTINES
ORDER BY LAST_ALTERED DESC;

-- ดู scheduled events
SELECT EVENT_SCHEMA, EVENT_NAME, EVENT_DEFINITION, STATUS, CREATED
FROM information_schema.EVENTS
ORDER BY CREATED DESC;

-- MSSQL: ดู login ครั้งล่าสุด
SELECT login_name, event_time, client_ip, action_id
FROM sys.fn_get_audit_file('/var/opt/mssql/data/audit*.sqlaudit', DEFAULT, DEFAULT)
ORDER BY event_time DESC;

-- PostgreSQL: ดู audit log (pgaudit)
SELECT log_time, user_name, database_name, command_tag, query
FROM pg_log  -- pgaudit log table
ORDER BY log_time DESC LIMIT 100;
```

---

## 1094. Evidence Preservation

```bash
# Linux: เก็บรักษา evidence

# 1. สร้าง forensic copy ของ web logs
md5sum /var/log/apache2/access.log > access.log.md5
cp /var/log/apache2/access.log evidence/

# 2. Database dump (preserve state)
mysqldump --all-databases > evidence/db_snapshot_$(date +%Y%m%d).sql
md5sum evidence/db_snapshot_*.sql > evidence/db_snapshot.md5

# 3. เก็บ process list
mysqladmin processlist > evidence/mysql_procs_$(date +%Y%m%d_%H%M%S).txt

# 4. Network connections
ss -tnp | grep 3306 > evidence/db_connections.txt

# 5. Memory dump (ปรับตาม OS)
avml capture evidence/  # Linux
winpmem memory.raw      # Windows

# 6. Filesystem timeline
find /var/www/html -newer /var/www/html/index.php -type f \
  | xargs ls -la > evidence/new_files.txt
```

---

## 1095. รายงาน Forensic

```markdown
# SQL Injection Incident Report

## Executive Summary
- Date of Detection: ...
- Date of Breach: ...
- Systems Affected: ...
- Data Compromised: ...

## Timeline of Events
| Time | Event | Source |
|------|-------|--------|
| T-1  | First SQLi attempt | Web log |
| T0   | Successful extraction | DB log |
| T+1  | Webshell uploaded | File system |

## Attack Vector
- Entry point: /search?q= parameter
- Type: UNION-based SQLi
- Tool: SQLMap (based on User-Agent pattern)

## Data Exfiltrated
- Tables accessed: users, transactions
- Records affected: ~50,000

## Remediation
- Patched vulnerable parameter
- Added parameterized queries
- Deployed WAF rules
- Reset all DB credentials

## Recommendations
1. Regular pentest
2. SIEM monitoring
3. WAF deployment
```

---

## สรุป

Database Forensics:
- **IR steps** - Contain, Identify, Preserve, Analyze
- **Log analysis** - Python analyzer + regex patterns
- **DB audit** - หา backdoor users/procedures
- **Evidence** - md5sum, timestamps, memory dump
- **Report** - timeline, scope, remediation

---

*Part 068 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

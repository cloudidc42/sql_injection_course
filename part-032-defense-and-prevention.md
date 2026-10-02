# Part 032: Defense และการป้องกัน SQL Injection

## ภาพรวม

การป้องกัน SQL Injection เป็นสิ่งสำคัญที่สุดใน web security เรียนรู้วิธีการแก้ไขทั้งใน code และอีกหลายชั้น

**ขั้นตอนที่ 456-475**

---

## 456. Prepared Statements (Most Important)

### 56.1 PHP - PDO

```php
<?php
// VULNERABLE (DO NOT DO THIS)
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = $pdo->query($query);

// SECURE - Prepared Statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
$result = $stmt->fetchAll();

// SECURE - Named Parameters
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
$stmt->execute([
    ':username' => $_POST['username'],
    ':password' => hash('sha256', $_POST['password'])
]);
```

### 56.2 PHP - MySQLi

```php
<?php
$conn = new mysqli("localhost", "user", "pass", "db");

// SECURE
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$username = $_POST['username'];
$password = hash('sha256', $_POST['password']);
$stmt->execute();
$result = $stmt->get_result();
```

### 56.3 Python - psycopg2

```python
import psycopg2

conn = psycopg2.connect("dbname=mydb user=myuser")
cur = conn.cursor()

# VULNERABLE
# cur.execute(f"SELECT * FROM users WHERE id = {user_id}")

# SECURE
cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
results = cur.fetchall()
```

### 56.4 Python - SQLAlchemy ORM

```python
from sqlalchemy.orm import Session
from sqlalchemy import select

# SECURE - ORM query
with Session(engine) as session:
    users = session.execute(
        select(User).where(User.id == user_id)
    ).scalars().all()

# SECURE - raw SQL with params
with engine.connect() as conn:
    result = conn.execute(
        text("SELECT * FROM users WHERE id = :id"),
        {"id": user_id}
    )
```

### 56.5 Java - PreparedStatement

```java
// VULNERABLE
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);

// SECURE
PreparedStatement pstmt = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ?"
);
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();
```

### 56.6 Node.js - mysql2

```javascript
// VULNERABLE
const query = `SELECT * FROM users WHERE id = ${userId}`;

// SECURE
const [rows] = await connection.execute(
    'SELECT * FROM users WHERE id = ?',
    [userId]
);

// SECURE - named params
const [rows] = await connection.execute(
    'SELECT * FROM users WHERE username = :username',
    { username: req.body.username }
);
```

---

## 457. Input Validation

```python
import re
from typing import Union

def validate_id(value: str) -> Union[int, None]:
    """Validate that ID is a positive integer"""
    try:
        num = int(value)
        if num > 0:
            return num
    except (ValueError, TypeError):
        pass
    return None

def validate_username(value: str) -> Union[str, None]:
    """Allow only alphanumeric and underscore"""
    if value and re.match(r'^[a-zA-Z0-9_]{3,50}$', value):
        return value
    return None

# Usage
user_id = validate_id(request.args.get('id'))
if user_id is None:
    return "Invalid ID", 400
```

---

## 458. Least Privilege

```sql
-- MySQL: สร้าง user เฉพาะโดยไม่มีสิทธิ์เกินควร
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'strong_password';

-- ให้เฉพาะ SELECT สำหรับ tables ที่จำเป็น
GRANT SELECT ON mydb.products TO 'webapp'@'localhost';
GRANT SELECT, INSERT ON mydb.orders TO 'webapp'@'localhost';

-- ไม่ให้สิทธิ์ FILE, SUPER, GRANT
-- ไม่ให้ access mysql.user table

FLUSH PRIVILEGES;
```

---

## 459. WAF Configuration (ModSecurity)

```apache
# Apache ModSecurity Config
<IfModule mod_security2.c>
    SecRuleEngine On
    SecRequestBodyAccess On
    SecResponseBodyAccess On
    
    # OWASP CRS (Core Rule Set)
    Include /etc/modsecurity/crs/crs-setup.conf
    Include /etc/modsecurity/crs/rules/*.conf
    
    # Custom rule สำหรับ SQL injection
    SecRule ARGS "(union|select|insert|update|delete|drop|create)" \
        "id:1001,phase:2,deny,status:403,msg:'SQL Injection Attempt'"
IfModule>
```

---

## 460. Error Handling ที่ถูกต้อง

```php
<?php
// WRONG - แสดง SQL error ให้ user
try {
    $result = $pdo->query($sql);
} catch (PDOException $e) {
    echo "SQL Error: " . $e->getMessage(); // BAD!
}

// CORRECT - log error, แสดง generic message
try {
    $result = $pdo->query($sql);
} catch (PDOException $e) {
    error_log($e->getMessage()); // log เ privately
    http_response_code(500);
    echo "An error occurred. Please try again."; // generic message
    exit;
}
```

---

## 461. SAST/DAST Tools

```bash
# SAST (Static Analysis)
# Bandit - Python
pip install bandit
bandit -r ./app -l

# Semgrep
pip install semgrep
semgrep --config p/sql-injection .

# DAST (Dynamic Analysis)
# OWASP ZAP
zap-baseline.py -t http://localhost:5000

# sqlmap สำหรับ scan
sqlmap -u "http://localhost:5000" --crawl=3 --batch --dbs
```

---

## 462. Security Headers

```python
from flask import Flask, Response

app = Flask(__name__)

@app.after_request
def add_security_headers(response: Response) -> Response:
    # Prevent content-type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # HSTS
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # CSP
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    return response
```

---

## สรุป

SQL Injection Prevention:
1. **Prepared Statements** - วิธีที่ดีที่สุด
2. **Input Validation** - whitelist characters
3. **Least Privilege** - จำกัดสิทธิ์ไว้เป็นขั้นต่ำสุด
4. **WAF** - ModSecurity, cloud WAF
5. **Error Handling** - ไม่เปิดเผย SQL errors
6. **Monitoring** - log และเตือนความผิดปกติ

---

*Part 032 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

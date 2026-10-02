# Part 005: Understanding SQL Queries in Web Applications
## ทำความเข้าใจ SQL Queries ใน Web Applications และการสร้าง Query ที่ปลอดภัย

**ระดับ:** ⭐⭐ Easy  
**เวลาที่ใช้เรียน:** 3-4 ชั่วโมง  
**Prerequisites:** Part 001-004

---

## 🎯 วัตถุประสงค์การเรียนรู้

เมื่อเรียนจบบทนี้ ผู้เรียนจะสามารถ:
1. อธิบายวิธีที่ Web Application สร้าง SQL Queries
2. ระบุ Pattern ของ Query Construction ที่อันตราย
3. เข้าใจหลักการทำงานของ Parameterized Queries
4. วิเคราะห์ว่า Input ใดที่ควบคุม Query ได้อย่างไร
5. เตรียมพร้อมสำหรับการทดสอบ SQL Injection จริง

---

## 1. วงจรชีวิตของ SQL Query (SQL Query Lifecycle)

เมื่อผู้ใช้ส่ง Request มายัง Web Application สิ่งต่อไปนี้เกิดขึ้น:

```
User Action (กรอกฟอร์ม/คลิกลิงก์)
         ↓
Browser สร้าง HTTP Request
         ↓
Web Server รับ Request
         ↓
Application Code รับ User Input
         ↓
Application สร้าง SQL Query
         ↓
Database Driver ส่ง Query ไปยัง Database
         ↓
Database Parse และ Execute Query
         ↓
Database ส่งผลลัพธ์กลับ
         ↓
Application ประมวลผลผลลัพธ์
         ↓
Browser แสดงผล HTML
```

---

## 2. Query Construction Patterns

### Pattern 1: Simple String Concatenation (อันตรายมาก!)

```php
// PHP - String Concatenation
$id = $_GET['id'];
$query = "SELECT * FROM products WHERE id = " . $id;
```

**ปัญหา:** ถ้า `$id` = `1 OR 1=1`, Query กลายเป็น:
```sql
SELECT * FROM products WHERE id = 1 OR 1=1
```

### Pattern 2: String Interpolation (อันตรายมาก!)

```python
# Python - String Interpolation
username = request.form['username']
query = f"SELECT * FROM users WHERE username = '{username}'"
```

**ปัญหา:** ถ้า `username` = `admin' OR '1'='1`, Query กลายเป็น:
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1'
```

### Pattern 3: String Formatting (อันตราย!)

```javascript
// JavaScript - String Formatting  
const userId = req.params.id;
const query = `SELECT * FROM users WHERE id = ${userId}`;
```

### Pattern 4: Parameterized Query (ปลอดภัย!)

```php
// PHP - Parameterized Query (Prepared Statement)
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$username]);
```

```python
# Python - Parameterized Query
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
```

```javascript
// JavaScript/Node.js - Parameterized Query
db.query("SELECT * FROM users WHERE id = ?", [userId], callback);
```

---

## 3. ทำไม String Concatenation ถึงอันตราย (Why String Concatenation is Dangerous)

### ตัวอย่างเปรียบเทียบโดยละเอียด

```php
<?php
// กรณีที่ 1: Login Form ธรรมดา
$username = "admin";
$password = "password123";

// String Concatenation สร้าง Query:
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
// ผล:
// SELECT * FROM users WHERE username = 'admin' AND password = 'password123'
// → ถูกต้อง ทำงานปกติ

// กรณีที่ 2: ผู้ใช้ส่ง SQL Injection
$username = "admin'--";
$password = "anything";

// String Concatenation สร้าง Query:
$query = "SELECT * FROM users WHERE username = 'admin'--' AND password = 'anything'";
// ผล:
// SELECT * FROM users WHERE username = 'admin'  ← จุดสิ้นสุดที่ --
// --' AND password = 'anything'  ← ส่วนนี้ถูก Comment ออก!
// → Login สำเร็จโดยไม่ต้องรู้ Password!

// กรณีที่ 3: UNION Attack
$id = "0 UNION SELECT 1,username,password,4 FROM users--";

$query = "SELECT id, name, price, description FROM products WHERE id = $id";
// ผล:
// SELECT id, name, price, description FROM products WHERE id = 0 
// UNION SELECT 1,username,password,4 FROM users--
// → แสดงข้อมูล Username และ Password ทั้งหมด!
?>
```

---

## 4. SQL Query Types ใน Web Applications

### 4.1 SELECT Queries (Data Retrieval)

```php
// Login Authentication
$q1 = "SELECT id, username, role FROM users 
       WHERE username = '$username' AND password = '$password'";

// Product Detail
$q2 = "SELECT * FROM products WHERE id = $id";

// Search
$q3 = "SELECT * FROM products 
       WHERE name LIKE '%$search%' OR description LIKE '%$search%'";

// User Profile
$q4 = "SELECT username, email, phone FROM users WHERE id = $user_id";

// Order History
$q5 = "SELECT o.*, p.name 
       FROM orders o 
       JOIN products p ON o.product_id = p.id 
       WHERE o.user_id = $user_id 
       ORDER BY $sort $order";
```

### 4.2 INSERT Queries (Data Creation)

```php
// User Registration
$q1 = "INSERT INTO users (username, password, email) 
       VALUES ('$username', '$password', '$email')";

// Submit Comment
$q2 = "INSERT INTO comments (user_id, product_id, comment, rating) 
       VALUES ($user_id, $product_id, '$comment', $rating)";

// Log Access (Header Injection!)
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
$q3 = "INSERT INTO access_logs (ip_address, url, timestamp) 
       VALUES ('$ip', '$url', NOW())";
```

### 4.3 UPDATE Queries (Data Modification)

```php
// Update Profile
$q1 = "UPDATE users SET email = '$email', phone = '$phone' 
       WHERE id = $user_id";

// Change Password
$q2 = "UPDATE users SET password = '$new_password' 
       WHERE id = $user_id AND password = '$old_password'";

// Update Settings
$q3 = "UPDATE user_settings SET theme = '$theme', language = '$lang' 
       WHERE user_id = $user_id";
```

### 4.4 DELETE Queries (Data Deletion)

```php
// Delete Comment
$q1 = "DELETE FROM comments WHERE id = $comment_id AND user_id = $user_id";

// Delete Account
$q2 = "DELETE FROM users WHERE id = $user_id";
```

---

## 5. การวิเคราะห์ Query เพื่อหาจุดโจมตี (Attack Point Analysis)

### เทคนิคการวิเคราะห์ Query

เมื่อเราเห็น URL หรือ Form ให้ถามตัวเองว่า:

```
1. Input ใดถูกนำไปใส่ใน Query?
2. Input นั้นถูก Quote ด้วย ' หรือไม่?
3. มีการ Validate/Sanitize ก่อนหรือเปล่า?
4. Input อยู่ในส่วนใดของ Query?
   - WHERE clause?
   - ORDER BY clause?
   - LIMIT clause?
   - INSERT/UPDATE values?
```

### ตัวอย่างการวิเคราะห์

```
URL: /products?id=5&sort=price&order=asc

สมมติว่า PHP Code เป็น:
$id = $_GET['id'];
$sort = $_GET['sort'];
$order = $_GET['order'];
$query = "SELECT * FROM products WHERE id=$id ORDER BY $sort $order";

วิเคราะห์:
- $id: Integer context, ไม่มี Quote → SQLi ง่ายด้วย: 5 OR 1=1
- $sort: ไม่มี Quote, ใน ORDER BY → อาจใช้: price, (SELECT SLEEP(5))
- $order: ไม่มี Quote → อาจใช้: asc, DESC, (CASE WHEN 1=1 THEN asc ELSE SLEEP(5) END)
```

---

## 6. Context-Based SQL Injection (ประเภทตาม Context)

### 6.1 String Context

```sql
-- Input อยู่ใน String Context (ระหว่าง Quotes)
SELECT * FROM users WHERE username = '[INPUT]'

-- วิธีออกจาก String Context: ใส่ ' เพิ่มเข้าไป
-- Input: ' OR '1'='1
-- Result: SELECT * FROM users WHERE username = '' OR '1'='1'

-- Input: admin' --
-- Result: SELECT * FROM users WHERE username = 'admin' --'
```

### 6.2 Numeric Context

```sql
-- Input อยู่ใน Numeric Context (ไม่มี Quotes)
SELECT * FROM products WHERE id = [INPUT]

-- ไม่จำเป็นต้องออกจาก Context
-- Input: 1 OR 1=1
-- Result: SELECT * FROM products WHERE id = 1 OR 1=1

-- Input: 0 UNION SELECT 1,2,3
-- Result: SELECT * FROM products WHERE id = 0 UNION SELECT 1,2,3
```

### 6.3 ORDER BY Context

```sql
-- Input อยู่ใน ORDER BY
SELECT * FROM products ORDER BY [INPUT]

-- ไม่สามารถใช้ UNION ได้ใน ORDER BY
-- ใช้ CASE WHEN แทน:
-- Input: (CASE WHEN 1=1 THEN price ELSE name END)
-- Result: SELECT * FROM products ORDER BY (CASE WHEN 1=1 THEN price ELSE name END)

-- สำหรับ Boolean-Based Blind:
-- Input: (SELECT CASE WHEN (1=1) THEN price ELSE SLEEP(5) END)
```

### 6.4 LIKE Context

```sql
-- Input อยู่ใน LIKE Pattern
SELECT * FROM products WHERE name LIKE '%[INPUT]%'

-- วิธีออก: ใส่ %' เพื่อปิด Pattern แล้วเพิ่ม Condition
-- Input: %' OR 1=1--
-- Result: SELECT * FROM products WHERE name LIKE '%%' OR 1=1--'%'
```

### 6.5 IN Context

```sql
-- Input อยู่ใน IN Clause
SELECT * FROM products WHERE category IN ([INPUT])

-- Input: 1,2,3) OR 1=1 --
-- Result: SELECT * FROM products WHERE category IN (1,2,3) OR 1=1 --'
```

---

## 7. Parameterized Queries (การป้องกัน)

### ทำไม Parameterized Queries ถึงปลอดภัย?

```
Prepared Statement ทำงานอย่างไร:

1. ส่ง Template Query ไปยัง Database:
   "SELECT * FROM users WHERE username = ?"
   Database parse และเตรียม Execution Plan

2. ส่ง Parameters แยกต่างหาก:
   Parameters: ["admin' OR '1'='1"]

3. Database ใส่ Parameters เข้าไปในตำแหน่ง ? โดยไม่ Parse อีกครั้ง
   ผลลัพธ์: ค้นหา username ที่ตรงกับ "admin' OR '1'='1" ตรงๆ
   (ซึ่งไม่มีใน Database → Login ล้มเหลวอย่างถูกต้อง)

สรุป: Input ถูกปฏิบัติเป็น "ข้อมูล" ไม่ใช่ "คำสั่ง SQL"
```

### ตัวอย่าง Parameterized Queries ในภาษาต่างๆ

```php
<?php
// PHP - PDO Prepared Statements
$pdo = new PDO('mysql:host=localhost;dbname=myapp', $user, $pass);

// เตรียม Statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");

// Execute พร้อม Parameters
$stmt->execute([$username, $password]);
$user = $stmt->fetch();

// Named Parameters
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$stmt->execute([':username' => $username]);

// ป้องกัน Integer ด้วย Type Casting
$id = (int) $_GET['id'];  // บังคับให้เป็น Integer
$stmt = $pdo->prepare("SELECT * FROM products WHERE id = ?");
$stmt->execute([$id]);

// ตัวอย่าง INSERT
$stmt = $pdo->prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)");
$stmt->execute([$username, password_hash($password, PASSWORD_BCRYPT), $email]);
?>
```

```python
# Python - MySQLdb/MySQL-connector
import mysql.connector

conn = mysql.connector.connect(host='localhost', user='webapp', 
                                password='pass', database='myapp')
cursor = conn.cursor()

# Parameterized Query
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", 
               (username, password))
user = cursor.fetchone()

# Named Parameters  
cursor.execute("SELECT * FROM users WHERE username = %(username)s", 
               {'username': username})

# Python - psycopg2 (PostgreSQL)
import psycopg2
conn = psycopg2.connect("host=localhost dbname=myapp user=webapp")
cursor = conn.cursor()

cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Python - SQLAlchemy ORM (ปลอดภัยมาก)
from sqlalchemy.orm import Session
from models import User

session = Session()
user = session.query(User).filter(User.username == username).first()
```

```javascript
// Node.js - mysql2
const mysql = require('mysql2');
const pool = mysql.createPool({...});

// Parameterized Query (?)
pool.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) throw err;
    console.log(results);
});

// Node.js - pg (PostgreSQL)
const { Pool } = require('pg');
const pool = new Pool({...});

// PostgreSQL ใช้ $1, $2, ...
pool.query('SELECT * FROM users WHERE id = $1', [userId])
    .then(res => console.log(res.rows));

// Node.js - Knex.js (Query Builder - ปลอดภัย)
const knex = require('knex')({client: 'mysql'});

const users = await knex('users')
    .where('username', username)
    .andWhere('is_active', true)
    .select();
```

```java
// Java - JDBC Prepared Statement
String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement stmt = connection.prepareStatement(sql);
stmt.setString(1, username);
stmt.setString(2, password);
ResultSet rs = stmt.executeQuery();

// Java - Hibernate ORM (ปลอดภัย)
User user = session.createQuery("FROM User WHERE username = :username", User.class)
    .setParameter("username", username)
    .uniqueResult();
```

```csharp
// C# - ADO.NET
string sql = "SELECT * FROM users WHERE username = @username AND password = @password";
SqlCommand cmd = new SqlCommand(sql, connection);
cmd.Parameters.AddWithValue("@username", username);
cmd.Parameters.AddWithValue("@password", password);
SqlDataReader reader = cmd.ExecuteReader();

// C# - Entity Framework (ปลอดภัย)
var user = context.Users
    .Where(u => u.Username == username && u.Password == password)
    .FirstOrDefault();
```

---

## 8. ORM Security (Object-Relational Mapping)

### ORM ปลอดภัยอย่างไร?

```python
# Django ORM - ปลอดภัย
# ทุก QuerySet method ใช้ Parameterized Queries โดยอัตโนมัติ

# ปลอดภัย
from django.contrib.auth.models import User
User.objects.filter(username=request.GET.get('username'))

# ปลอดภัย
from myapp.models import Product
Product.objects.filter(price__gte=min_price, price__lte=max_price)

# ปลอดภัย - แต่ต้องระวัง extra() และ raw()
User.objects.extra(
    where=["username = %s"],  # ปลอดภัย (parameterized)
    params=[username]
)

# อันตราย - string formatting
User.objects.extra(
    where=[f"username = '{username}'"]
)

# อันตราย - raw() ที่ไม่ parameterized
User.objects.raw(f"SELECT * FROM users WHERE username = '{username}'")

# ปลอดภัย - raw() ที่ parameterized
User.objects.raw("SELECT * FROM users WHERE username = %s", [username])
```

```ruby
# Ruby on Rails ActiveRecord - ปลอดภัย

# ปลอดภัย
User.where(username: params[:username])
User.where("username = ?", params[:username])
User.where("username = :username", username: params[:username])

# อันตราย - string interpolation
User.where("username = '#{params[:username]}'")  # ช่องโหว่!

# อันตราย - order ที่ไม่ตรวจสอบ
User.order(params[:sort])  # ช่องโหว่! ถ้าไม่ Whitelist
# ควรใช้:
ALLOWED_SORT = %w[name email created_at].freeze
sort_column = ALLOWED_SORT.include?(params[:sort]) ? params[:sort] : 'name'
User.order(sort_column)
```

---

## 9. Input Validation กับ SQL Injection Prevention

### ความแตกต่างระหว่าง Validation และ Parameterization

```
Input Validation:
- ตรวจสอบว่า Input อยู่ในรูปแบบที่ถูกต้อง
- ตัวอย่าง: email ต้องเป็น email format, id ต้องเป็นตัวเลข
- จำเป็น แต่ไม่เพียงพอสำหรับป้องกัน SQLi ทั้งหมด
- ช่องโหว่: อาจ Bypass ได้ด้วย Encoding หรือ Edge Cases

Parameterized Queries:
- แยก Code และ Data อย่างสมบูรณ์
- Input ถูกปฏิบัติเป็นข้อมูลเสมอ ไม่ใช่ Code
- ป้องกัน SQLi ได้ในทุกกรณี
- ควรใช้เป็น Primary Defense เสมอ
```

### Input Validation ตัวอย่าง

```php
<?php
// Validate Integer
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($id === false || $id === null) {
    die("Invalid ID");
}

// Validate Email
$email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
if (!$email) {
    die("Invalid email");
}

// Validate และ Sanitize
$username = trim($_POST['username']);
$username = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');

// ตรวจสอบ Length
if (strlen($username) > 50) {
    die("Username too long");
}

// ตรวจสอบ Pattern ด้วย Regex
if (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
    die("Invalid username format");
}

// Whitelist สำหรับ ORDER BY (เพราะ Parameterized ไม่ทำงานกับ Column Names)
$allowed_sorts = ['name', 'price', 'created_at', 'rating'];
$sort = $_GET['sort'] ?? 'name';
if (!in_array($sort, $allowed_sorts)) {
    $sort = 'name';  // Default ถ้าไม่อยู่ใน Whitelist
}

$allowed_orders = ['ASC', 'DESC'];
$order = strtoupper($_GET['order'] ?? 'ASC');
if (!in_array($order, $allowed_orders)) {
    $order = 'ASC';
}

// ตอนนี้ปลอดภัยที่จะใส่ใน Query
$query = "SELECT * FROM products ORDER BY $sort $order";
?>
```

---

## 10. Stored Procedures และ SQL Injection

### Stored Procedures ไม่ได้ปลอดภัยเสมอไป

```sql
-- Stored Procedure ที่ปลอดภัย
CREATE PROCEDURE GetUserByUsername(@username NVARCHAR(50))
AS BEGIN
    SELECT * FROM users WHERE username = @username
END;
-- Parameters ถูก Parameterize โดยอัตโนมัติ ปลอดภัย!

-- Stored Procedure ที่มีช่องโหว่ (Dynamic SQL)
CREATE PROCEDURE SearchProducts(@search NVARCHAR(100))
AS BEGIN
    DECLARE @sql NVARCHAR(500)
    SET @sql = 'SELECT * FROM products WHERE name LIKE ''%' + @search + '%'''
    EXEC(@sql)  -- Dynamic SQL! อันตราย!
END;

-- เรียกใช้ด้วย Injection:
EXEC SearchProducts 'laptop%'' OR 1=1--'
-- SQL ที่สร้างขึ้น:
-- SELECT * FROM products WHERE name LIKE '%laptop%' OR 1=1--%'
-- → แสดงสินค้าทั้งหมด!

-- Stored Procedure ที่ใช้ Dynamic SQL แต่ปลอดภัย (MSSQL)
CREATE PROCEDURE SearchProductsSafe(@search NVARCHAR(100))
AS BEGIN
    DECLARE @sql NVARCHAR(500)
    SET @sql = 'SELECT * FROM products WHERE name LIKE @pattern'
    EXEC sp_executesql @sql, N'@pattern NVARCHAR(102)', @pattern = '%' + @search + '%'
END;
```

---

## 11. ORMs และ Raw Queries

### เมื่อต้องใช้ Raw SQL ใน ORM

```python
# Django - เมื่อต้องการ Complex Query
from django.db import connection

# วิธีที่ปลอดภัย:
with connection.cursor() as cursor:
    cursor.execute("""
        SELECT p.*, COUNT(o.id) as order_count
        FROM products p
        LEFT JOIN orders o ON p.id = o.product_id
        WHERE p.category_id = %s
        GROUP BY p.id
        HAVING COUNT(o.id) > %s
    """, [category_id, min_orders])
    rows = cursor.fetchall()

# วิธีที่ไม่ปลอดภัย:
with connection.cursor() as cursor:
    cursor.execute(f"""
        SELECT * FROM products 
        WHERE category_id = {category_id}  -- ช่องโหว่!
    """)
```

```javascript
// Sequelize ORM (Node.js) - Raw Query
const { QueryTypes } = require('sequelize');

// ปลอดภัย:
const products = await sequelize.query(
    'SELECT * FROM products WHERE category = :category',
    {
        replacements: { category: categoryName },
        type: QueryTypes.SELECT
    }
);

// อันตราย:
const products = await sequelize.query(
    `SELECT * FROM products WHERE category = '${categoryName}'`,  // ช่องโหว่!
    { type: QueryTypes.SELECT }
);
```

---

## 12. Second-Order SQL Injection (การโจมตีแบบล่าช้า)

### Second-Order คืออะไร?

```
Normal SQLi:
Input → Application → SQL Query (ทันที)

Second-Order SQLi:
Step 1: Input → Application → Database (เก็บข้อมูลที่มีอันตราย)
Step 2: ดึงข้อมูลกลับมา → Application → SQL Query ใหม่ (โจมตีเกิดขึ้นตอนนี้)
```

### ตัวอย่าง Second-Order

```php
<?php
// Step 1: Registration (มีการ Escape ถูกต้อง)
$username = mysqli_real_escape_string($conn, $_POST['username']);
$query = "INSERT INTO users (username) VALUES ('$username')";
// User ลงทะเบียนด้วย username: admin'--
// เก็บใน DB เป็น: admin'-- (escaped เป็น admin\'--)  
// แต่ใน DB จริงๆ เก็บเป็น: admin'--

// Step 2: Change Password (อ่านจาก DB และนำไปใช้)
$user = getCurrentUser();  // ดึงชื่อจาก Database: admin'--
$new_password = $_POST['new_password'];

// ไม่ได้ Escape username ที่อ่านจาก DB (เพราะคิดว่าปลอดภัยแล้ว)
$query = "UPDATE users SET password = '$new_password' 
          WHERE username = '$user'";
// สร้าง Query:
// UPDATE users SET password = 'newpass' WHERE username = 'admin'--'
// → แก้ Password ของ admin แทน!
?>
```

### ป้องกัน Second-Order

```php
// วิธีป้องกัน: ใช้ Parameterized Queries เสมอ
// แม้ข้อมูลที่อ่านมาจาก Database ก็ต้องใช้ Parameterized

$stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
$stmt->execute([$new_password, $current_user_id]);
// ใช้ user_id (integer) ไม่ใช่ username (string) เพื่อความปลอดภัยยิ่งขึ้น
```

---

## 13. Query Logging และ Monitoring

### บันทึก SQL Queries เพื่อตรวจจับการโจมตี

```php
<?php
// Wrapper Function สำหรับ Logging
function executeQuery($pdo, $sql, $params = []) {
    // Log the query
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'ip' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'],
        'sql' => $sql,
        'params' => json_encode($params)
    ];
    
    // เขียน Log
    file_put_contents('/var/log/app_queries.log', 
                       json_encode($logEntry) . "\n", 
                       FILE_APPEND);
    
    // Execute Query
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt;
}

// ใช้งาน
$stmt = executeQuery($pdo, 
    "SELECT * FROM users WHERE username = ?", 
    [$username]);
?>
```

### Detection Patterns ใน Logs

```bash
# ค้นหา Pattern ที่น่าสงสัยใน Logs
grep -i "union\|select\|drop\|insert\|update\|delete\|exec\|xp_" /var/log/apache2/access.log
grep -i "'\|--\|;\|or 1=1\|and 1=1" /var/log/apache2/access.log
grep -i "sleep(\|waitfor\|benchmark(" /var/log/apache2/access.log
```

---

## 14. Testing Methodology Preview

### วิธีทดสอบ SQL Injection เบื้องต้น

```
1. ระบุ Input Points ทั้งหมด
   - URL Parameters
   - Form Fields
   - Headers (User-Agent, Cookie, X-Forwarded-For)

2. ทดสอบ Basic Injection Characters:
   ' (single quote)
   " (double quote)
   ` (backtick - MySQL)
   ) (close parenthesis)
   -- (comment)
   # (comment - MySQL)
   /* */ (multi-line comment)

3. สังเกต Response:
   - Error message เปลี่ยนไปหรือไม่?
   - ข้อมูลที่แสดงเปลี่ยนไปหรือไม่?
   - Response time เปลี่ยนไปหรือไม่?
   - HTTP Status Code เปลี่ยนไปหรือไม่?

4. ยืนยัน Injection:
   - Boolean-based: ?id=1 AND 1=1 vs ?id=1 AND 1=2
   - Error-based: ดู Error Message
   - Time-based: ?id=1 AND SLEEP(5)
```

---

## 15. ตัวอย่าง Real-World Query Patterns

### E-commerce Website

```sql
-- Product Listing with Filters
SELECT p.*, c.name AS category_name, AVG(r.rating) AS avg_rating
FROM products p
JOIN categories c ON p.category_id = c.id
LEFT JOIN reviews r ON p.id = r.product_id
WHERE p.is_active = 1
  AND p.category_id = $category_id
  AND p.price BETWEEN $min_price AND $max_price
  AND p.name LIKE '%$search%'
GROUP BY p.id
ORDER BY $sort $order
LIMIT $per_page OFFSET $offset

-- Shopping Cart
SELECT ci.*, p.name, p.price
FROM cart_items ci
JOIN products p ON ci.product_id = p.id
WHERE ci.session_id = '$session_id'

-- Order History
SELECT o.*, SUM(oi.quantity * oi.price) AS total
FROM orders o
JOIN order_items oi ON o.id = oi.order_id
WHERE o.user_id = $user_id
GROUP BY o.id
ORDER BY o.created_at DESC
```

### Blog/CMS System

```sql
-- Get Post by Slug
SELECT p.*, u.username AS author, c.name AS category
FROM posts p
JOIN users u ON p.author_id = u.id
JOIN categories c ON p.category_id = c.id
WHERE p.slug = '$slug'

-- Search Posts
SELECT * FROM posts 
WHERE (title LIKE '%$query%' OR content LIKE '%$query%')
  AND status = 'published'
  AND category_id = $category

-- Admin Login
SELECT * FROM admins WHERE username = '$username' AND password = MD5('$password')
```

---

## 📝 แบบฝึกหัด

### Exercise 1: Query Analysis

วิเคราะห์ Query ต่อไปนี้และระบุ Injection Points:

```php
<?php
$search = $_GET['q'];
$category = $_GET['cat'];
$min_price = $_GET['min'];
$max_price = $_GET['max'];
$sort = $_GET['sort'];
$page = $_GET['page'];
$per_page = 20;
$offset = ($page - 1) * $per_page;

$query = "SELECT p.id, p.name, p.price, c.name AS cat_name
          FROM products p
          JOIN categories c ON p.category_id = c.id
          WHERE p.name LIKE '%$search%'
            AND p.category_id = $category
            AND p.price BETWEEN $min_price AND $max_price
          ORDER BY $sort
          LIMIT $per_page OFFSET $offset";
?>
```

**คำถาม:**
1. ระบุ Injection Points ทั้งหมด
2. ระบุว่าแต่ละ Point อยู่ใน Context ใด (String/Numeric/ORDER BY/LIMIT)
3. เขียนเวอร์ชันที่ปลอดภัยโดยใช้ Prepared Statements

### Exercise 2: Building a Secure Query

แปลง Query ที่มีช่องโหว่นี้ให้ปลอดภัย:

```php
// ช่องโหว่
$username = $_POST['username'];
$password = md5($_POST['password']);
$query = "SELECT id, username, email, role 
          FROM users 
          WHERE username = '$username' AND password = '$password'";
```

**ต้องการ:** เขียนใหม่โดยใช้ PDO Prepared Statement

### Exercise 3: Second-Order Analysis

อธิบายว่าโค้ดต่อไปนี้มีช่องโหว่ Second-Order SQL Injection อย่างไร:

```php
<?php
// ขั้นที่ 1: เปลี่ยนชื่อผู้ใช้
$new_username = mysqli_real_escape_string($conn, $_POST['new_username']);
mysqli_query($conn, "UPDATE users SET username = '$new_username' WHERE id = {$_SESSION['user_id']}");

// ขั้นที่ 2: ฟังก์ชันอื่นที่ใช้ username
function getUserPermissions($conn) {
    $user = mysqli_fetch_assoc(mysqli_query($conn, 
        "SELECT username FROM users WHERE id = {$_SESSION['user_id']}"));
    
    // ใช้ username จาก DB โดยไม่ Escape!
    $result = mysqli_query($conn, 
        "SELECT * FROM permissions WHERE username = '{$user['username']}'");
    return mysqli_fetch_all($result);
}
?>
```

---

## 🏆 Challenge

**Challenge:** เขียน Web Application ง่ายๆ (PHP/Python) ที่:
1. มี Login Form
2. มี Product Search
3. ใช้ Parameterized Queries ทั้งหมด
4. มี Input Validation
5. ไม่แสดง SQL Error Messages ต่อผู้ใช้
6. มี Logging สำหรับ Query ที่น่าสงสัย

---

## 🔑 สรุป

```
1. SQL Queries สร้างขึ้นจาก User Input → จุดอันตราย

2. String Concatenation ทำให้ Input กลายเป็นส่วนหนึ่งของ SQL Code

3. Parameterized Queries แยก Code และ Data → ปลอดภัย

4. Context ที่แตกต่างกัน (String, Numeric, ORDER BY) ต้องการ Technique ต่างกัน

5. ORM ช่วยลด Risk แต่ Raw Queries ยังอาจมีช่องโหว่

6. Second-Order SQLi เกิดเมื่อข้อมูลที่เก็บไว้ถูกนำไปใช้ใน Query ใหม่

7. Logging ช่วยตรวจจับและสอบสวนการโจมตี
```

---

## ➡️ ถัดไป

**Part 006: Your First SQL Injection**  
- ฝึกทำ SQL Injection จริงบน DVWA หรือ SQLi-labs
- การระบุ Injection Points
- Basic Payloads
- การยืนยันช่องโหว่

---

*Part 005 | SQL Injection Mastery Course | Security Education Only*
# Part 004: Web Application Architecture
## สถาปัตยกรรมเว็บแอปพลิเคชันและการโต้ตอบกับฐานข้อมูล

**ระดับ:** ⭐⭐ Easy  
**เวลาที่ใช้เรียน:** 3-4 ชั่วโมง  
**Prerequisites:** Part 001-003

---

## 🎯 วัตถุประสงค์การเรียนรู้

เมื่อเรียนจบบทนี้ ผู้เรียนจะสามารถ:
1. อธิบาย Request/Response Cycle ของ HTTP ได้
2. เข้าใจ Multi-tier Architecture ของ Web Application
3. ระบุจุดที่ User Input เข้าสู่ระบบ (Attack Surface)
4. เข้าใจวิธีที่ Web Application สร้าง SQL Queries
5. ใช้ Browser Developer Tools วิเคราะห์ Web Traffic

---

## 1. HTTP Protocol พื้นฐาน (HTTP Basics)

HTTP (HyperText Transfer Protocol) คือโปรโตคอลที่ Browser และ Web Server ใช้สื่อสารกัน

### HTTP Request Structure

```
GET /products?id=5&category=electronics HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: th-TH,th;q=0.9,en-US;q=0.8
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: session_id=abc123def456; user_pref=th
Referer: https://www.example.com/shop
```

**ส่วนประกอบของ HTTP Request:**
```
┌──────────────────────────────────────────────────────────────┐
│ Request Line: METHOD  PATH  HTTP_VERSION                      │
│ GET /products?id=5&category=electronics HTTP/1.1             │
├──────────────────────────────────────────────────────────────┤
│ Headers: Key: Value pairs                                     │
│ Host: www.example.com                                         │
│ User-Agent: Mozilla/5.0...                                    │
│ Cookie: session_id=abc123...                                  │
├──────────────────────────────────────────────────────────────┤
│ (Empty Line)                                                  │
├──────────────────────────────────────────────────────────────┤
│ Body: (ใน POST/PUT requests)                                  │
│ username=admin&password=secret123                             │
└──────────────────────────────────────────────────────────────┘
```

### HTTP Response Structure

```
HTTP/1.1 200 OK
Date: Thu, 15 Jan 2024 10:30:00 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Content-Length: 2048
Set-Cookie: session_id=newtoken123; Path=/; HttpOnly; Secure
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block

<!DOCTYPE html>
<html>
  <body>
    <h1>Product Details</h1>
    ...
  </body>
</html>
```

### HTTP Methods

```
GET     - ดึงข้อมูล (อ่าน)
POST    - ส่งข้อมูล (สร้าง)
PUT     - แก้ไขข้อมูลทั้งหมด
PATCH   - แก้ไขข้อมูลบางส่วน
DELETE  - ลบข้อมูล
HEAD    - เหมือน GET แต่ไม่ส่ง Body
OPTIONS - ดู Methods ที่รองรับ
```

### HTTP Status Codes ที่สำคัญ

```
200 OK              - สำเร็จ
201 Created         - สร้างข้อมูลสำเร็จ
301 Moved Permanently - Redirect ถาวร
302 Found           - Redirect ชั่วคราว
400 Bad Request     - Request ไม่ถูกต้อง
401 Unauthorized    - ยังไม่ได้ Login
403 Forbidden       - ไม่มีสิทธิ์
404 Not Found       - ไม่พบหน้า
405 Method Not Allowed - Method ไม่รองรับ
500 Internal Server Error - Server Error
503 Service Unavailable - Server ไม่พร้อม
```

---

## 2. Web Application Architecture Models

### 2.1 Traditional 3-Tier Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    3-Tier Architecture                        │
├──────────────────┬─────────────────┬────────────────────────┤
│  Presentation    │    Logic         │    Data                 │
│  Tier            │    Tier          │    Tier                 │
│                  │                  │                         │
│  ┌──────────┐   │  ┌───────────┐  │  ┌─────────────────┐   │
│  │ Browser  │   │  │  Web App  │  │  │    Database      │   │
│  │ HTML     │──▶│  │  PHP/     │──▶│  │    MySQL        │   │
│  │ CSS      │   │  │  Python/  │  │  │    PostgreSQL   │   │
│  │ JS       │◀──│  │  Node.js  │◀──│  │    MSSQL        │   │
│  └──────────┘   │  └───────────┘  │  └─────────────────┘   │
│                  │                  │                         │
│  Client-side     │  Server-side     │  Database               │
└──────────────────┴─────────────────┴────────────────────────┘
```

### 2.2 Modern Microservices Architecture

```
                        ┌─────────────┐
                        │  API Gateway │
                        │  (Load      │
                        │  Balancer)  │
                        └──────┬──────┘
                               │
              ┌────────────────┼─────────────────┐
              │                │                  │
    ┌─────────▼──────┐ ┌──────▼──────┐ ┌────────▼──────┐
    │ User Service   │ │Product Svc  │ │ Order Service │
    │ (Node.js)      │ │ (Python)    │ │ (Java/Spring) │
    └────────┬───────┘ └──────┬──────┘ └───────┬───────┘
             │                │                 │
    ┌────────▼──────┐ ┌──────▼──────┐ ┌───────▼───────┐
    │  MySQL DB     │ │ PostgreSQL  │ │  MongoDB       │
    └───────────────┘ └─────────────┘ └───────────────┘
```

### 2.3 LAMP Stack (Linux, Apache, MySQL, PHP)

นิยมมากในการโจมตีจริงเนื่องจากมีมาก:

```
Browser → Apache Web Server → PHP Application → MySQL Database
         (Port 80/443)       (/var/www/html/)   (localhost:3306)

ไฟล์ Configuration ที่สำคัญ:
/etc/apache2/apache2.conf  - Apache Config
/etc/apache2/sites-enabled/  - Virtual Hosts
/var/www/html/             - Web Root
/var/www/html/config.php   - Database Config (มักมี Password!)
/etc/mysql/my.cnf          - MySQL Config
```

---

## 3. ช่องทาง Input ของผู้ใช้ (User Input Channels)

ทุกช่องทางที่รับข้อมูลจากผู้ใช้คือจุดที่ต้องตรวจสอบสำหรับ SQL Injection:

### 3.1 URL Parameters (GET Parameters)

```
https://shop.example.com/product?id=5&sort=price&order=asc
                                  ^^^     ^^^^          ^^^
                                  Input1  Input2        Input3

ตัวอย่างโค้ดที่มีช่องโหว่ (PHP):
$id = $_GET['id'];
$query = "SELECT * FROM products WHERE id = $id";
// ↑ ไม่มีการตรวจสอบ id!
```

### 3.2 Form POST Data

```html
<!-- HTML Form -->
<form action="/login" method="POST">
    <input type="text" name="username" />
    <input type="password" name="password" />
    <input type="submit" value="Login" />
</form>
```

```
HTTP POST Request:
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=secret

โค้ดที่มีช่องโหว่:
$username = $_POST['username'];
$password = $_POST['password'];
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
```

### 3.3 HTTP Headers

```
User-Agent: Mozilla/5.0' OR 1=1--
Referer: http://evil.com/' UNION SELECT 1,2,3--
X-Forwarded-For: 127.0.0.1' AND SLEEP(5)--
Cookie: session=abc123; user_id=1 OR 1=1--
```

```php
// โค้ดที่มักมีช่องโหว่:
$user_agent = $_SERVER['HTTP_USER_AGENT'];
$referer = $_SERVER['HTTP_REFERER'];
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];

// บันทึก Log โดยไม่ตรวจสอบ
$query = "INSERT INTO access_logs (ip, user_agent, page) 
          VALUES ('$ip', '$user_agent', '$page')";
```

### 3.4 Cookies

```
Cookie: user_id=5; theme=dark; language=th

โค้ดที่มีช่องโหว่:
$user_id = $_COOKIE['user_id'];
$query = "SELECT * FROM users WHERE id = $user_id";
// Cookie สามารถแก้ไขได้ง่ายผ่าน Browser!
```

### 3.5 JSON API Requests

```json
POST /api/users/search
Content-Type: application/json

{
    "username": "admin",
    "filter": "role='admin' OR '1'='1"
}
```

```javascript
// Node.js ที่มีช่องโหว่:
const { username } = req.body;
const query = `SELECT * FROM users WHERE username = '${username}'`;
db.query(query, callback);
```

### 3.6 Search Functionality

```
GET /search?q=laptop&category=electronics&price_min=0&price_max=5000

โค้ดที่มีช่องโหว่:
$q = $_GET['q'];
$category = $_GET['category'];
$query = "SELECT * FROM products WHERE name LIKE '%$q%' 
          AND category = '$category'";
```

### 3.7 Order By / Sort Parameters

```
GET /products?sort=price&order=asc

โค้ดที่มีช่องโหว่:
$sort = $_GET['sort'];
$order = $_GET['order'];
$query = "SELECT * FROM products ORDER BY $sort $order";
// ORDER BY ไม่รองรับ Parameterized Queries!
```

---

## 4. PHP Application Flow

PHP เป็นภาษาที่นิยมมากสำหรับ Web Development และมักพบ SQL Injection:

### ตัวอย่าง Login System

```php
<?php
// config.php - Database Configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'webapp');
define('DB_PASS', 'dbpassword123');
define('DB_NAME', 'myapp');

// เชื่อมต่อ Database
$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}
?>

<?php
// login.php - ระบบ Login ที่มีช่องโหว่ (VULNERABLE - ใช้เพื่อศึกษาเท่านั้น)
session_start();
require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // รับ Input โดยไม่ตรวจสอบ
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // สร้าง Query โดยต่อ String (อันตราย!)
    $query = "SELECT id, username, role FROM users 
              WHERE username = '$username' 
              AND password = MD5('$password')";
    
    $result = mysqli_query($conn, $query);
    
    if (mysqli_num_rows($result) > 0) {
        $user = mysqli_fetch_assoc($result);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        header("Location: dashboard.php");
    } else {
        $error = "Invalid username or password";
    }
}
?>

<!-- HTML Form -->
<form method="POST" action="login.php">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
    <?php if (isset($error)) echo "<p>$error</p>"; ?>
</form>
```

### ตัวอย่าง Product Search

```php
<?php
// search.php - ระบบค้นหาที่มีช่องโหว่ (VULNERABLE)
require_once 'config.php';

$search = $_GET['q'];
$category = $_GET['category'];

// Query ที่มีช่องโหว่
$query = "SELECT id, name, price, description 
          FROM products 
          WHERE (name LIKE '%$search%' OR description LIKE '%$search%')
          AND category = '$category'
          AND is_active = 1";

$result = mysqli_query($conn, $query);

echo "<ul>";
while ($row = mysqli_fetch_assoc($result)) {
    echo "<li>" . htmlspecialchars($row['name']) . " - ฿" . $row['price'] . "</li>";
}
echo "</ul>";
?>
```

### ตัวอย่าง Product Detail

```php
<?php
// product.php - หน้าแสดงรายละเอียดสินค้า (VULNERABLE)
require_once 'config.php';

$id = $_GET['id'];

// Integer ที่ยังมีช่องโหว่ (ไม่มี intval())
$query = "SELECT * FROM products WHERE id = $id";

$result = mysqli_query($conn, $query);
$product = mysqli_fetch_assoc($result);

if ($product) {
    echo "<h1>" . htmlspecialchars($product['name']) . "</h1>";
    echo "<p>ราคา: ฿" . $product['price'] . "</p>";
    echo "<p>" . $product['description'] . "</p>";
} else {
    echo "ไม่พบสินค้า";
}
?>
```

---

## 5. Python (Flask/Django) Application

### Flask Application ที่มีช่องโหว่

```python
from flask import Flask, request, render_template, redirect, session
import mysql.connector

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# เชื่อมต่อ Database
db = mysql.connector.connect(
    host="localhost",
    user="webapp",
    password="dbpassword",
    database="myapp"
)

# Login - มีช่องโหว่ (VULNERABLE)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        cursor = db.cursor()
        # String concatenation - อันตราย!
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            session['user_id'] = user[0]
            return redirect('/dashboard')
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

# Search - มีช่องโหว่ (VULNERABLE)
@app.route('/search')
def search():
    query_param = request.args.get('q', '')
    
    cursor = db.cursor()
    sql = f"SELECT id, name, price FROM products WHERE name LIKE '%{query_param}%'"
    cursor.execute(sql)
    products = cursor.fetchall()
    
    return render_template('search.html', products=products)

# User Profile - มีช่องโหว่ (VULNERABLE)
@app.route('/user/<user_id>')
def user_profile(user_id):
    cursor = db.cursor()
    sql = f"SELECT username, email, created_at FROM users WHERE id = {user_id}"
    cursor.execute(sql)
    user = cursor.fetchone()
    
    return render_template('profile.html', user=user)
```

### Django ORM vs Raw SQL

```python
# Django ORM - ปลอดภัย (parameterized)
from django.contrib.auth.models import User

# ปลอดภัย - Django ORM handle escaping
users = User.objects.filter(username='admin')
users = User.objects.filter(username=request.GET.get('q'))

# ปลอดภัย - Parameterized Query
from django.db import connection
cursor = connection.cursor()
cursor.execute("SELECT * FROM users WHERE username = %s", [username])

# อันตราย - Raw SQL with string formatting
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")  # ช่องโหว่!

# อันตราย - extra() หรือ raw() ที่ไม่ระวัง
User.objects.extra(where=[f"username = '{username}'"])  # ช่องโหว่!
```

---

## 6. Node.js Application

### Express.js ที่มีช่องโหว่

```javascript
const express = require('express');
const mysql = require('mysql2');

const app = express();
const pool = mysql.createPool({
    host: 'localhost',
    user: 'webapp',
    password: 'dbpassword',
    database: 'myapp'
});

// GET - มีช่องโหว่ (VULNERABLE)
app.get('/product', (req, res) => {
    const productId = req.query.id;
    
    // String concatenation - อันตราย!
    const query = `SELECT * FROM products WHERE id = ${productId}`;
    
    pool.query(query, (err, results) => {
        if (err) {
            // Error message อาจเปิดเผยข้อมูล!
            return res.status(500).json({ error: err.message });
        }
        res.json(results);
    });
});

// POST Login - มีช่องโหว่ (VULNERABLE)
app.post('/login', express.json(), (req, res) => {
    const { username, password } = req.body;
    
    // Template literal - อันตราย!
    const query = `SELECT * FROM users 
                   WHERE username = '${username}' 
                   AND password = '${password}'`;
    
    pool.query(query, (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            req.session.userId = results[0].id;
            res.json({ success: true });
        } else {
            res.json({ success: false, message: 'Invalid credentials' });
        }
    });
});
```

---

## 7. HTTP Request Analysis ด้วย Browser Developer Tools

### การใช้ Chrome DevTools

```
1. เปิด Chrome DevTools: F12 หรือ Ctrl+Shift+I
2. ไปที่ Tab "Network"
3. ทำ Action บนเว็บ (Login, Search, ฯลฯ)
4. ดู Request ที่เกิดขึ้น

ข้อมูลที่ดูได้:
- Request Headers
- Response Headers
- Request Body (สำหรับ POST)
- Response Body
- Cookies
- Timing
```

### การ Intercept Request ด้วย Burp Suite

```
1. ตั้งค่า Browser ให้ใช้ Proxy: 127.0.0.1:8080
2. เปิด Burp Suite → Proxy → Intercept
3. กด "Intercept is on"
4. ทำ Action บนเว็บ
5. Request จะถูก Capture ใน Burp

สิ่งที่ทำได้ใน Burp:
- แก้ไข Request ก่อนส่ง
- ส่ง Request ไปที่ Repeater เพื่อทดสอบซ้ำ
- ส่งไปที่ Intruder เพื่อ Fuzzing
- ดู Response อย่างละเอียด
```

### Request ตัวอย่าง - Login Form

```
Raw HTTP Request (จาก Burp Suite):

POST /login HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Cookie: PHPSESSID=abc123def456789

username=admin&password=password123

การทดสอบ SQL Injection:
1. เปลี่ยน username เป็น: admin'
   → ถ้า Error → มีช่องโหว่!

2. ทดสอบ: admin' OR '1'='1'--
   → ถ้า Login สำเร็จ → Confirmed SQLi!
```

---

## 8. Session Management และ Cookies

### วิธีที่ Web Application ใช้ Sessions

```
1. User Login สำเร็จ
         ↓
2. Server สร้าง Session:
   $_SESSION['user_id'] = 5;
   $_SESSION['role'] = 'admin';
         ↓
3. Server ส่ง Session Cookie:
   Set-Cookie: PHPSESSID=a1b2c3d4e5f6; HttpOnly; Secure
         ↓
4. Browser เก็บ Cookie
         ↓
5. ทุก Request ถัดไป Browser ส่ง Cookie:
   Cookie: PHPSESSID=a1b2c3d4e5f6
         ↓
6. Server อ่าน Session จาก Cookie
```

### Cookie Attributes ที่สำคัญด้าน Security

```
Set-Cookie: session=abc123; 
    Path=/;           ← Cookie ใช้ได้กับทุก Path
    Domain=.example.com; ← ใช้ได้กับ Subdomains
    Secure;           ← ส่งผ่าน HTTPS เท่านั้น
    HttpOnly;         ← JavaScript ไม่สามารถอ่านได้ (ป้องกัน XSS)
    SameSite=Strict;  ← ป้องกัน CSRF
    Max-Age=3600;     ← หมดอายุใน 1 ชั่วโมง
```

### JWT (JSON Web Token)

```
JWT Structure:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9  ← Header (Base64)
.eyJ1c2VySWQiOjEsInJvbGUiOiJhZG1pbiJ9  ← Payload (Base64)
.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  ← Signature

Decoded Payload:
{
    "userId": 1,
    "role": "admin",
    "iat": 1516239022,
    "exp": 1516242622
}

หมายเหตุ: SQL Injection ที่ Database ที่เก็บ User Data
อาจทำให้ผู้โจมตีสร้าง JWT ได้เองถ้าได้ Secret Key
```

---

## 9. Web Application Firewall (WAF)

WAF คือ Security Layer ที่พยายามป้องกัน SQL Injection:

### วิธีทำงานของ WAF

```
Browser → Request → WAF → Web Server → Database
                     ↓
                 ตรวจสอบ:
                 - SQL Keywords (SELECT, UNION, DROP)
                 - Special Characters (', ", --)
                 - Pattern Matching (SQL Injection Patterns)
                     ↓
                 Block หรือ Pass?
```

### ตัวอย่าง WAF Rules

```
# ModSecurity Rules (Apache/Nginx WAF)
# Block SQL Injection attempts

SecRule ARGS "@detectSQLi" \
    "id:942100, \
    phase:2, \
    block, \
    log, \
    msg:'SQL Injection Attack Detected', \
    severity:'CRITICAL'"

# Block common SQLi patterns
SecRule ARGS "(?i:(union|select|insert|update|delete|drop|create|alter|exec|execute))" \
    "id:942200, \
    phase:2, \
    block"
```

### Common WAF Bypass Techniques (Preview)

```sql
-- Case Manipulation
SeLeCt * FrOm UsErS

-- Comment Injection
SEL/**/ECT * FR/**/OM users

-- URL Encoding
%53%45%4C%45%43%54 = SELECT

-- Double Encoding
%2527 = ' (double URL encoded)

-- Whitespace Alternatives
SELECT%09*%09FROM%09users  (Tab แทน Space)

-- หมายเหตุ: เนื้อหาเต็มเกี่ยวกับ WAF Bypass อยู่ใน Part 071-080
```

---

## 10. HTTPS และ TLS/SSL

### ความสำคัญต่อ SQL Injection

```
HTTP (ไม่เข้ารหัส):
Browser ─────────────────────────────── Server
         GET /login?user=admin&pass=123
         ↑ ดักฟังได้ง่ายผ่าน Network!

HTTPS (เข้ารหัสด้วย TLS):
Browser ─────────────────────────────── Server
         [TLS Encrypted Traffic]
         ↑ ดักฟังได้ยากกว่า แต่ SQL Injection ยังทำงานได้!
         
หมายเหตุ: HTTPS ป้องกัน Man-in-the-Middle แต่ไม่ได้ป้องกัน SQLi
          ผู้โจมตียังส่ง Payload ผ่าน HTTPS ได้โดยตรง
```

---

## 11. API Architecture (REST API)

### REST API ที่มีช่องโหว่

```javascript
// Node.js/Express REST API

// GET /api/products?id=5
app.get('/api/products', async (req, res) => {
    const id = req.query.id;
    
    // มีช่องโหว่!
    const result = await db.query(`SELECT * FROM products WHERE id = ${id}`);
    res.json(result.rows);
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    
    // มีช่องโหว่!
    const result = await db.query(
        `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`
    );
    
    if (result.rows.length > 0) {
        const token = generateJWT(result.rows[0]);
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// GET /api/users/:id
app.get('/api/users/:id', auth, async (req, res) => {
    const userId = req.params.id;
    
    // มีช่องโหว่!
    const result = await db.query(
        `SELECT id, username, email FROM users WHERE id = ${userId}`
    );
    res.json(result.rows[0]);
});
```

### การทดสอบ REST API ด้วย curl

```bash
# ทดสอบ GET Request
curl -v "http://api.example.com/products?id=1"

# ทดสอบ SQL Injection ใน GET
curl -v "http://api.example.com/products?id=1%20OR%201=1"
curl -v "http://api.example.com/products?id=1%20UNION%20SELECT%201,2,3--"

# ทดสอบ POST Request
curl -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"test"}' \
  http://api.example.com/auth/login

# ทดสอบ SQL Injection ใน POST Body
curl -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com'\''--","password":"anything"}' \
  http://api.example.com/auth/login
```

---

## 12. การทำความเข้าใจ Error Messages

Error Messages เป็นข้อมูลสำคัญสำหรับ SQL Injection:

### ตัวอย่าง Error Messages

```
MySQL Error:
You have an error in your SQL syntax; check the manual that corresponds 
to your MySQL server version for the right syntax to use near ''1'' at line 1

→ บอกว่า: ใช้ MySQL, มีช่องโหว่ที่ตำแหน่งที่ระบุ

PostgreSQL Error:
ERROR: unterminated quoted string at or near "'" LINE 1: ...WHERE username = '''
                                                             ^

→ บอกว่า: ใช้ PostgreSQL, มีช่องโหว่

MSSQL Error:
Unclosed quotation mark after the character string ' AND password='test'.
Server: Msg 105, Level 15, State 1, Line 1

→ บอกว่า: ใช้ MSSQL

Oracle Error:
ORA-00907: missing right parenthesis
ORA-00933: SQL command not properly ended

→ บอกว่า: ใช้ Oracle
```

### การปิด Error Messages (Best Practice)

```php
// PHP - ไม่แสดง Error Messages ต่อผู้ใช้
error_reporting(0);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/php_errors.log');

// หรือใน php.ini:
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
```

---

## 13. Content Types และ Encoding

### ประเภทของ Content-Type ที่มักพบ

```
application/x-www-form-urlencoded  ← HTML Form ปกติ
multipart/form-data                ← Form ที่มี File Upload
application/json                   ← REST API JSON
text/xml / application/xml         ← XML/SOAP
application/graphql                ← GraphQL
```

### URL Encoding

```
ตัวอักษรพิเศษที่ต้อง Encode ใน URL:
  '  → %27
  "  → %22
  <  → %3C
  >  → %3E
  (  → %28
  )  → %29
  ;  → %3B
  #  → %23
  &  → %26
  =  → %3D
  +  → %2B
  /  → %2F
  \  → %5C
  Space → %20 หรือ +
```

---

## 14. Proxying Traffic for Testing

### ตั้งค่า Burp Suite Proxy

```
1. Download และติดตั้ง Burp Suite Community Edition (Free)

2. ตั้งค่า Proxy Listener:
   - Burp → Proxy → Options → Proxy Listeners
   - 127.0.0.1:8080

3. ตั้งค่า Browser:
   Firefox → Settings → Network Settings
   → Manual proxy configuration
   → HTTP Proxy: 127.0.0.1 Port: 8080
   → ✓ Use this proxy server for all protocols

4. ติดตั้ง Burp CA Certificate:
   - Browse to: http://burp
   - Download CA Certificate
   - Import ใน Browser

5. เริ่ม Intercept:
   Proxy → Intercept → Turn on
```

---

## 📝 แบบฝึกหัด

### Exercise 1: HTTP Analysis

ใช้ Browser DevTools หรือ Burp Suite:

1. เปิด https://httpbin.org/get?test=hello
2. ดู Request Headers ทั้งหมด
3. ระบุ Cookie, User-Agent, Accept Headers
4. ลองเปลี่ยน User-Agent ผ่าน curl

```bash
# ส่ง Request ด้วย Custom Headers
curl -v \
  -H "User-Agent: TestAgent/1.0" \
  -H "X-Custom-Header: TestValue" \
  "https://httpbin.org/headers"
```

### Exercise 2: Form Analysis

1. สร้าง HTML Form ง่ายๆ
2. Submit Form และดู Network Traffic
3. ระบุว่า Data ถูกส่งอย่างไร (GET vs POST)
4. ลอง Modify Request ด้วย Burp Suite

### Exercise 3: API Testing

```bash
# ทดสอบ JSONPlaceholder API (Free testing API)
# GET Request
curl -v "https://jsonplaceholder.typicode.com/users/1"

# POST Request
curl -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"name": "Test User", "email": "test@example.com"}' \
  "https://jsonplaceholder.typicode.com/users"

# สังเกต Request/Response Headers
# วิเคราะห์โครงสร้างของ API
```

---

## 🏆 Challenge

**Challenge:** สร้าง Vulnerable Web Application ง่ายๆ:
1. สร้าง PHP หรือ Python Script ที่รับ GET Parameter
2. ใส่ Parameter ลงใน SQL Query โดยตรง
3. ทดสอบด้วยตัวเอง (บน Local Machine เท่านั้น!)
4. แก้ไขให้ปลอดภัยด้วย Parameterized Queries
5. ทดสอบอีกครั้งเพื่อยืนยันว่าปลอดภัยแล้ว

---

## 🔑 สรุป

```
1. HTTP Request ประกอบด้วย Method, Path, Headers, Body

2. User Input เข้าสู่ระบบผ่าน: URL Params, POST Body, Headers, Cookies

3. การ Debug ด้วย DevTools และ Burp Suite ช่วยให้เห็น Request/Response

4. Error Messages เปิดเผยข้อมูลสำคัญเกี่ยวกับ Database ที่ใช้

5. HTTPS ป้องกัน MITM แต่ไม่ได้ป้องกัน SQL Injection

6. WAF พยายามป้องกัน SQLi แต่สามารถ Bypass ได้ด้วยเทคนิคต่างๆ
```

---

## ➡️ ถัดไป

**Part 005: Understanding SQL Queries in Web Applications**
- เรียนรู้วิธีที่ Web Apps สร้าง SQL Queries
- วิเคราะห์ Query Construction Patterns
- เข้าใจเหตุผลที่ String Concatenation อันตราย
- เรียนรู้ Parameterization

---

*Part 004 | SQL Injection Mastery Course | Security Education Only*
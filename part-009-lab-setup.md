# Part 009: Lab Setup
## การตั้งค่า Lab Environment สำหรับการฝึกหัด SQL Injection

**ระดับ:** ⭐⭐ Easy  
**เวลาที่ใช้เรียน:** 3-5 ชั่วโมง (รวมการติดตั้ง)  
**Prerequisites:** ความรู้ Docker พื้นฐาน, Command Line

---

## 🎯 วัตถุประสงค์การเรียนรู้

เมื่อเรียนจบบทนี้ ผู้เรียนจะสามารถ:
1. ติดตั้ง Docker บน Linux/Windows/macOS
2. รัน DVWA, WebGoat, SQLi-labs, Mutillidae ผ่าน Docker
3. ตั้งค่า Burp Suite Proxy
4. ยืนยันว่า Lab ทำงานได้อย่างถูกต้อง
5. สร้าง Custom Vulnerable Application

---

## 1. ภาพรวม Lab Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Security Testing Lab                          │
│                                                                   │
│  ┌─────────────────┐    ┌───────────────────────────────────┐   │
│  │  Testing Machine │    │     Docker Host                   │   │
│  │                 │    │                                    │   │
│  │  Burp Suite     │    │  ┌──────────┐  ┌─────────────┐   │   │
│  │  Port 8080      │◄──►│  │   DVWA   │  │  WebGoat    │   │   │
│  │  (Proxy)        │    │  │ :8080    │  │  :8081      │   │   │
│  │                 │    │  └──────────┘  └─────────────┘   │   │
│  │  Browser        │    │                                    │   │
│  │  (Firefox)      │    │  ┌──────────┐  ┌─────────────┐   │   │
│  │                 │    │  │sqli-labs│  │  Mutillidae  │   │   │
│  └─────────────────┘    │  │ :8082    │  │  :8083      │   │   │
│                          │  └──────────┘  └─────────────┘   │   │
│                          └───────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. Docker Compose Configuration

```yaml
# docker-compose.yml
version: '3.8'

services:
  dvwa:
    image: vulnerables/web-dvwa
    container_name: dvwa
    ports:
      - "8080:80"
    restart: unless-stopped
    networks:
      - lab-network

  webgoat:
    image: webgoat/webgoat
    container_name: webgoat
    ports:
      - "8081:8080"
    restart: unless-stopped
    networks:
      - lab-network

  sqli-labs:
    image: acgpiano/sqli-labs
    container_name: sqli-labs
    ports:
      - "8082:80"
    restart: unless-stopped
    networks:
      - lab-network

  mutillidae:
    image: webpwnized/mutillidae
    container_name: mutillidae
    ports:
      - "8083:80"
    restart: unless-stopped
    networks:
      - lab-network

  mysql:
    image: mysql:8.0
    container_name: lab-mysql
    ports:
      - "3306:3306"
    environment:
      - MYSQL_ROOT_PASSWORD=rootpassword
      - MYSQL_DATABASE=vulnerable_app
      - MYSQL_USER=webapp
      - MYSQL_PASSWORD=webapppassword
    volumes:
      - mysql-data:/var/lib/mysql
      - ./sql/init.sql:/docker-entrypoint-initdb.d/init.sql
    restart: unless-stopped
    networks:
      - lab-network

  phpmyadmin:
    image: phpmyadmin:latest
    container_name: phpmyadmin
    ports:
      - "8090:80"
    environment:
      - PMA_HOST=mysql
      - PMA_USER=root
      - PMA_PASSWORD=rootpassword
    depends_on:
      - mysql
    restart: unless-stopped
    networks:
      - lab-network

networks:
  lab-network:
    driver: bridge

volumes:
  mysql-data:
```

---

## 3. SQL Init File

```sql
-- /opt/security-lab/sql/init.sql
CREATE DATABASE IF NOT EXISTS vulnerable_app;
USE vulnerable_app;

CREATE TABLE users (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(50) NOT NULL UNIQUE,
    password    VARCHAR(255) NOT NULL,
    email       VARCHAR(100),
    role        ENUM('admin', 'user', 'moderator') DEFAULT 'user',
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(200) NOT NULL,
    description TEXT,
    price       DECIMAL(10,2) NOT NULL,
    category    VARCHAR(50),
    stock       INT DEFAULT 0
);

CREATE TABLE secrets (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    secret_key  VARCHAR(100) NOT NULL,
    secret_value TEXT NOT NULL,
    owner       VARCHAR(50)
);

INSERT INTO users (username, password, email, role) VALUES
('admin', MD5('adminpassword'), 'admin@vulnerable.com', 'admin'),
('john', MD5('john123'), 'john@example.com', 'user'),
('alice', MD5('alice456'), 'alice@example.com', 'moderator'),
('bob', MD5('bob789'), 'bob@example.com', 'user');

INSERT INTO products (name, description, price, category, stock) VALUES
('Laptop Pro 15"', 'High performance laptop', 45000.00, 'Electronics', 50),
('Mechanical Keyboard', 'RGB Mechanical Keyboard', 3500.00, 'Electronics', 100),
('SQL Injection Book', 'Learn SQL Injection', 599.00, 'Books', 200);

INSERT INTO secrets (secret_key, secret_value, owner) VALUES
('api_key_1', 'sk-123456789abcdef', 'admin'),
('database_backup_password', 'BackupPass@2024!', 'admin');
```

---

## 4. DVWA Setup

```
URL: http://localhost:8080/DVWA/
Username: admin
Password: password

Setup:
1. เปิด: http://localhost:8080/DVWA/setup.php
2. คลิก "Create / Reset Database"
3. Login: admin / password
4. เลือก Security Level: Low (สำหรับเริ่มต้น)
```

### DVWA Features

```
├── SQL Injection               ← 🎯 เราจะใช้บทนี้มาก!
├── SQL Injection (Blind)       ← 🎯 Blind SQLi
├── Command Injection
├── CSRF
├── File Inclusion
├── File Upload
└── XSS (DOM/Reflected/Stored)
```

---

## 5. SQLi-labs Structure

```
Page 1 (Less 1-20):    GET Based Injection
├── Less 1:  GET - Error Based - Single Quotes
├── Less 2:  GET - Error Based - Integer
├── Less 5:  GET - Double Injection
├── Less 8:  GET - Blind - Boolean Based
├── Less 9:  GET - Blind - Time Based
...

Page 2 (Less 11-20):   POST Based Injection
Page 3 (Less 21-37):   Advanced Techniques
Page 4 (Less 38-53):   Stacked Queries
```

### ทดสอบ SQLi-labs Less 1

```
URL: http://localhost:8082/sqli-labs/Less-1/?id=1

1. ?id=1         → Login Name: Dumb
2. ?id=1'        → SQL Error
3. ?id=1'--      → Login Name: Dumb (ปกติ)
4. ?id=-1' UNION SELECT 1,version(),3--+ → MySQL Version
```

---

## 6. ติดตั้ง Burp Suite

```bash
# Download จาก PortSwigger
# https://portswigger.net/burp/communitydownload

# ตั้งค่า Proxy:
1. Proxy → Options → Proxy Listeners
   Interface: 127.0.0.1:8080

2. ตั้งค่า Firefox:
   HTTP Proxy: 127.0.0.1  Port: 8080

3. ติดตั้ง CA Certificate:
   - Browse ไปที่: http://burp
   - Download CA Certificate
   - Firefox → Settings → Certificates → Import
```

---

## 7. Custom Vulnerable PHP App

```php
<?php
// index.php - ⚠️ สำหรับการเรียนรู้เท่านั้น!

$conn = new mysqli('localhost', 'webapp', 'webapppassword', 'vulnerable_app');
?>
<!DOCTYPE html>
<html lang="th">
<head><title>Vulnerable Shop (Lab Only)</title></head>
<body>

<h1>Product Search</h1>
<form method="GET">
    <input type="text" name="search" placeholder="ค้นหาสินค้า...">
    <button type="submit">ค้นหา</button>
</form>

<?php
if (isset($_GET['search'])) {
    $search = $_GET['search'];
    
    // ⚠️ SQL Injection ตรงนี้! (จงใจ)
    $sql = "SELECT * FROM products WHERE name LIKE '%$search%'";
    $result = $conn->query($sql);
    
    if ($result === false) {
        echo "<p>Error: " . $conn->error . "</p>";
    } else {
        while ($row = $result->fetch_assoc()) {
            echo "<p>" . htmlspecialchars($row['name']) . " - ฿" . $row['price'] . "</p>";
        }
    }
}
?>

</body>
</html>
```

---

## 8. Lab Management

```bash
# Start Lab
cd /opt/security-lab
docker compose up -d

# Check Status
docker compose ps

# Stop Lab
docker compose down

# Verify services
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/DVWA/
# ควรได้ 200

# Test SQLMap
sqlmap -u "http://localhost:8080/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="security=low; PHPSESSID=YOUR_SESSION_ID" \
  --dbs --batch
```

---

## 🔑 สรุป

```
1. Docker ทำให้สร้าง Lab Environment ได้ง่ายและ Reproducible
2. DVWA, WebGoat, SQLi-labs, Mutillidae เป็น Labs ที่นิยม
3. Burp Suite เป็นเครื่องมือหลักสำหรับ Web Security Testing
4. CA Certificate ต้องติดตั้งเพื่อ Intercept HTTPS
```

---

*Part 009 | SQL Injection Mastery Course | Security Education Only*
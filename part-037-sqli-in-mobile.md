# Part 037: SQL Injection ใน Mobile Applications

## ภาพรวม

Mobile applications มักมี SQL Injection ใน SQLite databases หรือ backend APIs ที่แอปเชื่อมต่ออยู่

**ขั้นตอนที่ 556-575**

---

## 556. SQLite SQL Injection

```sql
-- SQLite ใช้ใน Android/iOS สำหรับ local storage

-- Basic syntax
SELECT * FROM users WHERE id=1;

-- SQLite system tables
SELECT * FROM sqlite_master;     -- ใช้แทน information_schema
SELECT name FROM sqlite_master WHERE type='table';
SELECT sql FROM sqlite_master WHERE name='users';

-- UNION injection
' UNION SELECT name,sql,3,4 FROM sqlite_master WHERE type='table'-- -

-- String functions
SUBSTR() -- แทน SUBSTRING
HEX()     -- hex encoding
RANDOM()  -- random number
```

---

## 557. Android SQLite Injection

```java
// Android SQLiteDatabase - VULNERABLE
public Cursor searchUser(String username) {
    String query = "SELECT * FROM users WHERE username='" + username + "'";
    return db.rawQuery(query, null);
}

// SECURE - rawQuery กับ parameters
public Cursor searchUserSecure(String username) {
    return db.rawQuery(
        "SELECT * FROM users WHERE username=?",
        new String[]{username}
    );
}

// SECURE - query() method
public Cursor searchUserSecure2(String username) {
    return db.query(
        "users",          // table
        null,             // columns (null = all)
        "username=?",     // selection
        new String[]{username}, // selectionArgs
        null, null, null
    );
}
```

---

## 558. iOS SQLite (Swift)

```swift
import SQLite3

// VULNERABLE
func searchUser(username: String) -> [User] {
    let query = "SELECT * FROM users WHERE username='\(username)'" // BAD!
    // ...
}

// SECURE - Prepared Statement
func searchUserSecure(username: String) -> [User] {
    var stmt: OpaquePointer?
    let query = "SELECT * FROM users WHERE username=?"
    
    guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK else {
        return []
    }
    
    sqlite3_bind_text(stmt, 1, username, -1, nil)
    
    var users: [User] = []
    while sqlite3_step(stmt) == SQLITE_ROW {
        // process row
    }
    
    sqlite3_finalize(stmt)
    return users
}
```

---

## 559. Mobile API Testing

```python
import requests

# intercept mobile traffic with Burp Suite
# Configure device proxy -> Burp proxy
# Install Burp CA certificate on device

# Test mobile API
base_url = "https://api.mobileapp.com/v1"
headers = {
    "Authorization": "Bearer MOBILE_TOKEN",
    "X-App-Version": "1.0.0",
    "X-Platform": "android",
    "Content-Type": "application/json"
}

# Test search endpoint
payloads = [
    "test'",
    "test' OR '1'='1",
    "test' UNION SELECT 1,2,3-- -",
]

for payload in payloads:
    r = requests.get(
        f"{base_url}/search",
        params={"q": payload},
        headers=headers
    )
    print(f"Payload: {payload[:30]} | Status: {r.status_code} | Len: {len(r.text)}")
```

---

## 560. APK Analysis

```bash
# Decompile APK เพื่อหา SQL queries

# jadx - Java decompiler
jadx app.apk -d output/

# หา SQL queries
grep -r "rawQuery" output/
grep -r "execSQL" output/
grep -r "SELECT" output/ --include="*.java"

# apktool - resources + Smali
apktool d app.apk
grep -r "SELECT" app/smali/ --include="*.smali"

# หา SQLite database ในไฟล์
find . -name "*.db" -o -name "*.sqlite"

# หา hardcoded credentials
grep -r "password" output/ --include="*.java"
grep -r "api_key" output/ --include="*.java"
grep -r "secret" output/ --include="*.java"
```

---

## 561. Mobile SQLite บน Android Device

```bash
# เข้าถึง SQLite DB ผ่าน ADB (rooted device)
adb shell
run-as com.example.app  # สำหรับ debug apps
cd /data/data/com.example.app/databases/
ls -la  # ดู database files

# Pull database
adb pull /data/data/com.example.app/databases/app.db ./

# เปิดด้วย sqlite3
sqlite3 app.db
.tables
SELECT * FROM users;
SELECT * FROM sqlite_master;
```

---

## สรุป

SQL Injection ใน Mobile:
- **SQLite** - Android/iOS local DB
- **Backend APIs** - test เหมือน web
- **APK Decompile** - หา vulnerable queries
- **ADB** - เข้าถึง device DB
- **Prepared Statements** - ป้องกันทั้ง Android และ iOS

---

*Part 037 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

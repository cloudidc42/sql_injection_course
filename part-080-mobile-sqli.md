# Part 080: SQL Injection ใน Mobile Apps

## ภาพรวม

Android และ iOS app บ่อยมี SQLite local DB และเชื่อม API ที่อาจมีช่องโหว่

**ขั้นตอนที่ 1271-1285**

---

## 1271. Android SQLite Injection

```java
// Android SQLiteDatabase - vulnerable code:

// VULNERABLE:
public Cursor searchContacts(String name) {
    SQLiteDatabase db = dbHelper.getReadableDatabase();
    String query = "SELECT * FROM contacts WHERE name = '" + name + "'";
    return db.rawQuery(query, null);
}

// SECURE: parameterized
public Cursor searchContactsSafe(String name) {
    SQLiteDatabase db = dbHelper.getReadableDatabase();
    return db.query(
        "contacts",        // table
        null,              // columns (all)
        "name = ?",        // selection
        new String[]{name}, // selectionArgs
        null, null, null
    );
}

// หรือ rawQuery แบบ parameterized:
return db.rawQuery("SELECT * FROM contacts WHERE name = ?", new String[]{name});
```

---

## 1272. Android Content Provider SQLi

```java
// Content Provider ที่ vulnerable:
// (อนุญาตให้ app อื่น query ได้ผ่าน ContentResolver)

@Override
public Cursor query(Uri uri, String[] projection, String selection,
                    String[] selectionArgs, String sortOrder) {
    SQLiteDatabase db = dbHelper.getReadableDatabase();
    
    // VULNERABLE: ไม่ validate projection/selection
    return db.query("users", projection, selection, selectionArgs, null, null, sortOrder);
}

// Attack จาก app อื่น (Android ADB):
// adb shell content query --uri content://com.target.provider/users \
//   --projection "name;DROP TABLE users--"

// หรือ ผ่าน ADB:
// adb shell am start -n com.target.app/.MainActivity \
//   --es 'query' "' OR '1'='1"
```

---

## 1273. iOS SQLite (Swift)

```swift
// iOS SQLite ด้วย FMDB framework

// VULNERABLE:
func searchUser(name: String) -> [User] {
    let query = "SELECT * FROM users WHERE name = '\(name)'"
    // String interpolation = SQL injection!
    return db.executeQuery(query, withArgumentsIn: [])
}

// SECURE:
func searchUserSafe(name: String) -> [User] {
    let query = "SELECT * FROM users WHERE name = ?"
    return db.executeQuery(query, withArgumentsIn: [name])
    // FMDB uses ? placeholder automatically
}

// CoreData (iOS ORM) - safer by default:
let request: NSFetchRequest<User> = User.fetchRequest()
request.predicate = NSPredicate(format: "name == %@", name)
// NSPredicate escapes strings automatically
```

---

## 1274. Mobile API และ SQLi

```python
# Mobile app เรียก API backend
# สามารถ intercept ด้วย Burp Suite

# Setup:
# 1. ติดตั้ง Burp CA ในโทรศัพท์
# 2. ตั้ง proxy: Settings > Wifi > Proxy
# 3. Trust certificate (Android 7+: ต้องเพิ่มใน user certs)

# หรือ ใช้ Frida bypass SSL pinning:
# frida -U -f com.target.app --codeshare "mbkum/frida-universal-sslpinning-bypass"

import requests

# หลังจาก intercept API call:
def test_mobile_api(api_url: str, token: str):
    payloads = [
        "' OR '1'='1",
        "1 UNION SELECT 1,2,3,4-- -",
        "1'; DROP TABLE orders--",
    ]
    
    for payload in payloads:
        r = requests.post(
            api_url,
            json={'search': payload, 'page': 1},
            headers={'Authorization': f'Bearer {token}'},
            timeout=5
        )
        print(f"Status: {r.status_code}, Size: {len(r.text)}")
```

---

## สรุป

Mobile SQL Injection:
- **Android SQLite** - rawQuery, db.query() parameterized
- **Content Providers** - validate projection/selection
- **iOS/Swift** - FMDB `?` placeholder, NSPredicate
- **API** - Burp intercept, Frida SSL bypass

---

*Part 080 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

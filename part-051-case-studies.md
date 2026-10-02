# Part 051: Real-World SQL Injection Case Studies

## ภาพรวม

วิเคราะห์เหตุการณ์ SQL Injection จริงในประวัติศาสตร์ความปลอดภัยไซเบอร์

**ขั้นตอนที่ 821-840**

---

## 821. Sony PlayStation Network (2011)

```
เหตุการณ์: 77 ล้าน accounts ถูก compromise
ช่องโหว่: SQL Injection ใน web application
ผลกระทบ: ข้อมูลส่วนตัว, credit card info

เทคนิคที่ใช้:
- Error-based SQL injection
- Union-based data extraction
- Credential dump

บทเรียน:
1. ไม่มี WAF หรือ IDS ที่เพียงพอ
2. Sensitive data ไม่ได้ encrypt
3. ไม่มี monitoring สำหรับ anomalous queries

Code ที่น่าจะเป็น:
$query = "SELECT * FROM users WHERE email = '" . $_POST['email'] . "'";

Fix:
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
$stmt->execute([$email]);
```

---

## 822. Heartland Payment Systems (2008)

```
เหตุการณ์: 130+ ล้าน credit cards ถูก steal
ช่องโหว่: SQL Injection ใน payment processing system
ผลกระทบ: ความเสียหาย ~140 ล้านดอลลาร์

เทคนิค:
1. SQL injection เข้า corporate network
2. ติดตั้ง malware บน payment servers
3. Sniff unencrypted card data

timeline:
- Dec 2007: initial breach
- Jan 2008: malware installed
- May 2008: discovered by Visa/Mastercard
- Jan 2009: publicly disclosed

บทเรียน:
- Network segmentation ไม่เพียงพอ
- P2PE (Point-to-Point Encryption) ควรใช้
- SQL injection = entry point สู่ deeper compromise
```

---

## 823. TalkTalk (2015)

```
เหตุการณ์: 157,000 customers' data stolen
ช่องโหว่: SQL Injection ใน legacy database
ผลกระทบ: ค่าปรับ 400,000 GBP (ICO)

ผู้โจมตี: ผู้ใช้อายุ 15-20 ปี

เทคนิค:
- Union-based SQL injection
- Direct data exfiltration
- ระบบเก่าไม่ได้ patch

บทเรียน:
- Legacy systems ต้องได้รับการ audit
- Input validation ขาดหายไป
- Penetration testing ไม่เพียงพอ
```

---

## 824. การวิเคราะห์ Pattern

```python
import re
from collections import Counter

def analyze_attack_pattern(log_lines: list) -> dict:
    patterns = {
        'union_select': 0,
        'blind_boolean': 0,
        'time_based': 0,
        'error_based': 0,
        'auth_bypass': 0,
        'comment_truncation': 0,
    }
    
    for line in log_lines:
        line_lower = line.lower()
        if 'union' in line_lower and 'select' in line_lower:
            patterns['union_select'] += 1
        if re.search(r"and\s+\d+=\d+|or\s+\d+=\d+", line_lower):
            patterns['blind_boolean'] += 1
        if 'sleep(' in line_lower or 'waitfor delay' in line_lower:
            patterns['time_based'] += 1
        if re.search(r"convert\(int|extractvalue|xmltype", line_lower):
            patterns['error_based'] += 1
        if re.search(r"'\s*(or|and)\s+'", line_lower):
            patterns['auth_bypass'] += 1
        if re.search(r"'--\s*$|'#\s*$", line_lower):
            patterns['comment_truncation'] += 1
    
    total = sum(patterns.values()) or 1
    percentages = {k: round(v/total*100, 1) for k, v in patterns.items()}
    
    return {
        'counts': patterns,
        'percentages': percentages,
        'most_common': max(patterns, key=patterns.get)
    }

sample_logs = [
    "GET /search?q=test' UNION SELECT 1,username,password FROM users-- HTTP/1.1",
    "GET /login?user=' OR '1'='1 HTTP/1.1",
    "GET /page?id=1' AND SLEEP(3)-- HTTP/1.1",
]

result = analyze_attack_pattern(sample_logs)
for k, v in result['counts'].items():
    if v > 0:
        print(f"  {k}: {v} ({result['percentages'][k]}%)")
```

---

## 825. Defense Lessons Learned

```
สิ่งที่ทุกเหตุการณ์มีเหมือนกัน:
1. Input validation ขาดหายหรือไม่เพียงพอ
2. ไม่ใช้ parameterized queries
3. ไม่มี WAF หรือ WAF configuration ไม่ดี
4. Log monitoring ไม่มีหรือไม่ถูก monitor
5. Network segmentation ไม่ดี

Checklist ป้องกัน:
[ ] ใช้ prepared statements ทุกจุด
[ ] Input validation ทุก entry point
[ ] WAF ที่ configured อย่างถูกต้อง
[ ] Database monitoring + alerting
[ ] Regular penetration testing
[ ] Encrypt sensitive data at rest
[ ] Principle of least privilege สำหรับ DB users
[ ] Regular security code reviews (SAST)
```

---

## สรุป

Case Studies:
- **Sony PSN** - 77M accounts, unencrypted data
- **Heartland** - 130M cards, malware via SQLi
- **TalkTalk** - legacy systems, teenager hackers
- **บทเรียน** - parameterized queries + monitoring
- **Pattern** - Union, blind, time-based เป็นเทคนิคหลัก

---

*Part 051 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

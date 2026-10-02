# Part 001: Introduction to SQL Injection
## ความรู้เบื้องต้นเกี่ยวกับ SQL Injection

**ระดับ:** ⭐ Beginner  
**เวลาที่ใช้เรียน:** 2-3 ชั่วโมง  
**Prerequisites:** ไม่มี

---

## 🎯 วัตถุประสงค์การเรียนรู้ (Learning Objectives)

เมื่อเรียนจบบทนี้ ผู้เรียนจะสามารถ:
1. อธิบายความหมายของ SQL Injection ได้
2. เข้าใจประวัติความเป็นมาของการโจมตีประเภทนี้
3. ระบุผลกระทบทางธุรกิจและเทคนิคของ SQL Injection
4. เข้าใจกฎหมายที่เกี่ยวข้องกับ Cybersecurity ในประเทศไทย
5. เข้าใจหลักจริยธรรมของ Ethical Hacker

---

## 1. SQL Injection คืออะไร? (What is SQL Injection?)

**SQL Injection (SQLi)** คือช่องโหว่ด้านความปลอดภัยของซอฟต์แวร์ประเภทหนึ่งที่เกิดขึ้นเมื่อแอปพลิเคชันไม่ได้ตรวจสอบหรือกรองข้อมูลที่รับมาจากผู้ใช้ (User Input) อย่างถูกต้อง ส่งผลให้ผู้ไม่หวังดีสามารถ "แทรกซึม" คำสั่ง SQL ที่เป็นอันตรายเข้าไปในคำสั่ง SQL ที่แอปพลิเคชันสร้างขึ้น

### คำอธิบายแบบง่าย (Simple Explanation)

ลองนึกภาพว่าคุณเป็นพนักงานห้องสมุดที่รับคำขอค้นหาหนังสือจากลูกค้า:

```
ลูกค้าปกติพูดว่า: "ฉันต้องการหนังสือเกี่ยวกับ Python"
คุณค้นหา: ค้นหาหนังสือที่มีคำว่า "Python"

แต่ลูกค้าที่ไม่หวังดีพูดว่า: "ฉันต้องการหนังสือเกี่ยวกับ Python" 
และแอบเพิ่มว่า: "...และให้ฉันดูทะเบียนพนักงานทุกคนด้วย"
คุณทำตามโดยไม่ตรวจสอบ: ค้นหา Python และแสดงทะเบียนพนักงานด้วย
```

ในโลกของ Web Application สิ่งนี้เกิดขึ้นผ่านช่องทาง Input ต่างๆ เช่น:
- **Login forms** (ช่องกรอก Username/Password)
- **Search boxes** (ช่องค้นหา)
- **URL parameters** (พารามิเตอร์ใน URL)
- **HTTP headers** (ส่วนหัวของ HTTP request)
- **Cookies** (ข้อมูล Cookie)

### ตัวอย่างแรก (First Example)

สมมติว่ามีเว็บไซต์ที่มีระบบ Login แบบนี้:

```php
<?php
// โค้ด PHP ที่มีช่องโหว่ (Vulnerable Code)
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($conn, $query);

if (mysqli_num_rows($result) > 0) {
    echo "Login สำเร็จ!";
} else {
    echo "Username หรือ Password ไม่ถูกต้อง";
}
?>
```

**การ Login ปกติ:**
```
Username: admin
Password: secretpassword123

SQL ที่สร้างขึ้น:
SELECT * FROM users WHERE username = 'admin' AND password = 'secretpassword123'
```

**การโจมตีด้วย SQL Injection:**
```
Username: admin' --
Password: anything

SQL ที่สร้างขึ้น:
SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'
```

> `--` คือ Comment ใน SQL ทำให้ส่วนที่ตรวจสอบ Password ถูกยกเลิกไป!

---

## 2. ประวัติความเป็นมา (History of SQL Injection)

### Timeline ของ SQL Injection

```
1998 - ปีแห่งการค้นพบ
├── Jeff Forristal (Rain Forest Puppy) เผยแพร่บทความ
│   "NT Web Technology Vulnerabilities" ใน Phrack Magazine
├── บทความนี้อธิบาย SQL Injection เป็นครั้งแรกอย่างเป็นทางการ
└── ในความเป็นจริง ช่องโหว่นี้มีมานานก่อนหน้านี้

2000-2005 - ยุคแพร่กระจาย
├── SQL Injection กลายเป็น Attack Vector ที่พบบ่อยที่สุด
├── เครื่องมือ Automated เริ่มถูกพัฒนา
└── เหตุการณ์ใหญ่เริ่มปรากฎในข่าว

2007 - การโจมตี Monster.com
├── ขโมยข้อมูลส่วนตัวของผู้ใช้กว่า 1.3 ล้านคน
└── ถือเป็นการโจมตีที่สร้างความเสียหายมากที่สุดในยุคนั้น

2008 - Heartland Payment Systems
├── ขโมยข้อมูลบัตรเครดิตกว่า 130 ล้านหมายเลข
├── ความเสียหายมูลค่ากว่า 140 ล้านดอลลาร์สหรัฐ
└── ยังคงเป็นหนึ่งในการโจมตีที่ใหญ่ที่สุดในประวัติศาสตร์

2009 - RockYou Breach
├── ขโมยข้อมูล Password ของผู้ใช้กว่า 32 ล้านคน
├── Password ถูกเก็บเป็น Plain Text!
└── Password list นี้ยังถูกใช้ในการโจมตี Dictionary Attack จนถึงปัจจุบัน

2011 - LulzSec & Anonymous
├── กลุ่ม Hacktivists ใช้ SQL Injection โจมตีหลายองค์กร
├── FBI, CIA, Sony Pictures, Nintendo ถูกโจมตี
└── เหตุการณ์นี้ทำให้ Security Community ตื่นตัวมากขึ้น

2012 - LinkedIn Breach
├── ขโมย Password Hash กว่า 6.5 ล้านรายการ
└── ใช้ MD5 ที่ไม่ Salted ทำให้ Crack ได้ง่าย

2013 - Adobe Systems
├── ขโมยข้อมูลลูกค้ากว่า 153 ล้านคน
└── รวมถึง Source Code ของ Adobe Acrobat, ColdFusion

2014-2020 - ยุค Modern SQL Injection
├── SQLMap ได้รับการพัฒนาอย่างต่อเนื่อง
├── Bug Bounty Programs เริ่มได้รับความนิยม
└── OWASP จัดอันดับ Injection เป็น #1 อยู่นาน

2021 - OWASP Top 10 ปรับเปลี่ยน
├── Injection (รวม SQLi) ยังอยู่ใน Top 3
└── A03:2021 - Injection

ปัจจุบัน
└── SQL Injection ยังคงเป็นหนึ่งในภัยคุกคามที่พบมากที่สุด
```

### บทเรียนที่ได้จากประวัติ

💡 **Insight:** แม้ว่า SQL Injection จะถูกค้นพบมาเกือบ 30 ปีแล้ว แต่ยังคงพบในระบบจำนวนมาก สาเหตุหลักคือ:
1. ขาดความรู้ด้าน Secure Coding
2. การเร่งรีบพัฒนาซอฟต์แวร์
3. Legacy code ที่ไม่ได้รับการอัปเดต
4. ขาดการทดสอบความปลอดภัย

---

## 3. ผลกระทบของ SQL Injection (Impact of SQL Injection)

### 3.1 ผลกระทบทางเทคนิค (Technical Impact)

**การขโมยข้อมูล (Data Theft)**
```
ผู้โจมตีสามารถ:
- ดึงข้อมูลผู้ใช้ทั้งหมด (Username, Password, Email)
- อ่านข้อมูลบัตรเครดิต
- ขโมยข้อมูลความลับทางธุรกิจ
- ดึง Source Code ของแอปพลิเคชัน
- อ่านไฟล์ในระบบ (ถ้าได้รับสิทธิ์)
```

**การแก้ไขข้อมูล (Data Manipulation)**
```
ผู้โจมตีสามารถ:
- แก้ไข, ลบ, หรือเพิ่มข้อมูลในฐานข้อมูล
- สร้าง Admin Account
- เปลี่ยน Password ของผู้ใช้
- แก้ไขราคาสินค้าหรือข้อมูลการเงิน
```

**การควบคุมระบบ (System Control)**
```
ในกรณีที่รุนแรงที่สุด ผู้โจมตีสามารถ:
- รันคำสั่ง OS ผ่านฐานข้อมูล
- สร้าง Backdoor ในระบบ
- เข้าถึง Network อื่นที่อยู่เบื้องหลัง
- ทำให้ระบบหยุดทำงาน (DoS)
```

### 3.2 ผลกระทบทางธุรกิจ (Business Impact)

```
┌─────────────────────────────────────────────────────────────┐
│                    ผลกระทบทางธุรกิจ                          │
├─────────────────┬───────────────────────────────────────────┤
│ ด้านการเงิน     │ ค่าปรับจาก Regulatory (GDPR, PDPA)       │
│                 │ ค่าใช้จ่ายในการแก้ไขระบบ                  │
│                 │ ค่าชดเชยให้ลูกค้า                         │
│                 │ รายได้ที่สูญเสียไป                         │
├─────────────────┼───────────────────────────────────────────┤
│ ด้านชื่อเสียง   │ ลูกค้าขาดความเชื่อมั่น                    │
│                 │ ข่าวเชิงลบในสื่อ                          │
│                 │ ราคาหุ้นลดลง (บริษัทจดทะเบียน)             │
│                 │ สูญเสียคู่ค้าทางธุรกิจ                     │
├─────────────────┼───────────────────────────────────────────┤
│ ด้านกฎหมาย     │ ถูกฟ้องร้องจากลูกค้าที่ได้รับผลกระทบ      │
│                 │ การสอบสวนจากหน่วยงานรัฐบาล               │
│                 │ ต้องจ้างทนายความเพื่อแก้ต่าง              │
└─────────────────┴───────────────────────────────────────────┘
```

### 3.3 Case Study: ความเสียหายจริงในไทย

หลายองค์กรในประเทศไทยเคยตกเป็นเหยื่อของ SQL Injection:

```
ตัวอย่างที่ 1: เว็บไซต์ E-commerce (ปกปิดชื่อ)
- ข้อมูลลูกค้ากว่า 200,000 รายการถูกขโมย
- รวมถึงข้อมูลบัตรเครดิตและที่อยู่
- บริษัทต้องจ่ายค่าปรับและค่าชดเชยหลายสิบล้านบาท

ตัวอย่างที่ 2: ระบบสมาชิกรัฐบาล (ปกปิดชื่อ)
- ข้อมูลบัตรประชาชนและข้อมูลส่วนตัวรั่วไหล
- ส่งผลต่อความเชื่อมั่นของประชาชนต่อระบบดิจิทัลภาครัฐ
```

---

## 4. กฎหมายที่เกี่ยวข้อง (Legal Aspects)

### 4.1 กฎหมายไทย (Thai Law)

**พระราชบัญญัติว่าด้วยการกระทำความผิดเกี่ยวกับคอมพิวเตอร์ พ.ศ. 2550 (แก้ไขเพิ่มเติม พ.ศ. 2560)**

```
มาตรา 5 - การเข้าถึงระบบโดยไม่ได้รับอนุญาต
โทษ: จำคุกไม่เกิน 6 เดือน หรือปรับไม่เกิน 10,000 บาท หรือทั้งจำทั้งปรับ

มาตรา 6 - การดักรับข้อมูล
โทษ: จำคุกไม่เกิน 2 ปี หรือปรับไม่เกิน 40,000 บาท หรือทั้งจำทั้งปรับ

มาตรา 7 - การเข้าถึงข้อมูลโดยมิชอบ
โทษ: จำคุกไม่เกิน 2 ปี หรือปรับไม่เกิน 40,000 บาท หรือทั้งจำทั้งปรับ

มาตรา 9 - การทำให้ข้อมูลเสียหาย
โทษ: จำคุกไม่เกิน 5 ปี หรือปรับไม่เกิน 100,000 บาท หรือทั้งจำทั้งปรับ

มาตรา 10 - การรบกวนระบบ
โทษ: จำคุกไม่เกิน 5 ปี หรือปรับไม่เกิน 100,000 บาท หรือทั้งจำทั้งปรับ
```

**พระราชบัญญัติคุ้มครองข้อมูลส่วนบุคคล (PDPA) พ.ศ. 2562**

```
- บังคับใช้เต็มรูปแบบตั้งแต่ปี 2565
- ผู้ควบคุมข้อมูลมีหน้าที่ปกป้องข้อมูลส่วนบุคคล
- โทษทางปกครอง: ปรับสูงสุด 5,000,000 บาท ต่อการกระทำผิดแต่ละครั้ง
- โทษทางอาญา: จำคุกไม่เกิน 1 ปี หรือปรับไม่เกิน 1,000,000 บาท
```

### 4.2 กฎหมายต่างประเทศ (International Laws)

```
GDPR (EU General Data Protection Regulation)
- ค่าปรับสูงสุด €20 ล้าน หรือ 4% ของรายได้ทั่วโลก (แล้วแต่อย่างใดสูงกว่า)

CFAA (Computer Fraud and Abuse Act - USA)
- โทษจำคุกสูงสุด 10-20 ปี ขึ้นอยู่กับความรุนแรง

Computer Misuse Act 1990 (UK)
- โทษจำคุกสูงสุด 10 ปี

Cybercrime Act (Australia)
- โทษจำคุกสูงสุด 10 ปี
```

### 4.3 การทำ Ethical Hacking อย่างถูกกฎหมาย

✅ **สิ่งที่ถูกกฎหมาย:**
```
1. ทดสอบระบบที่ตัวเองเป็นเจ้าของ
2. ทดสอบระบบที่ได้รับอนุญาตเป็นลายลักษณ์อักษร (Written Authorization)
3. ทดสอบใน Lab Environment ที่สร้างขึ้นสำหรับฝึกหัด
4. เข้าร่วม Bug Bounty Programs ที่ถูกกฎหมาย
5. ทำ Penetration Testing ตามสัญญาว่าจ้าง
```

❌ **สิ่งที่ผิดกฎหมาย:**
```
1. ทดสอบระบบของผู้อื่นโดยไม่ได้รับอนุญาต
2. ขโมยข้อมูลแม้จะมีเจตนาดี
3. เปิดเผยข้อมูลที่ขโมยมาต่อสาธารณะ
4. Selling vulnerabilities ที่ค้นพบจากการโจมตีผิดกฎหมาย
```

---

## 5. OWASP และ SQL Injection (OWASP & SQL Injection)

### OWASP Top 10 คืออะไร?

**OWASP (Open Web Application Security Project)** คือองค์กรไม่แสวงหากำไรที่มุ่งเน้นการพัฒนาความปลอดภัยของซอฟต์แวร์ OWASP Top 10 คือรายการช่องโหว่ที่พบบ่อยและอันตรายที่สุด 10 อันดับ

### OWASP Top 10 ล่าสุด (2021)

```
A01: Broken Access Control         ← ขึ้นมาที่ #1
A02: Cryptographic Failures        ← #2
A03: Injection (รวม SQL Injection) ← ยังอยู่ใน Top 3
A04: Insecure Design              ← เพิ่งเข้ามาใหม่
A05: Security Misconfiguration    ← #5
A06: Vulnerable Components        ← #6
A07: Identity & Authentication    ← #7
A08: Software & Data Integrity    ← #8
A09: Security Logging Failures    ← #9
A10: Server-Side Request Forgery  ← เพิ่งเข้ามาใหม่
```

### ทำไม Injection ยังคงอยู่ใน Top 10?

```
สาเหตุหลัก:
1. Prevalence - ยังพบบ่อยมากในระบบต่างๆ
2. Severity - ผลกระทบที่รุนแรงเมื่อถูกโจมตีสำเร็จ
3. Legacy Code - โค้ดเก่าที่ยังไม่ได้รับการปรับปรุง
4. Third-party Libraries - Libraries ที่ยังมีช่องโหว่
5. Lack of Awareness - ขาดความรู้ในหมู่นักพัฒนา
```

---

## 6. ประเภทของข้อมูลที่ตกเป็นเป้าหมาย (Target Data Types)

### ข้อมูลที่มักถูกโจมตี

```
┌──────────────────────────────────────────────────────────────┐
│                    ข้อมูลเป้าหมาย                             │
├──────────────────────┬───────────────────────────────────────┤
│ ข้อมูลส่วนตัว        │ ชื่อ, ที่อยู่, เบอร์โทร, อีเมล      │
│ (Personal Data)      │ เลขบัตรประชาชน, วันเกิด             │
├──────────────────────┼───────────────────────────────────────┤
│ ข้อมูลการเงิน        │ บัตรเครดิต, บัญชีธนาคาร             │
│ (Financial Data)     │ ประวัติการทำธุรกรรม                  │
├──────────────────────┼───────────────────────────────────────┤
│ Credentials          │ Username, Password (Hashed/Plain)    │
│                      │ Security Questions, Session Tokens   │
├──────────────────────┼───────────────────────────────────────┤
│ ข้อมูลองค์กร         │ ข้อมูลลับทางธุรกิจ, แผนงาน          │
│ (Business Data)      │ ข้อมูลลูกค้า, สัญญา                 │
├──────────────────────┼───────────────────────────────────────┤
│ ข้อมูลระบบ          │ Configuration, API Keys              │
│ (System Data)        │ Internal Network Information          │
└──────────────────────┴───────────────────────────────────────┘
```

---

## 7. ตัวอย่างการโจมตีในชีวิตจริง (Real-World Attack Examples)

### ตัวอย่างที่ 1: Authentication Bypass

**Scenario:** เว็บไซต์ขายสินค้า Online มีหน้า Login

```php
// Vulnerable Code
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
```

**Payload ที่ใช้โจมตี:**
```
Username: admin'--
Password: (ใส่อะไรก็ได้)

SQL ที่ได้:
SELECT * FROM users WHERE username='admin'--' AND password='anything'

ผล: Login สำเร็จโดยไม่ต้องรู้ Password!
```

### ตัวอย่างที่ 2: Data Extraction

**Scenario:** เว็บไซต์มีหน้าค้นหาสินค้า

```
URL ปกติ: /products?id=1
SQL ที่สร้าง: SELECT * FROM products WHERE id=1

URL ที่โจมตี: /products?id=1 UNION SELECT username,password FROM users--
SQL ที่สร้าง: SELECT * FROM products WHERE id=1 
              UNION SELECT username,password FROM users--
              
ผล: แสดงข้อมูล Username และ Password ของผู้ใช้ทั้งหมด!
```

### ตัวอย่างที่ 3: Database Destruction

```
Input ที่ใช้โจมตี: 1; DROP TABLE users; --

SQL ที่สร้าง: 
SELECT * FROM products WHERE id=1; DROP TABLE users; --

ผล: ตาราง users ถูกลบออกจากฐานข้อมูล!
```

---

## 8. วิธีการทำงานของ SQL Injection (How SQL Injection Works)

### กระบวนการโดยละเอียด

```
┌─────────────────────────────────────────────────────────────┐
│              กระบวนการ SQL Injection                          │
└─────────────────────────────────────────────────────────────┘

Step 1: ผู้ใช้ส่ง Input ผ่าน Web Form
        ┌─────────┐
        │ Browser │ ─── Input: admin' OR '1'='1
        └────┬────┘
             │ HTTP Request
             ▼

Step 2: Web Server รับ Request
        ┌─────────────┐
        │ Web Server  │ ─── รับ Input โดยไม่ตรวจสอบ
        └──────┬──────┘
               │
               ▼

Step 3: Application สร้าง SQL Query
        ┌──────────────────┐
        │ Application Code │ ─── สร้าง SQL โดยรวม Input
        └────────┬─────────┘
                 │ SQL: SELECT * FROM users WHERE username='admin' OR '1'='1'
                 ▼

Step 4: Database รัน Query ที่ถูกแทรก
        ┌──────────────┐
        │   Database   │ ─── '1'='1' เป็นจริงเสมอ → คืนค่าทุก Row
        └──────┬───────┘
               │
               ▼

Step 5: Application ส่งผลลัพธ์กลับ
        ┌─────────┐
        │ Browser │ ←── ผู้โจมตี Login สำเร็จ!
        └─────────┘
```

---

## 9. ทำไมนักพัฒนาถึงยังสร้าง SQL Injection (Why Developers Still Create SQLi)

### สาเหตุที่พบบ่อย

**1. ขาดความรู้ (Lack of Knowledge)**
```python
# นักพัฒนาใหม่มักเขียนแบบนี้:
username = request.form['username']
query = f"SELECT * FROM users WHERE username = '{username}'"

# โดยไม่รู้ว่านี่คือช่องโหว่ที่อันตราย
```

**2. ใช้ String Concatenation**
```javascript
// ในหลายภาษา การต่อ String ดูง่ายและตรงไปตรงมา
let query = "SELECT * FROM users WHERE id = " + userId;
// ผู้พัฒนาอาจไม่นึกถึงผลกระทบด้านความปลอดภัย
```

**3. ความรีบร้อน (Time Pressure)**
```
- Deadline โครงการที่กดดัน
- ไม่มีเวลาทำ Security Review
- "แก้ก่อน, ปรับทีหลัง" ซึ่งมักไม่เกิดขึ้น
```

**4. Legacy Code**
```
- โค้ดเก่าที่เขียนมาหลายปี
- ไม่มีใครกล้าแตะต้องเพราะกลัวพัง
- ขาดการ Maintain อย่างต่อเนื่อง
```

**5. ไม่มี Security Testing**
```
- ไม่มี Penetration Testing ก่อน Deploy
- ไม่มี Code Review ด้าน Security
- ไม่ใช้ SAST/DAST Tools
```

---

## 10. แนวคิดการป้องกันเบื้องต้น (Basic Prevention Concepts)

> **หมายเหตุ:** เนื้อหาการป้องกันอย่างละเอียดอยู่ใน Part 091-100

### แนวทางป้องกันหลัก

**1. Parameterized Queries / Prepared Statements**
```php
// แบบที่ถูกต้อง - ใช้ Prepared Statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);
```

**2. Input Validation**
```python
import re

def is_valid_username(username):
    # อนุญาตเฉพาะตัวอักษรและตัวเลข
    return re.match(r'^[a-zA-Z0-9_]{3,20}$', username) is not None
```

**3. Principle of Least Privilege**
```sql
-- สร้าง Database User ที่มีสิทธิ์จำกัด
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT, INSERT, UPDATE ON mydb.* TO 'webapp'@'localhost';
-- ไม่ให้ DROP, CREATE, ฯลฯ
```

---

## 11. หลักจริยธรรมของ Ethical Hacker (Ethical Hacker Ethics)

### Code of Ethics

```
1. ขออนุญาตก่อนเสมอ (Always Get Permission First)
   - ต้องมีหนังสืออนุญาตเป็นลายลักษณ์อักษร
   - กำหนด Scope ให้ชัดเจน
   - รู้ว่าระบบใดที่ได้รับอนุญาตให้ทดสอบ

2. รักษาความลับ (Maintain Confidentiality)
   - ไม่เปิดเผยข้อมูลที่ค้นพบโดยไม่ได้รับอนุญาต
   - เก็บรักษาผลการทดสอบอย่างปลอดภัย

3. ไม่ทำลายระบบ (Do Not Damage Systems)
   - หลีกเลี่ยงการกระทำที่อาจทำให้ระบบหยุดทำงาน
   - Backup ข้อมูลก่อนทดสอบ

4. รายงานช่องโหว่อย่างรับผิดชอบ (Responsible Disclosure)
   - แจ้งช่องโหว่ให้เจ้าของระบบทราบก่อน
   - ให้เวลาแก้ไขก่อนเปิดเผยต่อสาธารณะ

5. พัฒนาตัวเองอย่างต่อเนื่อง (Continuous Learning)
   - ติดตามข่าวสารด้าน Security
   - เรียนรู้เทคนิคใหม่ๆ
   - ฝึกฝนในสภาพแวดล้อมที่ถูกกฎหมาย
```

---

## 12. อาชีพด้าน Security (Career in Security)

### เส้นทางอาชีพที่เกี่ยวข้อง

```
Penetration Tester (Pentester)
├── Application Security Tester
│   ├── Web Application Pentester
│   ├── Mobile Application Pentester
│   └── API Security Specialist
├── Network Pentester
└── Red Team Specialist

Security Developer
├── Secure Code Developer
├── DevSecOps Engineer
└── Security Architect

Security Analyst
├── Vulnerability Analyst
├── Threat Intelligence Analyst
└── Security Operations Center (SOC) Analyst

Bug Bounty Hunter (Independent)
```

### รายได้โดยประมาณในไทย (2567)

```
Junior Security Analyst: 35,000 - 60,000 บาท/เดือน
Mid-level Pentester: 60,000 - 120,000 บาท/เดือน
Senior Security Engineer: 120,000 - 200,000+ บาท/เดือน
Bug Bounty: แตกต่างกันมากตั้งแต่หลักพันถึงหลักล้านบาทต่อ Bug
```

---

## 📝 แบบฝึกหัด (Exercises)

### Exercise 1: การระบุ SQL Injection Points

จากโค้ดต่อไปนี้ ให้หาและอธิบายว่ามีช่องโหว่ SQL Injection ที่ตำแหน่งใด:

```php
<?php
$id = $_GET['id'];
$name = $_GET['name'];
$email = $_POST['email'];

// Query 1
$q1 = "SELECT * FROM products WHERE id = $id";

// Query 2  
$q2 = "SELECT * FROM users WHERE name = '$name'";

// Query 3
$q3 = "INSERT INTO newsletter (email) VALUES ('$email')";

// Query 4
$stmt = $pdo->prepare("SELECT * FROM orders WHERE user_id = ?");
$stmt->execute([$_SESSION['user_id']]);
?>
```

**คำถาม:** Query ไหนมีช่องโหว่? Query ไหนปลอดภัย? เพราะอะไร?

### Exercise 2: การวิเคราะห์ Error Messages

ลองพิจารณา Error Message ต่อไปนี้:

```
You have an error in your SQL syntax; check the manual that corresponds 
to your MySQL server version for the right syntax to use near ''1''' 
at line 1
```

**คำถาม:** 
1. Error นี้บอกอะไรแก่เรา?
2. Database ที่ใช้คืออะไร?
3. ควรทดสอบ Payload อะไรต่อไป?

### Exercise 3: การวิเคราะห์ Impact

สมมติว่าเว็บไซต์ E-commerce ที่มีลูกค้า 10,000 คนถูกโจมตีด้วย SQL Injection และข้อมูลทั้งหมดรั่วไหล:

**คำถาม:**
1. ข้อมูลอะไรบ้างที่อาจถูกขโมย?
2. ผลกระทบต่อลูกค้าคืออะไร?
3. ผลกระทบต่อบริษัทคืออะไร?
4. บริษัทต้องทำอะไรบ้างหลังเกิดเหตุ?

---

## 🏆 Challenge

**Challenge 1:** ค้นหาข่าว SQL Injection Attack 3 เหตุการณ์ที่เกิดขึ้นในช่วง 2 ปีที่ผ่านมา และวิเคราะห์:
- เกิดขึ้นที่ไหน
- ผลกระทบเป็นอย่างไร
- บริษัทแก้ไขอย่างไร

**Challenge 2:** ลงทะเบียน Bug Bounty Platform (เช่น HackerOne หรือ Bugcrowd) และอ่าน Policy ของโปรแกรม 3 โปรแกรม วิเคราะห์:
- Scope ของแต่ละโปรแกรม
- Reward ที่ได้รับสำหรับ SQL Injection
- Rules และ Limitations

---

## 📚 แหล่งเรียนรู้เพิ่มเติม (Additional Resources)

### เว็บไซต์และ Platforms
```
- OWASP WebGoat: https://owasp.org/www-project-webgoat/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- HackTheBox: https://www.hackthebox.com/
- TryHackMe: https://tryhackme.com/
- DVWA: https://dvwa.co.uk/
```

### หนังสือแนะนำ
```
1. "The Web Application Hacker's Handbook" - Stuttard & Pinto
2. "SQL Injection Attacks and Defense" - Clarke
3. "The Hacker Playbook" - Kindel
4. "OWASP Testing Guide" - OWASP (Free PDF)
```

### Certifications ที่ควรพิจารณา
```
- CompTIA Security+ (สำหรับเริ่มต้น)
- CEH (Certified Ethical Hacker)
- OSCP (สำหรับระดับสูง)
```

---

## 🔑 สรุปประเด็นสำคัญ (Key Takeaways)

```
1. SQL Injection คือการแทรกคำสั่ง SQL ที่เป็นอันตรายผ่าน User Input

2. ช่องโหว่นี้มีมากว่า 25 ปีและยังคงพบบ่อย

3. ผลกระทบรุนแรง: ขโมยข้อมูล, ทำลายระบบ, ควบคุม Server

4. ทุกการทดสอบต้องได้รับอนุญาตก่อนเสมอ

5. กฎหมายไทย (พ.ร.บ. คอมพิวเตอร์) มีโทษรุนแรงสำหรับการโจมตีโดยไม่ได้รับอนุญาต

6. การป้องกันหลักคือการใช้ Parameterized Queries
```

---

## ➡️ ถัดไป (Next Part)

**Part 002: SQL Fundamentals**
- เรียนรู้คำสั่ง SQL พื้นฐาน: SELECT, INSERT, UPDATE, DELETE
- ทำความเข้าใจ WHERE Clause และ Operators
- การใช้ Functions ใน SQL
- เป็นรากฐานสำหรับการเรียนรู้ SQL Injection

---

*Part 001 | SQL Injection Mastery Course | Security Education Only*
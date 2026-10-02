# Part 053: Honeypots และ SQL Injection Traps

## ภาพรวม

การตั้งกับดักและฟังการโจมตี SQL injection ด้วย Honeypots

**ขั้นตอนที่ 861-875**

---

## 861. ทำไมต้องมี SQL Honeypot

```
SQL Honeypot คือ database หรือ endpoint ที่ไม่มี production ใช้จริง
แต่ปรากฟรูปร่างเป็นของจริง

วัตถุประสงค์:
1. ตรวจจับ attack ตั้งแต่เริ่มต้น
2. เรียนรู้เทคนิคของผู้โจมตี
3. เบี่ยงเวลาให้ Blue Team ตอบสนอง
4. ไม่มี false positive (ถ้ามีการเข้าถึง = เป็นแน่นอนว่า suspicious)
```

---

## 862. Simple Python Honeypot

```python
from flask import Flask, request, jsonify
import logging
from datetime import datetime
import json
import re

app = Flask(__name__)

# ตั้งค่า logging
logging.basicConfig(
    filename='honeypot_alerts.log',
    level=logging.INFO,
    format='%(asctime)s %(message)s'
)

SQLI_PATTERNS = [
    r"(?i)union.{0,20}select",
    r"(?i)'\s*(or|and)\s+'?\s*\d",
    r"(?i)drop\s+table",
    r"(?i)xp_cmdshell",
    r"(?i)sleep\s*\(",
    r"(?i)waitfor\s+delay",
    r"(?i)into\s+outfile",
    r"(?i)load_file",
    r"'\s*--",
    r"'\s*#",
    r"(?i)information_schema",
]

def is_sqli(value: str) -> bool:
    return any(re.search(p, value) for p in SQLI_PATTERNS)

def log_attack(ip, method, path, params, reason):
    alert = {
        'timestamp': datetime.utcnow().isoformat(),
        'ip': ip,
        'method': method,
        'path': path,
        'params': dict(params),
        'reason': reason,
        'honeypot': True
    }
    logging.info(json.dumps(alert))
    return alert

# Fake login endpoint (honeypot)
@app.route('/admin/login', methods=['GET', 'POST'])
def fake_login():
    ip = request.remote_addr
    
    # ตรวจสอบทุก parameter
    all_params = {}
    all_params.update(request.args)
    if request.method == 'POST':
        if request.is_json:
            all_params.update(request.json or {})
        else:
            all_params.update(request.form)
    
    for key, value in all_params.items():
        if is_sqli(str(value)):
            alert = log_attack(ip, request.method, request.path, all_params,
                             f'SQLi in {key}: {str(value)[:100]}')
            # คืนค่าเหมือนหน้าเว็บจริง
            break
    
    # แสดง fake login page เสมอ
    return '''
    <html><body>
    <h2>Admin Login</h2>
    <form method="POST">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Login">
    </form>
    <p>Invalid credentials</p>
    </body></html>
    ''', 401

# Fake API endpoint
@app.route('/api/v1/users', methods=['GET'])
def fake_users_api():
    ip = request.remote_addr
    
    for key, value in request.args.items():
        if is_sqli(value):
            log_attack(ip, 'GET', request.path, request.args,
                      f'API SQLi in {key}')
    
    # Return fake data
    return jsonify({'users': [], 'total': 0, 'page': 1})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
```

---

## 863. Database Canary Tokens

```sql
-- สร้างตาราง decoy ที่มี canary data
CREATE TABLE _honeypot_users (
    id INT,
    username VARCHAR(50),
    password VARCHAR(100),
    email VARCHAR(100)
);

INSERT INTO _honeypot_users VALUES
    (1, 'admin', 'canary_token_1234', 'admin@company.com'),
    (2, 'root', 'canary_token_5678', 'root@company.com'),
    (3, 'superuser', 'canary_token_9012', 'super@company.com');

-- Trigger เมื่อมีการ SELECT
DELIMITER //
CREATE TRIGGER honeypot_alert
AFTER SELECT ON _honeypot_users
FOR EACH ROW
BEGIN
    INSERT INTO security_alerts (event_type, user, timestamp)
    VALUES ('HONEYPOT_ACCESS', CURRENT_USER(), NOW());
END//
DELIMITER ;

-- หรือใช้ stored procedure monitor:
CREATE PROCEDURE check_honeypot_access()
BEGIN
    SELECT COUNT(*) as accesses FROM security_alerts
    WHERE event_type = 'HONEYPOT_ACCESS'
    AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR);
END;
```

---

## 864. Honeypot Response Automation

```python
import subprocess
import ipaddress
from datetime import datetime, timedelta

class HoneypotResponder:
    def __init__(self):
        self.blocked_ips = set()
        self.alert_counts = {}
    
    def process_alert(self, ip: str, attack_type: str):
        now = datetime.now()
        
        # นับจำนวนการโจมตี
        if ip not in self.alert_counts:
            self.alert_counts[ip] = []
        self.alert_counts[ip].append(now)
        
        # เอาเฉพาะใน  5 นาทีล่าสุด
        recent = [t for t in self.alert_counts[ip] if now - t < timedelta(minutes=5)]
        self.alert_counts[ip] = recent
        
        # block หาก > 5 ครั้งใน 5 นาที
        if len(recent) >= 5 and ip not in self.blocked_ips:
            self.block_ip(ip)
    
    def block_ip(self, ip: str):
        try:
            ipaddress.ip_address(ip)  # validate
            # เพิ่ม iptables rule (ต้องเป็น root)
            # subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            self.blocked_ips.add(ip)
            print(f"[!] Blocked IP: {ip}")
        except ValueError:
            pass

responder = HoneypotResponder()
# responder.process_alert('1.2.3.4', 'union_select')
```

---

## สรุป

Honeypots:
- **Fake endpoints** - /admin/login, /api/v1/users
- **Canary tokens** - ดึงดูดให้เข้ามา enumerate
- **DB triggers** - ตรวจจับการเข้าถึง honeypot tables
- **Auto-response** - block IP อัตโนมัติ
- **Zero false positives** - ถ้าเข้าถึง = แน่นอนว่า malicious

---

*Part 053 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

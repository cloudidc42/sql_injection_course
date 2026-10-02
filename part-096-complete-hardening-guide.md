# Part 096: Complete SQL Injection Hardening Guide

## ภาพรวม

คู่มือ hardening ครบถ้วนสำหรับ production systems

**ขั้นตอนที่ 1511-1525**

---

## 1511. Database Hardening (MySQL)

```sql
-- MySQL Hardening Checklist:

-- 1. ลบ anonymous users
DELETE FROM mysql.user WHERE User='';

-- 2. ลบ test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';

-- 3. ลบ remote root access
DELETE FROM mysql.user WHERE User='root' AND Host!='localhost';

-- 4. ผู้ใช้แอปพลิเคชัน: least privilege
CREATE USER 'app_user'@'app_server_ip' IDENTIFIED BY 'strong_password_here';
GRANT SELECT, INSERT, UPDATE, DELETE ON app_db.* TO 'app_user'@'app_server_ip';
-- NO: GRANT ALL, GRANT FILE, GRANT SUPER, GRANT REPLICATION

-- 5. ปิด file privilege
SET GLOBAL secure_file_priv = '/dev/null';  -- ใน my.cnf

-- 6. Enable audit logging (mysql_audit plugin):
INSTALL PLUGIN audit_log SONAME 'audit_log.so';
SET GLOBAL audit_log_policy = 'ALL';

-- 7. Apply changes
FLUSH PRIVILEGES;
```

---

## 1512. Database Hardening (PostgreSQL)

```
# postgresql.conf settings:

# ป้องกัน DB server ฟัง network ทุก interface
listen_addresses = 'localhost'  # หรือ app server IP เท่านั้น

# สิทธิ์ connection:
max_connections = 100

# Logging:
log_connections = on
log_disconnections = on
log_statement = 'ddl'  # หรือ 'all' สำหรับ audit
log_min_duration_statement = 1000  # บันทึก slow queries (>1s)

# pg_hba.conf:
# TYPE  DATABASE  USER  ADDRESS       METHOD
local   all       all                 md5
host    app_db    app_user app_ip/32  scram-sha-256
# ไม่มี 'trust' authentication!

# ปิด superuser เข้าจากภายนอก:
ALTER ROLE postgres NOLOGIN;  -- เฝ้าเข้าจากได้เฉพาะ socket
```

---

## 1513. Application Layer Hardening

```python
# app_security.py - Security middleware

from functools import wraps
from flask import Flask, request, abort
import re

app = Flask(__name__)

# 1. ปิด stack traces ใน production
app.config['PROPAGATE_EXCEPTIONS'] = False

@app.errorhandler(Exception)
def handle_error(e):
    return {'error': 'An error occurred'}, 500  # ไม่เปิดเผย detail

# 2. Input validation middleware
FORBIDDEN_PATTERNS = [
    r"(?i)(?:union|select|insert|update|delete|drop|create|exec|execute|sp_|xp_)",
    r"--",
    r"(?i)information_schema",
    r"(?i)pg_catalog",
]

def check_input(value: str) -> bool:
    """Returns True if safe"""
    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, value):
            return False
    return True

@app.before_request
def inspect_request():
    # ตรวจสอบ query params
    for key, value in request.args.items():
        if not check_input(str(value)):
            app.logger.warning(f"Suspicious input: {key}={value[:100]}")
            abort(400, 'Invalid input')

# 3. HTTP Security Headers
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

---

## 1514. CI/CD Security Gates

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Bandit (Python SAST)
        run: |
          pip install bandit
          bandit -r src/ -f json -o bandit-report.json
          # ผลลัพธ์: bandit ตรวจหา SQL injection patterns
      
      - name: Run Semgrep
        run: |
          pip install semgrep
          semgrep --config=p/sql-injection --json --output=semgrep.json src/
      
      - name: DAST with OWASP ZAP
        run: |
          docker run -t owasp/zap2docker-stable zap-baseline.py \
            -t http://staging.example.com \
            -r zap-report.html \
            -f 3  # fail on HIGH findings
      
      - name: Upload reports
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: '*-report.*'
```

---

## สรุป

Complete Hardening Guide:
- **MySQL** - remove anonymous users, file_priv, audit log
- **PostgreSQL** - listen_addresses, pg_hba.conf, logging
- **Application** - error handling, input validation, headers
- **CI/CD** - Bandit + Semgrep + OWASP ZAP gates

---

*Part 096 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

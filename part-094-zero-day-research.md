# Part 094: Zero-Day SQL Injection Research Methodology

## ภาพรวม

กระบวนการค้นหา novel SQLi vulnerabilities ใน frameworks, ORMs, และ DB engines

**ขั้นตอนที่ 1481-1495**

---

## 1481. กรอบการวิจัย

```
Zero-Day Research Framework:

1. TARGET SELECTION
   - Open source ORMs / query builders
   - Popular CMS platforms
   - Database drivers
   - Cloud DB wrappers
   
2. CODE REVIEW APPROACH
   a. Find SQL construction points
   b. Trace untrusted input paths
   c. Look for implicit type coercion
   d. Check encoding edge cases
   e. Examine template engines
   
3. FUZZING APPROACH
   a. Setup instrumented test environment
   b. Generate mutation-based inputs
   c. Detect: error responses, time delays, behavioral changes
   d. Minimize PoC payload
   
4. RESPONSIBLE DISCLOSURE
   a. Contact vendor security team
   b. CVE request via MITRE
   c. 90-day disclosure deadline (Google Project Zero standard)
   d. Public disclosure with patch
```

---

## 1482. Source Code Audit Methodology

```python
import ast
import os
from pathlib import Path

# Python AST-based SQLi finder
class SQLiAuditor(ast.NodeVisitor):
    def __init__(self):
        self.findings = []
        self.current_file = ''
    
    def visit_Call(self, node):
        """Find execute(f'...') or execute('...' + var) patterns"""
        # Check for f-string in execute call
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ('execute', 'raw', 'query'):
                for arg in node.args:
                    if isinstance(arg, ast.JoinedStr):  # f-string
                        self.findings.append({
                            'file': self.current_file,
                            'line': node.lineno,
                            'issue': 'f-string in SQL execute',
                        })
                    elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                        self.findings.append({
                            'file': self.current_file,
                            'line': node.lineno,
                            'issue': 'string concatenation in SQL execute',
                        })
        self.generic_visit(node)
    
    def audit_file(self, filepath: str):
        self.current_file = filepath
        try:
            with open(filepath) as f:
                tree = ast.parse(f.read())
            self.visit(tree)
        except (SyntaxError, UnicodeDecodeError):
            pass
    
    def audit_directory(self, dirpath: str):
        for path in Path(dirpath).rglob('*.py'):
            self.audit_file(str(path))
        return self.findings

# Usage:
auditor = SQLiAuditor()
findings = auditor.audit_directory('/path/to/project')
for f in findings:
    print(f"{f['file']}:{f['line']} - {f['issue']}")
```

---

## 1483. ORM Implicit Conversion Vulnerabilities

```python
# ตัวอย่าง ORM vulnerability pattern ที่พบบ่อย:

# 1. Integer coercion bypass (Django):
# User.objects.get(id=user_input)  # ถ้า id field = IntegerField
# Django cast user_input เป็น int → injection ไม่ได้ (SAFE)
# แต่ถ้า: User.objects.extra(where=[f'id = {user_input}']) → VULNERABLE

# 2. SQLAlchemy column() abuse:
from sqlalchemy import text, column

def get_sorted(col_name: str):
    # VULNERABLE: column() รับ string โดยตรง
    return db.execute(
        text('SELECT * FROM products ORDER BY :col').bindparams(
            col=column(col_name)  # column() ไม่ quote!
        )
    )
# Payload: col_name = "1; DROP TABLE products--"

# SECURE:
ALLOWED_COLS = {'name', 'price', 'created_at'}
def get_sorted_safe(col_name: str):
    if col_name not in ALLOWED_COLS:
        raise ValueError('Invalid column')
    return db.execute(text(f'SELECT * FROM products ORDER BY {col_name}'))
```

---

## 1484. Fuzzing for Novel Injection Points

```python
import requests
import itertools
import time

# สร้าง mutation corpus จาก base payload
BASE_PAYLOADS = ["'", '"', '`', ';', '--', "/*", "*/", 'UNION', 'SELECT']

def generate_mutations(base: str, depth: int = 2) -> list:
    mutations = [base]
    
    # Insertions
    special_chars = ["'", '"', ';', '-', '%', '_', '\\', '/']
    for c in special_chars:
        mutations.append(base + c)
        mutations.append(c + base)
        mutations.append(base[:len(base)//2] + c + base[len(base)//2:])
    
    # Encoding
    mutations.append(base.replace("'", '%27'))
    mutations.append(base.replace("'", "''"))
    mutations.append(base.replace(' ', '/**/'))
    
    # Truncation
    for i in range(1, min(len(base), 5)):
        mutations.append(base[:i])
    
    return list(set(mutations))

def fuzz_endpoint(url: str, param: str, base: str = "test"):
    mutations = generate_mutations(base)
    baseline = requests.get(url, params={param: base}, timeout=5)
    
    for payload in mutations:
        try:
            start = time.monotonic()
            r = requests.get(url, params={param: payload}, timeout=8)
            elapsed = time.monotonic() - start
            
            if elapsed > 3.0:
                print(f"[TIME] {payload!r} -> {elapsed:.1f}s")
            elif r.status_code != baseline.status_code:
                print(f"[STATUS] {payload!r} -> {r.status_code}")
            elif abs(len(r.text) - len(baseline.text)) > 200:
                print(f"[CONTENT_DIFF] {payload!r} -> delta={len(r.text)-len(baseline.text)}")
        except requests.Timeout:
            print(f"[TIMEOUT] {payload!r}")
```

---

## สรุป

Zero-Day Research:
- **Source audit** - AST analysis สำหรับ Python
- **ORM implicit** - column(), extra(), raw()
- **Mutation fuzzing** - generate + detect
- **Disclosure** - 90-day Google standard

---

*Part 094 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

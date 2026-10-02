# Part 086: SQL Injection ในระบบ Financial

## ภาพรวม

ระบบธนาคารและการเงิน - ผลกระทบเชิงอาญา

**ขั้นตอนที่ 1361-1375**

---

## 1361. Banking System Vectors

```sql
-- ช่องทางทั่วไป:

-- 1. Account lookup:
/account?account_no=1234567890
-> SELECT * FROM accounts WHERE account_number = '$account_no'

-- 2. Transaction history:
/transactions?date_from=2024-01-01&date_to=2024-12-31
-> SELECT * FROM transactions WHERE date BETWEEN '$from' AND '$to'

-- 3. Transfer:
POST /transfer {from_account: '...', to_account: '...', amount: '...'}
-> UPDATE accounts SET balance = balance - $amount WHERE account_number = '$from'

-- 4. Statement search:
/statement/search?reference=TXN123
-> SELECT * FROM transactions WHERE reference LIKE '%$ref%'
```

---

## 1362. Account Balance Manipulation

```sql
-- ถ้ามี SQL injection ใน transfer:
-- UPDATE accounts SET balance = balance - $amount WHERE account = '$from'

-- Payload amount: -1000 (negative = เพิ่ม balance!)
POST /transfer
{"amount": "-1000", "from_account": "my_acc", "to_account": "target"}

-- หรือ amount injection:
amount = "100 WHERE 1=2)-- -"
-- UPDATE accounts SET balance = balance - 100 WHERE 1=2)-- - WHERE account = '...'
-- ไม่เปลี่ยน balance ใดเลย!

-- Union-based:
account_no = "' UNION SELECT 1,account_number,balance,4 FROM accounts-- -"
```

---

## 1363. หลักการ ACID Transactions

```sql
-- ระบบการเงินต้องใช้ transactions เสมอ
-- เพื่อความ consistency (A=Atomicity)

-- SECURE transfer (MySQL):
BEGIN;
-- หักจากต้นทาง
 UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?;
 IF ROW_COUNT() = 0 THEN
   ROLLBACK;
   SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Insufficient funds';
 END IF;
-- เพิ่มไปปลายทาง
 UPDATE accounts SET balance = balance + ? WHERE id = ?;
COMMIT;

-- Python แบบ parameterized:
import mysql.connector

def transfer(from_id: int, to_id: int, amount: float):
    conn = mysql.connector.connect(host='localhost', database='bank',
                                   user='app', password='pass')
    cursor = conn.cursor()
    try:
        conn.start_transaction()
        
        # Deduct
        cursor.execute(
            "UPDATE accounts SET balance = balance - %s WHERE id = %s AND balance >= %s",
            (amount, from_id, amount)
        )
        if cursor.rowcount == 0:
            raise ValueError('Insufficient funds')
        
        # Credit
        cursor.execute(
            "UPDATE accounts SET balance = balance + %s WHERE id = %s",
            (amount, to_id)
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
```

---

## 1364. PCI DSS + Code Review

```python
# SAST scanner สำหรับ financial systems

import ast
import re

SQLI_PATTERNS = [
    r'cursor\.execute\(f["\']',   # f-string in execute
    r'cursor\.execute\(["\'][^"]+%[^s(]', # unsafe % format
    r'\.format\([^)]+\)[^;]*(?:WHERE|FROM|SELECT)',  # .format() in SQL context
    r'".*SELECT.*" \+',  # string concatenation with SELECT
    r'f".*(?:SELECT|INSERT|UPDATE|DELETE).*"',  # f-string SQL
]

def scan_file(filepath: str) -> list:
    findings = []
    with open(filepath) as f:
        content = f.read()
    
    for pattern in SQLI_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            line = content[:match.start()].count('\n') + 1
            findings.append({'line': line, 'pattern': pattern, 'match': match.group()[:80]})
    
    return findings
```

---

## สรุป

Financial SQL Injection:
- **Account/balance** - manipulation via injection
- **ACID transactions** - parameterized + rollback
- **PCI DSS** - SAST scanning required
- **Prevention** - int cast amounts, parameterize all queries

---

*Part 086 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

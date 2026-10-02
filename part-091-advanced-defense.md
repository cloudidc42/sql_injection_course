# Part 091: Advanced Defense Mechanisms

## ภาพรวม

กลยุทธ์ป้องกัน SQL Injection ระดับสูง: runtime protection, query analysis, honeypots

**ขั้นตอนที่ 1436-1450**

---

## 1436. Runtime Query Analysis

```python
import re
import logging
from functools import wraps

logger = logging.getLogger('sql_monitor')

# Pattern สำหรับ detect anomalous queries
ANOMALY_PATTERNS = [
    (r'UNION\s+(?:ALL\s+)?SELECT', 'UNION_SELECT'),
    (r'SLEEP\s*\(\d+\)', 'TIME_DELAY'),
    (r'WAITFOR\s+DELAY', 'TIME_DELAY_MSSQL'),
    (r'xp_cmdshell', 'RCE_ATTEMPT'),
    (r'INTO\s+(?:OUT|DUMP)FILE', 'FILE_WRITE'),
    (r'LOAD_FILE\s*\(', 'FILE_READ'),
    (r'information_schema', 'SCHEMA_ENUM'),
    (r'sys\.(?:tables|columns|objects)', 'SCHEMA_ENUM_MSSQL'),
    (r'OR\s+1\s*=\s*1', 'AUTH_BYPASS'),
    (r"'\s*OR\s+'\d", 'AUTH_BYPASS_STR'),
]

class QueryMonitor:
    def __init__(self, block_on_detection: bool = False):
        self.block = block_on_detection
        self.alerts = []
    
    def analyze(self, query: str, params: tuple = ()) -> bool:
        """Returns True if suspicious"""
        full = query + ' ' + str(params)
        detected = []
        
        for pattern, name in ANOMALY_PATTERNS:
            if re.search(pattern, full, re.IGNORECASE):
                detected.append(name)
        
        if detected:
            alert = {'query': query[:200], 'patterns': detected}
            self.alerts.append(alert)
            logger.warning(f"SQLi detected: {detected} in query: {query[:100]}")
            
            if self.block:
                raise SecurityError(f"Blocked query with patterns: {detected}")
            return True
        
        return False

monitor = QueryMonitor(block_on_detection=True)

def monitored_execute(cursor, query: str, params: tuple = ()):
    monitor.analyze(query, params)
    return cursor.execute(query, params)
```

---

## 1437. SQL Honeypot Tables

```sql
-- สร้าง honeypot tables ที่ดูน่าสนใจ
-- เมื่อใครเข้าถึง → alert!

-- MySQL
CREATE TABLE admin_passwords_backup (
    username VARCHAR(50),
    password TEXT
);
INSERT INTO admin_passwords_backup VALUES ('admin', 'honeypot_triggered');

-- MySQL Audit Plugin หรือ trigger:
CREATE TRIGGER honeypot_trigger
AFTER SELECT ON admin_passwords_backup
FOR EACH ROW
BEGIN
    INSERT INTO security_alerts (event, query_time, user, host)
    VALUES ('HONEYPOT_ACCESS', NOW(), CURRENT_USER(), @@hostname);
END;

-- PostgreSQL audit:
CREATE OR REPLACE RULE honeypot_alert AS
ON SELECT TO admin_passwords_backup DO ALSO
    INSERT INTO security_alerts(event, ts) VALUES ('HONEYPOT', NOW());
```

---

## 1438. Prepared Statement Cache

```python
# Connection pooling + prepared statement cache
# ป้องกัน injection และเพิ่ม performance

import psycopg2
import psycopg2.pool

class SafeDBPool:
    def __init__(self, dsn: str, min_conn: int = 2, max_conn: int = 10):
        self.pool = psycopg2.pool.ThreadedConnectionPool(min_conn, max_conn, dsn)
        self._statements = {}  # query_name -> prepared statement name
    
    def prepare(self, name: str, query: str):
        """Pre-register known queries"""
        self._statements[name] = query
    
    def execute(self, stmt_name: str, params: tuple):
        """Execute only pre-registered statements"""
        if stmt_name not in self._statements:
            raise ValueError(f"Unknown statement: {stmt_name}")
        
        conn = self.pool.getconn()
        try:
            with conn.cursor() as cur:
                # Use server-side prepared statement
                cur.execute(
                    f"EXECUTE {stmt_name} (%s)" if len(params) == 1
                    else "SELECT %s" % ','.join(['%s']*len(params)),
                    params
                )
                # Better: use psycopg2's native prepared statements
                cur.execute(self._statements[stmt_name], params)
                return cur.fetchall()
        finally:
            self.pool.putconn(conn)

# Register allowed queries only:
db = SafeDBPool('postgresql://user:pass@localhost/db')
db.prepare('get_user', 'SELECT id, name, email FROM users WHERE id = %s')
db.prepare('get_product', 'SELECT * FROM products WHERE sku = %s')
# ไม่มีการ execute query อื่น!
```

---

## 1439. Defense-in-Depth Checklist

```yaml
# defense_checklist.yml
levels:
  level_1_input:
    - Parameterized queries / Prepared statements (ALL queries)
    - Input type validation (int, date, enum)
    - Input length limits
    - Whitelist validation for column/table names
    
  level_2_application:
    - ORM with parameterized methods only
    - SAST scanning in CI/CD pipeline
    - Code review checklist for SQL construction
    - Disable ORM raw query methods where possible
    
  level_3_database:
    - Least privilege DB users (no DDL, no FILE)
    - Separate read/write DB users
    - DB audit logging enabled
    - Honeypot tables
    - Stored procedures with EXECUTE permissions only
    
  level_4_network:
    - WAF (ModSecurity + OWASP CRS rules)
    - Rate limiting per IP/user
    - DB accessible only from app servers
    - DB port not exposed to internet
    
  level_5_monitoring:
    - Real-time query monitoring
    - SIEM alerts for SQLi patterns
    - Anomaly detection for unusual query rates
    - Incident response playbook
    
  level_6_testing:
    - DAST scanning (OWASP ZAP, Burp Suite)
    - Annual penetration testing
    - Bug bounty program
    - Red team exercises
```

---

## สรุป

Advanced Defense:
- **Runtime monitoring** - QueryMonitor blocks anomalous queries
- **Honeypot tables** - detect reconnaissance
- **Prepared statement cache** - ป้องกัน dynamic query
- **Defense-in-depth** - 6 layers ครอบคลุมทุกจุด

---

*Part 091 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

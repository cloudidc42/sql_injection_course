# Part 089: SQL Injection ใน ETL/Data Pipeline

## ภาพรวม

ETL (Extract, Transform, Load) pipelines มักถูกมองข้ามด้านความปลอดภัย

**ขั้นตอนที่ 1406-1420**

---

## 1406. ETL Injection Surface

```
ETL Injection Points:

1. Dynamic SQL ใน stored procedures
   - EXEC('SELECT ' + @column + ' FROM ' + @table)
   
2. ORM/query builders รับ column names จาก config:
   - df = pd.read_sql('SELECT ' + col + ' FROM data', conn)

3. Data transformation scripts:
   - สร้าง SQL จาก CSV headers
   - Column names = SQL injection
   
4. Airflow DAGs:
   - Task parameters จาก external sources
   - Template rendering ใน SQL operators
   
5. dbt (data build tool):
   - Jinja templates
   - {{ ref() }} และ {{ source() }} functions
```

---

## 1407. Apache Airflow SQL Injection

```python
# VULNERABLE: SqlSensor กับ dynamic query
from airflow.providers.common.sql.sensors.sql import SqlSensor

# Injection ผ่าน Airflow Variables:
table_name = Variable.get('report_table')  # = "users; DROP TABLE users--"

sensor = SqlSensor(
    task_id='check_data',
    conn_id='postgres_default',
    sql=f"SELECT COUNT(*) FROM {table_name}",  # VULNERABLE!
    timeout=3600,
)

# SECURE: whitelist table names
ALLOWED_TABLES = {'daily_report', 'monthly_report', 'raw_events'}

if table_name not in ALLOWED_TABLES:
    raise ValueError(f"Invalid table: {table_name}")

sensor = SqlSensor(
    task_id='check_data',
    conn_id='postgres_default', 
    sql=f"SELECT COUNT(*) FROM {table_name}",  # SAFE after whitelist
    timeout=3600,
)
```

---

## 1408. Pandas + SQLAlchemy Pipeline Injection

```python
import pandas as pd
from sqlalchemy import create_engine, text

# VULNERABLE: dynamic column from user/config input
def load_report(column: str, start_date: str):
    engine = create_engine('postgresql://user:pass@localhost/db')
    # column injection: "* FROM users--"
    # start_date injection: "2024-01-01' OR '1'='1"
    query = f"SELECT {column} FROM sales WHERE date > '{start_date}'"
    return pd.read_sql(query, engine)

# SECURE: whitelist columns + parameterize
ALLOWED_COLUMNS = {'revenue', 'units', 'customer_id', 'date'}

def load_report_safe(column: str, start_date: str):
    if column not in ALLOWED_COLUMNS:
        raise ValueError(f"Invalid column: {column}")
    
    engine = create_engine('postgresql://user:pass@localhost/db')
    # Whitelist ป้องกัน column injection
    # text() + :param ป้องกัน value injection
    query = text(f"SELECT {column} FROM sales WHERE date > :start")
    with engine.connect() as conn:
        return pd.read_sql(query, conn, params={'start': start_date})
```

---

## 1409. dbt Jinja Template Injection

```sql
-- dbt model: models/sales_report.sql
-- VULNERABLE: รับ column จาก variable

{% set user_column = var('extra_column', 'NULL') %}

SELECT
    sale_id,
    amount,
    {{ user_column }}  -- Injection point!
FROM {{ ref('raw_sales') }}

-- Payload: var extra_column = "1 FROM pg_user--"
-- ผล: SELECT sale_id, amount, 1 FROM pg_user-- FROM raw_sales

-- SECURE: whitelist ใน dbt
{% set allowed = ['discount', 'tax', 'net_amount'] %}
{% set user_column = var('extra_column', 'NULL') %}

{% if user_column not in allowed %}
  {{ exceptions.raise_compiler_error("Invalid column: " ~ user_column) }}
{% endif %}

SELECT sale_id, amount, {{ user_column }}
FROM {{ ref('raw_sales') }}
```

---

## 1410. CSV Header Injection

```python
import csv
import re

# VULNERABLE: ใช้ CSV headers เป็น column names โดยตรง
def import_csv_to_db(filepath: str, table: str, cursor):
    with open(filepath) as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames  # อาจเป็น "name; DROP TABLE users--"
        
        for row in reader:
            cols = ', '.join(headers)  # INJECTION!
            vals = ', '.join(['%s'] * len(headers))
            sql = f"INSERT INTO {table} ({cols}) VALUES ({vals})"
            cursor.execute(sql, list(row.values()))

# SECURE: sanitize column names
def sanitize_column(name: str) -> str:
    """Allow only alphanumeric and underscore"""
    clean = re.sub(r'[^a-zA-Z0-9_]', '', name)
    if not clean:
        raise ValueError(f"Invalid column name: {name}")
    return clean

def import_csv_safe(filepath: str, table: str, cursor, allowed_cols: set):
    # Validate table name
    if not re.match(r'^[a-zA-Z0-9_]+$', table):
        raise ValueError("Invalid table name")
    
    with open(filepath) as f:
        reader = csv.DictReader(f)
        headers = [sanitize_column(h) for h in reader.fieldnames]
        
        # Only use headers that are in allowed columns
        headers = [h for h in headers if h in allowed_cols]
        if not headers:
            raise ValueError("No valid columns found")
        
        for row in reader:
            vals = [row[h] for h in reader.fieldnames if sanitize_column(h) in headers]
            cols = ', '.join(headers)
            placeholders = ', '.join(['%s'] * len(headers))
            cursor.execute(f"INSERT INTO {table} ({cols}) VALUES ({placeholders})", vals)
```

---

## สรุป

ETL Pipeline Injection:
- **Airflow** - Variable/template injection → whitelist
- **Pandas** - column name concat → whitelist + text()
- **dbt** - Jinja var injection → exceptions.raise_compiler_error
- **CSV import** - header-to-column → sanitize + whitelist

---

*Part 089 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

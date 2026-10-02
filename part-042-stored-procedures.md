# Part 042: Stored Procedures และ SQL Injection

## ภาพรวม

Stored Procedures ไม่สามารถป้องกัน SQL injection ได้โดยอัตโนมัติ ถ้าเขียน dynamic SQL ภายใน

**ขั้นตอนที่ 641-660**

---

## 641. Stored Procedure Vulnerabilities

```sql
-- MySQL: VULNERABLE stored procedure
DELIMITER //
CREATE PROCEDURE get_user(IN username VARCHAR(100))
BEGIN
    SET @query = CONCAT('SELECT * FROM users WHERE username = \'', username, '\'');
    PREPARE stmt FROM @query;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END//
DELIMITER ;

-- การเรียกใช้
-- CALL get_user('admin');

-- โจมตี:
-- CALL get_user("' UNION SELECT 1,username,password FROM users-- -");
```

---

## 642. Parameterized Stored Procedures (Secure)

```sql
-- MySQL: SECURE stored procedure
DELIMITER //
CREATE PROCEDURE get_user_secure(IN p_username VARCHAR(100))
BEGIN
    -- ใช้ direct parameter ไม่ใช้ CONCAT
    SELECT id, username, email FROM users WHERE username = p_username;
END//
DELIMITER ;

-- CALL get_user_secure('admin'); -- SAFE!
```

---

## 643. Dynamic SQL ใน Stored Procedures

```sql
-- MSSQL - VULNERABLE dynamic SQL
CREATE PROCEDURE search_products
    @product_name VARCHAR(100)
AS
BEGIN
    DECLARE @sql NVARCHAR(1000);
    SET @sql = 'SELECT * FROM products WHERE name LIKE ''%' + @product_name + '%''';
    EXEC(@sql);
END;

-- ส่ง stacked queries:
-- EXEC search_products "test'; EXEC xp_cmdshell 'whoami'--"

-- MSSQL - SECURE กับ sp_executesql
CREATE PROCEDURE search_products_secure
    @product_name VARCHAR(100)
AS
BEGIN
    DECLARE @sql NVARCHAR(1000);
    DECLARE @params NVARCHAR(100);
    
    SET @sql = N'SELECT * FROM products WHERE name LIKE @pattern';
    SET @params = N'@pattern VARCHAR(100)';
    
    EXEC sp_executesql @sql, @params, @pattern = '%' + @product_name + '%';
END;
```

---

## 644. PostgreSQL Stored Procedures

```sql
-- PostgreSQL - VULNERABLE function
CREATE OR REPLACE FUNCTION get_user(username text) RETURNS TABLE(id int, name text) AS $$
DECLARE
    query text;
BEGIN
    query := 'SELECT id, username FROM users WHERE username = ''' || username || '''';
    RETURN QUERY EXECUTE query;
END;
$$ LANGUAGE plpgsql;

-- ส่ง injection:
-- SELECT * FROM get_user("' OR '1'='1");

-- PostgreSQL - SECURE
CREATE OR REPLACE FUNCTION get_user_secure(p_username text) RETURNS TABLE(id int, name text) AS $$
BEGIN
    -- ใช้ EXECUTE ... USING สำหรับ parameterized
    RETURN QUERY EXECUTE 'SELECT id, username FROM users WHERE username = $1'
    USING p_username;
END;
$$ LANGUAGE plpgsql;
```

---

## 645. การตรวจสอบ Stored Procedures เพื่อหา Vulnerabilities

```python
import mysql.connector

def test_stored_proc_injection(host, user, password, database, proc_name, param):
    """Test stored procedure for SQL injection"""
    conn = mysql.connector.connect(
        host=host, user=user, password=password, database=database
    )
    cursor = conn.cursor()
    
    payloads = [
        "'",
        "''",
        "' OR '1'='1",
        "' UNION SELECT 1,2,3-- -",
        "'; DROP TABLE test-- -",
    ]
    
    for payload in payloads:
        try:
            cursor.callproc(proc_name, [payload])
            results = list(cursor.stored_results())
            for r in results:
                data = r.fetchall()
                if data:
                    print(f"[+] Possible injection: {payload}")
                    print(f"    Returned {len(data)} rows")
        except mysql.connector.Error as e:
            if 'syntax' in str(e).lower() or 'you have an error' in str(e).lower():
                print(f"[+] SQL Error with payload: {payload}")
                print(f"    Error: {e}")
    
    cursor.close()
    conn.close()
```

---

## สรุป

Stored Procedures + SQL Injection:
- **CONCAT/+** - dynamic SQL = vulnerable
- **PREPARE/EXEC** - ระวัง dynamic queries
- **sp_executesql** - MSSQL parameterized
- **EXECUTE...USING** - PostgreSQL parameterized
- **Rule**: ถ้าใช้ direct parameter = safe, CONCAT = vulnerable

---

*Part 042 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

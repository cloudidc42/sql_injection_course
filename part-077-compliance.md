# Part 077: Compliance Frameworks และ SQL Injection

## ภาพรวม

PCI DSS, GDPR, SOC2 และการป้องกัน SQL injection

**ขั้นตอนที่ 1226-1240**

---

## 1226. PCI DSS และ SQL Injection

```
PCI DSS (Payment Card Industry Data Security Standard)
เกี่ยวข้องกับ SQL injection:

Requirement 6.3.2:
  ต้องสร้างและดูแล software ระหว่าง development lifecycle
  - Code review (SAST, manual)
  - Training นักพัฒนา

Requirement 6.4.1:
  WAF ต้องมีหรือ active monitoring

Requirement 11.3.1:
  Penetration testing อย่างน้อยปีละครั้ง
  - External + Internal pentest
  - ครอบคลุม application layer
  - ต้อง test SQL injection

Requirement 6.2.4:
  Secure coding guidelines ต้องครอบคลุม OWASP Top 10
  - SQL injection เป็น #3 ใน OWASP 2021
```

---

## 1227. GDPR และ SQL Injection

```
GDPR (General Data Protection Regulation)

ผลกระทบ:
- SQL injection ส่งผลให้ personal data ถูกเข้าถึงโดยไม่ได้รับอนุญาต
- = data breach = ต้องแจ้งภายใน 72 ชั่วโมง
- ค่าปรับ: สูงสุด 4% ของยอดขายต่อปีทั่วโลก
  หรือ 20 ล้าน EUR

Article 32 - Security of Processing:
  "ผู้ควบคุม data ต้องใช้มาตรการทางเทคนิคที่เหมาะสมเพื่อความปลอดภัย"
  -> Input validation + Parameterized queries

Article 25 - Privacy by Design:
  -> สร้าง security ตั้งแต่ต้น
  -> SQL injection prevention ต้องเป็นส่วนหนึ่งของ design
```

---

## 1228. SOC2 Type II

```
SOC2 Criteria CC6 - Logical and Physical Access Controls

CC6.1 Security:
  องค์กรต้องแสดงหลักฐานที่:
  1. Vulnerability scanning สม่ำเสมอ
  2. Penetration testing
  3. SAST/DAST ใน CI/CD
  4. Developer security training

CC7.1 System Operations:
  - Log monitoring
  - WAF alerts
  - Anomaly detection (UEBA)

CC8.1 Change Management:
  - Security code review ก่อน deploy
  - ตรวจสอบ SQL injection ใน QA

Audit Evidence:
  - SAST scan results (Semgrep, SonarQube)
  - Pentest reports
  - WAF rule configurations
  - Training completion records
```

---

## 1229. OWASP ASVS สำหรับ SQLi

```python
# OWASP Application Security Verification Standard
# Section 5: Validation, Sanitization and Encoding

# ASVS Level 1 (minimum):
# V5.3.4: Verify ORM, SQL builders, stored procedures use parameterized queries
# V5.3.5: Verify no dynamic SQL concatenation

# Checklist tool:
def asvs_check_sqlcode(code: str) -> list:
    import ast
    issues = []
    
    # ตรวจสอบ f-string ใน SQL queries
    if 'f"' in code or "f'" in code:
        if any(kw in code.upper() for kw in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'WHERE']):
            issues.append('ASVS V5.3.5: Potential f-string SQL concatenation')
    
    # ตรวจสอบ % format ใน SQL
    if "% " in code or "%s" in code:
        if 'cursor.execute' in code:
            # เช็คว่าใช้ดี (%s เป็น parameterized)
            pass
    
    # ตรวจสอบ string format
    if '.format(' in code:
        if any(kw in code.upper() for kw in ['SELECT', 'WHERE']):
            issues.append('ASVS V5.3.5: Potential .format() SQL concatenation')
    
    return issues

# Example:
code = "sql = f'SELECT * FROM users WHERE id = {user_id}'"
print(asvs_check_sqlcode(code))
```

---

## สรุป

Compliance + SQL Injection:
- **PCI DSS** - pentest annually, WAF required
- **GDPR** - data breach = fine up to 4% global revenue
- **SOC2** - evidence: SAST, pentest, training
- **ASVS** - V5.3.4/5.3.5 parameterized queries

---

*Part 077 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

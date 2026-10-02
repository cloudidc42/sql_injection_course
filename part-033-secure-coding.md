# Part 033: Secure Coding Practices

## ภาพรวม

Secure coding เป็นทั้งศาสตร์และศิลป์ในการเขียนโค้ดที่ปลอดภัย

**ขั้นตอนที่ 476-495**

---

## 476. ORM แทน Raw SQL

```python
# Django ORM - SECURE
from django.db import models

users = User.objects.filter(username=request.POST['username'])

# Django ORM - ระวัง raw() ถ้าไม่ใช้ params
users = User.objects.raw(
    "SELECT * FROM users WHERE username = %s",
    [request.POST['username']]
)  # SECURE - parameterized

users = User.objects.raw(
    f"SELECT * FROM users WHERE username = '{request.POST['username']}'"
)  # VULNERABLE!

# SQLAlchemy ORM
from sqlalchemy.orm import Session

with Session(engine) as session:
    user = session.query(User).filter(User.username == username).first()
```

---

## 477. Django Security Settings

```python
# settings.py

# DATABASES - ใช้ parameterized queriesเสมอ หากใช้ ORM อยู่แล้ว
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'mydb',
        'USER': 'webapp',  # limited privileges user
        'PASSWORD': 'strong_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

# Security settings
DEBUG = False  # NEVER True in production
SECRET_KEY = os.environ.get('SECRET_KEY')  # from env var
ALLOWED_HOSTS = ['example.com']

# Security middleware
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# CSRF
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True

# Session
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
```

---

## 478. Flask Security

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
import bleach
import re

app = Flask(__name__)

# Rate limiting
limiter = Limiter(app, default_limits=["100 per day", "10 per minute"])

# Input sanitization
def sanitize_input(value: str) -> str:
    # Remove HTML tags
    clean = bleach.clean(value)
    # Remove SQL metacharacters for display (ไม่ใช้แทน prepared statements!)
    return clean

# Parameterized query with SQLAlchemy
from sqlalchemy import text

@app.route('/users')
def get_users():
    user_id = request.args.get('id')
    
    # Validate input type
    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        return 'Invalid ID', 400
    
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT id, username, email FROM users WHERE id = :id"),
            {"id": user_id}
        )
        user = result.fetchone()
    
    if user:
        return {"id": user.id, "username": user.username}
    return 'Not found', 404
```

---

## 479. Password Hashing ที่ถูกต้อง

```python
import bcrypt
import hashlib
import secrets

# bcrypt (recommended)
def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

# Usage
hashed = hash_password("user_password")
if verify_password(input_password, hashed):
    print("Login successful")

# Argon2 (modern alternative)
from argon2 import PasswordHasher
ph = PasswordHasher()
hashed = ph.hash("password")
ph.verify(hashed, "password")

# SHA-256 with salt (หากไม่มี bcrypt/argon2)
salt = secrets.token_hex(32)
hashed = hashlib.sha256((salt + password).encode()).hexdigest()
# เก็บทั้ง salt และ hash ใน DB
```

---

## 480. Secure Configuration

```ini
# MySQL my.cnf
[mysqld]
# ไม่อนุญาต remote root login
bind-address = 127.0.0.1
skip-networking = 0

# สิทธิ์ file
secure-file-priv = /tmp

# ไม่แสดง version
version = ""

[mysql]
# ทำให้ error messages เป็น generic
```

```nginx
# Nginx ซ่อน server signature
server_tokens off;

# Security headers
add_header X-Content-Type-Options nosniff;
add_header X-Frame-Options DENY;
add_header X-XSS-Protection "1; mode=block";
add_header Content-Security-Policy "default-src 'self'";
```

---

## 481. Code Review Checklist

```
SQL Injection Code Review:
[ ] ทุก query ใช้ prepared statements หรือ ORM?
[ ] Input validation ก่อนใช้ใน query?
[ ] Error messages ไม่เปิดเผย SQL details?
[ ] Database user มีแต่ minimum privileges?
[ ] Logging เพื่อตรวจจับ anomalies?
[ ] ORM ถูกใช้ ไม่ใช้ raw() โดยไม่จำเป็น?
[ ] ไม่มี string concatenation ใน SQL?
[ ] Stored procedures ใช้ parameterized?
```

---

## สรุป

Secure Coding:
- **ORM** - ปลอดภัยที่สุด
- **Prepared Statements** - เท็คนิคหลัก
- **Input Validation** - whitelist แทน blacklist
- **Password Hashing** - bcrypt หรือ argon2
- **Configuration** - minimize attack surface
- **Code Review** - checklist สุดท้าย

---

*Part 033 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

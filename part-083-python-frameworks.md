# Part 083: SQL Injection ใน Python Frameworks

## ภาพรวม

Flask, Django, FastAPI - บั่งเสี่ยงและวิธีป้องกัน

**ขั้นตอนที่ 1316-1330**

---

## 1316. Flask + SQLAlchemy

```python
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

engine = create_engine('mysql+pymysql://user:pass@localhost/app')
app = Flask(__name__)

# VULNERABLE: f-string
@app.route('/user')
def get_user_vulnerable():
    user_id = request.args.get('id', '')
    with engine.connect() as conn:
        # SQL injection!
        result = conn.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))
        return jsonify([dict(r) for r in result])

# SECURE: bindparam
@app.route('/user/safe')
def get_user_safe():
    user_id = request.args.get('id', '')
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({'error': 'Invalid ID'}), 400
    
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT * FROM users WHERE id = :uid"),
            {'uid': user_id}
        )
        return jsonify([dict(r._mapping) for r in result])

# BEST: SQLAlchemy ORM
from sqlalchemy.orm import Session
from models import User

@app.route('/user/orm')
def get_user_orm():
    user_id = request.args.get('id', type=int)
    if not user_id:
        return jsonify({'error': 'Invalid ID'}), 400
    
    with Session(engine) as session:
        user = session.get(User, user_id)
        return jsonify(user.to_dict() if user else None)
```

---

## 1317. Django และ SQLi

```python
from django.db import models, connection
from django.http import JsonResponse

# VULNERABLE: raw() แบบ concat
def get_products_vuln(request):
    category = request.GET.get('category', '')
    # SQL injection!
    products = Product.objects.raw(
        f"SELECT * FROM shop_product WHERE category = '{category}'"
    )
    return JsonResponse({'count': len(list(products))})

# SECURE: raw() แบบ params
def get_products_safe(request):
    category = request.GET.get('category', '')
    products = Product.objects.raw(
        'SELECT * FROM shop_product WHERE category = %s',
        [category]
    )
    return JsonResponse({'count': len(list(products))})

# BEST: ORM
def get_products_orm(request):
    category = request.GET.get('category', '')
    products = Product.objects.filter(category=category)
    return JsonResponse({'count': products.count()})

# VULNERABLE: extra() เก็บ extra where
def search_products_vuln(request):
    q = request.GET.get('q', '')
    # ไม่ถูกต้อง!
    return Product.objects.extra(where=[f"name LIKE '%{q}%'"])

# SECURE: ORM Q objects
from django.db.models import Q
def search_products_safe(request):
    q = request.GET.get('q', '')
    return Product.objects.filter(Q(name__icontains=q) | Q(description__icontains=q))
```

---

## 1318. FastAPI + Databases

```python
from fastapi import FastAPI, HTTPException
from databases import Database

app = FastAPI()
DB_URL = 'mysql+aiomysql://user:pass@localhost/app'
database = Database(DB_URL)

@app.on_event('startup')
async def startup():
    await database.connect()

# VULNERABLE:
@app.get('/items/vuln')
async def get_item_vulnerable(name: str):
    query = f"SELECT * FROM items WHERE name = '{name}'"
    rows = await database.fetch_all(query)
    return rows

# SECURE: named binding
@app.get('/items/safe')
async def get_item_safe(name: str):
    query = "SELECT * FROM items WHERE name = :name"
    rows = await database.fetch_all(query, values={'name': name})
    return rows

# SECURE: SQLModel ORM
from sqlmodel import Session, select
from models import Item

@app.get('/items/orm/{item_id}')
async def get_item_orm(item_id: int):
    with Session(engine) as session:
        item = session.get(Item, item_id)
        if not item:
            raise HTTPException(status_code=404)
        return item
```

---

## 1319. psycopg2 และ SQLi

```python
import psycopg2

conn = psycopg2.connect(host='localhost', database='app', user='user', password='pass')
cursor = conn.cursor()

# VULNERABLE:
def get_user_vuln(user_id: str):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchall()

# SECURE: %s placeholder
def get_user_safe(user_id: str):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchall()

# EXTRA SAFE: explicit int cast
def get_user_int(user_id: str):
    uid = int(user_id)  # raises ValueError if not int
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
    return cursor.fetchall()

# Named parameters:
cursor.execute(
    "SELECT * FROM users WHERE name = %(name)s AND active = %(active)s",
    {'name': username, 'active': True}
)
```

---

## สรุป

Python Frameworks SQLi:
- **SQLAlchemy** - `text(':param')` + dict
- **Django** - raw(`%s`, list) หรือ ORM filter()
- **FastAPI** - `:name` + values dict
- **psycopg2** - `%s` placeholder

---

*Part 083 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

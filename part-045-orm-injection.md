# Part 045: ORM Injection และ Edge Cases

## ภาพรวม

ORM frameworks มักถูกเข้าใจผิดว่าปลอดภัย แต่ยังมีจุดอ่อแแฟโดยเฉพาะ raw queries

**ขั้นตอนที่ 701-720**

---

## 701. Django ORM Injection

```python
from django.db import models
from django.db.models import Q

# VULNERABLE: raw() with string formatting
def get_user_vulnerable(username):
    return User.objects.raw(
        f"SELECT * FROM auth_user WHERE username = '{username}'"
    )
# Attack: get_user_vulnerable("' OR '1'='1")

# VULNERABLE: extra() filter
def search_vulnerable(search_term):
    return User.objects.extra(
        where=[f"username LIKE '{search_term}%'"]
    )

# SECURE: raw() with parameters
def get_user_secure(username):
    return User.objects.raw(
        "SELECT * FROM auth_user WHERE username = %s",
        [username]
    )

# SECURE: ORM filter (always parameterized)
def get_user_orm(username):
    return User.objects.filter(username=username)

# SECURE: Q objects
def search_secure(search_term):
    return User.objects.filter(
        Q(username__icontains=search_term) | Q(email__icontains=search_term)
    )
```

---

## 702. Django Order By Injection

```python
# VULNERABLE: dynamic ordering
def list_users_vulnerable(order_field):
    # ถ้า order_field = "username; DROP TABLE users--"
    return User.objects.order_by(order_field)

# การโจมตี:
# order_field = "id), (SELECT password FROM auth_user LIMIT 1)--"

# SECURE: whitelist allowed fields
ALLOWED_FIELDS = ['username', 'email', 'date_joined', '-username', '-email']

def list_users_secure(order_field):
    if order_field not in ALLOWED_FIELDS:
        order_field = 'username'  # default
    return User.objects.order_by(order_field)
```

---

## 703. SQLAlchemy Injection

```python
from sqlalchemy import text
from sqlalchemy.orm import Session

# VULNERABLE: text() with string concat
def search_users_vulnerable(db: Session, username: str):
    query = text(f"SELECT * FROM users WHERE username = '{username}'")
    return db.execute(query).fetchall()

# SECURE: text() with bindparams
def search_users_secure(db: Session, username: str):
    query = text("SELECT * FROM users WHERE username = :username")
    return db.execute(query, {'username': username}).fetchall()

# SECURE: ORM query
from sqlalchemy import select
from models import User

def get_user_orm(db: Session, username: str):
    return db.execute(
        select(User).where(User.username == username)
    ).scalar_one_or_none()

# VULNERABLE: filter with string
def filter_vulnerable(db: Session, column: str, value: str):
    query = text(f"SELECT * FROM users WHERE {column} = :value")
    return db.execute(query, {'value': value}).fetchall()
# Attack: column = "1=1 OR username"
```

---

## 704. Hibernate/JPA Injection

```java
// VULNERABLE: JPQL string concat
public List<User> searchVulnerable(String username) {
    String jpql = "FROM User WHERE username = '" + username + "'";
    return entityManager.createQuery(jpql, User.class).getResultList();
}

// SECURE: Named Parameters
public List<User> searchSecure(String username) {
    String jpql = "FROM User WHERE username = :username";
    return entityManager.createQuery(jpql, User.class)
        .setParameter("username", username)
        .getResultList();
}

// SECURE: Criteria API
public List<User> searchCriteria(String username) {
    CriteriaBuilder cb = entityManager.getCriteriaBuilder();
    CriteriaQuery<User> cq = cb.createQuery(User.class);
    Root<User> root = cq.from(User.class);
    
    cq.select(root).where(cb.equal(root.get("username"), username));
    
    return entityManager.createQuery(cq).getResultList();
}
```

---

## 705. ActiveRecord (Ruby on Rails) Injection

```ruby
# VULNERABLE: string interpolation
def find_user_vulnerable(name)
  User.where("name = '#{name}'")  # VULNERABLE!
end

# Attack: name = "' OR '1'='1"

# SECURE: Hash conditions
def find_user_secure(name)
  User.where(name: name)          # SAFE
end

# SECURE: Array conditions (parameterized)
def find_user_array(name)
  User.where('name = ?', name)    # SAFE
end

# VULNERABLE: order injection
def list_users_vulnerable(order)
  User.order(order)  # VULNERABLE: User.order("id; DROP TABLE users")
end

# SECURE: sanitize_sql_for_order
def list_users_secure(order)
  allowed = %w[name email created_at]
  order = 'name' unless allowed.include?(order)
  User.order(order)
end
```

---

## สรุป

ORM Injection:
- **Django** - raw(), extra(), และ order_by() มีความเสี่ยง
- **SQLAlchemy** - text() ต้องใช้ bindparams
- **Hibernate** - JPQL concat = vulnerable, named params = safe
- **ActiveRecord** - string interpolation = vulnerable, ? = safe
- **Rule**: ORM ไม่ใช่ป้องกัน auto ถ้าใช้ raw/text string concat

---

*Part 045 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

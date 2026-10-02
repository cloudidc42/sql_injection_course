# Part 059: SQL Injection ใน Serverless Architecture

## ภาพรวม

Serverless functions (Lambda, Cloud Functions, Azure Functions) ยังคงมีความเสี่ยงต่อ SQL injection

**ขั้นตอนที่ 956-970**

---

## 956. AWS Lambda + RDS

```python
import json
import boto3
import pymysql
import os

def lambda_handler(event, context):
    # VULNERABLE: ใช้ query parameter โดยตรง
    user_id = event['queryStringParameters']['id']
    
    conn = pymysql.connect(
        host=os.environ['DB_HOST'],
        user=os.environ['DB_USER'],
        password=os.environ['DB_PASS'],
        database=os.environ['DB_NAME']
    )
    
    cursor = conn.cursor()
    # VULNERABLE:
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    
    results = cursor.fetchall()
    return {
        'statusCode': 200,
        'body': json.dumps(results)
    }

# SECURE version:
def lambda_handler_secure(event, context):
    user_id = event['queryStringParameters'].get('id', '')
    
    # Validate
    try:
        user_id = int(user_id)
    except (ValueError, TypeError):
        return {'statusCode': 400, 'body': 'Invalid id'}
    
    conn = pymysql.connect(
        host=os.environ['DB_HOST'],
        user=os.environ['DB_USER'],
        password=os.environ['DB_PASS'],
        database=os.environ['DB_NAME']
    )
    
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email FROM users WHERE id = %s", (user_id,))
    results = cursor.fetchall()
    conn.close()
    
    return {'statusCode': 200, 'body': json.dumps(results)}
```

---

## 957. API Gateway + Lambda Injection

```python
# API Gateway พาสจาก path parameter
# GET /users/{id} -> Lambda

def handler_path_injection(event, context):
    # Path: /users/1' UNION SELECT...
    user_id = event['pathParameters']['id']
    
    # VULNERABLE:
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    
# API Gateway input validation (request validator):
# serverless.yml:
# functions:
#   getUser:
#     events:
#       - http:
#           path: users/{id}
#           method: get
#           request:
#             parameters:
#               paths:
#                 id: true  # required
#             template:
#               application/json: |
#                 { "id": "$input.params('id')" }
```

---

## 958. DynamoDB Injection เทียบกับ SQL

```python
import boto3
from boto3.dynamodb.conditions import Key, Attr

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Users')

# DynamoDB ไม่มี SQL แต่มี NoSQL injection:

# VULNERABLE: FilterExpression ด้วย string concat
def get_user_vulnerable(username):
    response = table.scan(
        FilterExpression=f"username = '{username}'"
    )
    return response['Items']

# ไม่ใช่ SQL injection แต่เป็น expression injection

# SECURE: ใช้ Attr condition
def get_user_secure(username: str):
    response = table.scan(
        FilterExpression=Attr('username').eq(username)
    )
    return response['Items']

# Aurora Serverless SQL injection (same as RDS MySQL/PostgreSQL)
```

---

## 959. Serverless Security Best Practices

```python
import re
import json
from functools import wraps

def validate_params(schema: dict):
    """Decorator สำหรับ Lambda function validation"""
    def decorator(func):
        @wraps(func)
        def wrapper(event, context):
            params = event.get('queryStringParameters') or {}
            path_params = event.get('pathParameters') or {}
            body = {}
            
            if event.get('body'):
                try:
                    body = json.loads(event['body'])
                except Exception:
                    return {'statusCode': 400, 'body': 'Invalid JSON'}
            
            all_params = {**params, **path_params, **body}
            
            for field, rules in schema.items():
                value = all_params.get(field)
                
                if rules.get('required') and value is None:
                    return {'statusCode': 400, 'body': f'Missing: {field}'}
                
                if value is not None and rules.get('type') == 'int':
                    try:
                        all_params[field] = int(value)
                    except (ValueError, TypeError):
                        return {'statusCode': 400, 'body': f'Invalid: {field}'}
            
            event['_validated'] = all_params
            return func(event, context)
        
        return wrapper
    return decorator

# Usage:
# @validate_params({'id': {'required': True, 'type': 'int'}})
# def lambda_handler(event, context):
#     user_id = event['_validated']['id']
#     ...
```

---

## สรุป

Serverless SQL Injection:
- **Lambda + RDS** - ยัง inject ได้ถ้าไม่ใช้ parameterized
- **API Gateway** - ใช้ request validators
- **DynamoDB** - ไม่มี SQL แต่มี expression injection
- **Aurora Serverless** - เหมือน RDS
- **Prevention** - validate + parameterize ทุก function

---

*Part 059 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

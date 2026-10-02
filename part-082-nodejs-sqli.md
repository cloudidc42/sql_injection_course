# Part 082: SQL Injection ใน Node.js

## ภาพรวม

Node.js frameworks: Express, Fastify และ libraries ที่เสี่ยงต่อ SQL injection

**ขั้นตอนที่ 1301-1315**

---

## 1301. mysql2 / mysql Injection

```javascript
const mysql = require('mysql2/promise');

// VULNERABLE: string concatenation
async function getUserVulnerable(username) {
    const conn = await mysql.createConnection(process.env.DB_URL);
    const [rows] = await conn.query(`SELECT * FROM users WHERE username = '${username}'`);
    return rows;
}

// SECURE: parameterized
async function getUserSafe(username) {
    const conn = await mysql.createConnection(process.env.DB_URL);
    const [rows] = await conn.execute(
        'SELECT * FROM users WHERE username = ?',
        [username]
    );
    return rows;
}

// เพิ่มเติม: mysql.escape() (แต่ parameterized ดีกว่า)
const safeName = mysql.escape(username);
const [rows] = await conn.query(`SELECT * FROM users WHERE username = ${safeName}`);
```

---

## 1302. Sequelize ORM และ SQLi

```javascript
const { Op } = require('sequelize');
const { User } = require('./models');

// VULNERABLE: raw query แบบ concat
async function searchVulnerable(term) {
    return User.sequelize.query(
        `SELECT * FROM users WHERE name LIKE '%${term}%'`
    );
}

// SECURE: sequelize.query แบบ replacements
async function searchSafe(term) {
    return User.sequelize.query(
        'SELECT * FROM users WHERE name LIKE :term',
        { replacements: { term: `%${term}%` } }
    );
}

// BEST: ใช้ ORM methods
async function searchBest(term) {
    return User.findAll({
        where: { name: { [Op.like]: `%${term}%` } }
    });
}

// VULNERABLE: order by injection
async function sortVulnerable(column) {
    return User.findAll({ order: [[column, 'ASC']] })
    // column อาจเป็น '1,2 UNION SELECT...'
}

// SECURE: whitelist columns
const ALLOWED = ['name', 'email', 'created_at'];
async function sortSafe(column) {
    if (!ALLOWED.includes(column)) throw new Error('Invalid column');
    return User.findAll({ order: [[column, 'ASC']] });
}
```

---

## 1303. Knex.js และ SQLi

```javascript
const knex = require('knex')(/* config */);

// VULNERABLE: raw() แบบ concat
async function badRaw(id) {
    return knex.raw(`SELECT * FROM orders WHERE id = ${id}`);
}

// SECURE: raw() แบบ binding
async function goodRaw(id) {
    return knex.raw('SELECT * FROM orders WHERE id = ?', [id]);
}

// SECURE: query builder
async function queryBuilder(id) {
    return knex('orders').where({ id }).select();
}

// VULNERABLE: whereRaw แบบ concat
async function badWhereRaw(filter) {
    return knex('users').whereRaw(`status = '${filter}'`);
}

// SECURE:
async function goodWhereRaw(filter) {
    return knex('users').whereRaw('status = ?', [filter]);
}
```

---

## 1304. Express.js Middleware

```javascript
const express = require('express');
const app = express();

// Middleware สำหรับ validate inputs
function validateId(req, res, next) {
    const id = parseInt(req.params.id);
    if (isNaN(id) || id <= 0) {
        return res.status(400).json({ error: 'Invalid ID' });
    }
    req.validatedId = id;
    next();
}

app.get('/user/:id', validateId, async (req, res) => {
    const user = await getUserSafe(req.validatedId);
    res.json(user);
});

// Rate limiting เพื่อป้องกัน automated SQLi
const rateLimit = require('express-rate-limit');
app.use('/api/', rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
}));

// Helmet.js สำหรับ security headers
const helmet = require('helmet');
app.use(helmet());
```

---

## สรุป

Node.js SQL Injection:
- **mysql2** - `.execute()` ใช้ `?` placeholder
- **Sequelize** - `replacements` หรือ ORM methods
- **Knex.js** - `raw('? ...', [val])` binding
- **Express** - middleware validation, rate limiting

---

*Part 082 | SQL Injection Course | สำหรับการศึกษาเท่านั้น*

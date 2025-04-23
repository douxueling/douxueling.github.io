const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const client = require('prom-client');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// 数据库配置
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: 'yourpassword',
  database: 'cvms_db'
};

// JWT密钥
const JWT_SECRET = 'your_jwt_secret_key';

// 创建数据库连接池
const pool = mysql.createPool(dbConfig);

// 用户认证中间件
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: '未授权' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [decoded.id]);
    if (!users.length) return res.status(401).json({ error: '用户不存在' });
    req.user = users[0];
    next();
  } catch (err) {
    res.status(401).json({ error: '无效令牌' });
  }
};

// 用户登录
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE username = ? OR email = ?', [username, username]);
    if (!users.length) return res.status(401).json({ error: '用户名或密码错误' });

    const isValid = await bcrypt.compare(password, users[0].password);
    if (!isValid) return res.status(401).json({ error: '用户名或密码错误' });

    const token = jwt.sign({ id: users[0].id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, username: users[0].username });
  } catch (err) {
    res.status(500).json({ error: '服务器错误' });
  }
});

// 漏洞扫描API
app.post('/api/scan', authenticate, async (req, res) => {
  // 这里集成Nessus或其他扫描引擎
  res.json({ status: '扫描已启动' });
});

// 启动服务
const PORT = 3001;
app.listen(PORT, () => {
  console.log(`CVMS后端服务运行在 http://localhost:${PORT}`);
});

// 创建监控指标
const scanCounter = new client.Counter({
  name: 'cvms_scans_total',
  help: 'Total number of scans performed'
});

// 添加监控端点
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', client.register.contentType);
  res.end(await client.register.metrics());
});

// 在扫描API中增加计数器
app.post('/api/scan', authenticate, async (req, res) => {
  scanCounter.inc();
  // 这里集成Nessus或其他扫描引擎
  res.json({ status: '扫描已启动' });
});
const express = require('express');
const cors = require('cors');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const JWT_SECRET = 'MiniTechSupport_SecretKey_2026_SecureAES256';
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Explicit Route Handlers
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

function generateLongKey(typeTag) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let p1 = '', p2 = '';
  for (let i = 0; i < 4; i++) {
    p1 += chars.charAt(Math.floor(Math.random() * chars.length));
    p2 += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `MINI-${typeTag}-2026-${p1}-${p2}`;
}

function getRemainingTimeText(expDateStr) {
  const exp = new Date(expDateStr);
  const now = new Date();
  const diffMs = exp - now;
  if (diffMs <= 0) return 'Đã hết hạn';

  const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  
  if (days > 0) return `Còn ${days} ngày ${hours} giờ`;
  return `Còn ${hours} giờ`;
}

// In-Memory Database
let keys = [
  {
    id: 1,
    key: 'MINI-DAY-2026-X89K-912A',
    type: 'Tool Ngày',
    createdAt: new Date('2026-07-01').toISOString(),
    expirationDate: new Date('2026-12-31').toISOString(),
    status: 'Active',
    boundDeviceId: null,
    boundMachineName: null,
    note: 'Key dùng thử 1 ngày'
  },
  {
    id: 2,
    key: 'MINI-MONTH-2026-K92B-441F',
    type: 'Tool Tháng',
    createdAt: new Date('2026-07-01').toISOString(),
    expirationDate: new Date('2026-08-30').toISOString(),
    status: 'Active',
    boundDeviceId: null,
    boundMachineName: null,
    note: 'Key Hỗ Trợ Kỹ Thuật VIP'
  },
  {
    id: 3,
    key: 'MINI-TERM-2026-Z77P-9002',
    type: 'Tool Kỳ',
    createdAt: new Date('2026-07-01').toISOString(),
    expirationDate: new Date('2027-01-01').toISOString(),
    status: 'Active',
    boundDeviceId: null,
    boundMachineName: null,
    note: 'Key Hợp Đồng Kỳ 6 Tháng'
  }
];

let screenshots = [];
let chatMessages = []; // Stores 2-way chat messages between Support & User

let auditLogs = [
  { id: 1, timestamp: new Date().toISOString(), action: 'SYSTEM_START', actor: 'System', details: 'Server MiniTech Support đã khởi động.' }
];

let wsClients = new Set();

wss.on('connection', (ws) => {
  wsClients.add(ws);
  ws.on('close', () => wsClients.delete(ws));
});

function broadcast(data) {
  const payload = JSON.stringify(data);
  for (const client of wsClients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  }
}

function addLog(action, actor, details) {
  const log = { id: auditLogs.length + 1, timestamp: new Date().toISOString(), action, actor, details };
  auditLogs.unshift(log);
}

// Self Keep-Alive Ping every 4 minutes to prevent Render Free tier cold-starts
setInterval(() => {
  try {
    http.get('http://localhost:' + PORT + '/api/admin/stats', () => {});
  } catch (e) {}
}, 4 * 60 * 1000);

// -------------------------------------------------------------
// 1. ADMIN LOGIN API
// -------------------------------------------------------------
app.post('/api/admin/login', (req, res) => {
  const username = req.body.username || req.body.Username;
  const password = req.body.password || req.body.Password;

  if (username === 'admin' && password === '0934494823') {
    const token = jwt.sign({ role: 'admin', username: 'admin' }, JWT_SECRET, { expiresIn: '1d' });
    addLog('ADMIN_LOGIN', 'admin', 'Admin đã đăng nhập vào Portal quản lý Key.');
    return res.json({ success: true, message: 'Đăng nhập thành công!', token });
  }

  return res.status(401).json({ success: false, message: 'Tài khoản hoặc mật khẩu không chính xác.' });
});

// -------------------------------------------------------------
// 2. CLIENT AUTH API - CLEARS ALL SCREENSHOTS & CHAT ON VALIDATION
// -------------------------------------------------------------
app.post('/api/auth/validate-key', (req, res) => {
  const rawKey = req.body.key || req.body.Key;
  const machineName = req.body.machineName || req.body.MachineName || 'ClientPC';
  const windowsUser = req.body.windowsUser || req.body.WindowsUser || 'User';
  const deviceId = req.body.deviceId || req.body.DeviceId || `${machineName}-${windowsUser}`;

  const cleanKey = (rawKey || '').trim().toUpperCase();

  const foundKey = keys.find(k => k.key.toUpperCase() === cleanKey);
  if (!foundKey) {
    return res.status(404).json({ success: false, message: 'Mã Key không tồn tại trên hệ thống.' });
  }

  if (foundKey.status === 'Disabled') {
    return res.status(403).json({ success: false, message: 'Mã Key này đã bị Admin khóa/thu hồi.' });
  }

  const now = new Date();
  if (new Date(foundKey.expirationDate) < now) {
    return res.status(403).json({ success: false, message: 'Mã Key này đã hết hạn sử dụng.' });
  }

  if (foundKey.boundDeviceId && foundKey.boundDeviceId !== deviceId) {
    return res.status(403).json({
      success: false,
      message: `Key đã được đăng ký cho thiết bị khác (${foundKey.boundMachineName || 'Unknown'}). Không thể dùng nhiều máy!`
    });
  }

  if (!foundKey.boundDeviceId) {
    foundKey.boundDeviceId = deviceId;
    foundKey.boundMachineName = machineName;
  }

  // WIPE ALL SCREENSHOTS AND CHAT MESSAGES ON EVERY KEY VALIDATION
  screenshots = [];
  chatMessages = [];
  broadcast({ type: 'SESSION_CLEARED' });

  const remainingText = getRemainingTimeText(foundKey.expirationDate);
  const token = jwt.sign({ key: foundKey.key, deviceId }, JWT_SECRET, { expiresIn: '7d' });

  addLog('KEY_VALIDATED', `${machineName}\\${windowsUser}`, `Kích hoạt Key ${foundKey.key}. Lịch sử được làm mới. Hạn còn: ${remainingText}`);

  return res.json({
    success: true,
    message: `Xác thực thành công! Key hạn sử dụng: ${remainingText}`,
    remainingText: remainingText,
    key: foundKey.key,
    keyType: foundKey.type,
    status: foundKey.status,
    createdAt: foundKey.createdAt,
    expirationDate: foundKey.expirationDate,
    token
  });
});

// -------------------------------------------------------------
// 3. SCREENSHOT API
// -------------------------------------------------------------
app.post('/api/session/upload-screenshot', (req, res) => {
  const rawKey = req.body.key || req.body.Key;
  const machineName = req.body.machineName || req.body.MachineName || 'ClientPC';
  const windowsUser = req.body.windowsUser || req.body.WindowsUser || 'User';
  let imageBase64 = req.body.imageBase64 || req.body.ImageBase64 || '';
  let capturedAt = req.body.capturedAt || req.body.CapturedAt;

  if (imageBase64 && !imageBase64.startsWith('data:')) {
    imageBase64 = 'data:image/jpeg;base64,' + imageBase64;
  }

  if (!capturedAt || typeof capturedAt !== 'string' || capturedAt.includes('/Date(')) {
    capturedAt = new Date().toISOString();
  }

  const cleanKey = (rawKey || 'MINI-DEFAULT').toUpperCase();

  const newShot = {
    id: Date.now(),
    key: cleanKey,
    machineName,
    windowsUser,
    imageBase64,
    capturedAt,
    isRead: false,
    note: '',
    noteAuthor: '',
    noteHistory: []
  };

  screenshots.unshift(newShot);
  addLog('SCREENSHOT_UPLOAD', `${machineName}\\${windowsUser}`, `Chụp ảnh màn hình mới cho Key ${rawKey}`);

  broadcast({ type: 'NEW_SCREENSHOT', data: newShot });

  res.json({
    success: true,
    screenshotId: newShot.id,
    message: `Đã gửi ảnh thành công!`
  });
});

app.get('/api/session/screenshots', (req, res) => {
  const { key } = req.query;
  if (!key) return res.json(screenshots);

  const cleanKey = key.trim().toUpperCase();
  let filtered = screenshots.filter(s => s.key.toUpperCase() === cleanKey);
  if (filtered.length === 0) filtered = screenshots;
  return res.json(filtered);
});

// -------------------------------------------------------------
// 4. 2-WAY REALTIME CHAT API
// -------------------------------------------------------------
app.post('/api/chat/send', (req, res) => {
  const key = (req.body.key || req.body.Key || '').trim().toUpperCase();
  const sender = req.body.sender || req.body.Sender || 'Support';
  const text = (req.body.text || req.body.Text || '').trim();

  if (!text) return res.status(400).json({ success: false, message: 'Nội dung tin nhắn trống.' });

  const msgObj = {
    id: Date.now(),
    key,
    sender, // 'Support' or 'User'
    text,
    timestamp: new Date().toISOString()
  };

  chatMessages.unshift(msgObj);
  addLog('CHAT_MSG', sender, `[Key ${key}]: ${text}`);

  broadcast({
    type: 'CHAT_MESSAGE',
    key,
    sender,
    text,
    timestamp: msgObj.timestamp,
    id: msgObj.id
  });

  return res.json({ success: true, message: msgObj });
});

app.get('/api/chat/latest', (req, res) => {
  const key = (req.query.key || '').trim().toUpperCase();
  let list = [];
  if (key) {
    list = chatMessages.filter(m => m.key.toUpperCase() === key || !m.key);
  }
  if (list.length === 0) {
    list = chatMessages;
  }

  if (list.length > 0) {
    const latest = list[0];
    return res.json({
      success: true,
      id: latest.id,
      key: latest.key,
      sender: latest.sender,
      text: latest.text,
      timestamp: latest.timestamp
    });
  }

  return res.json({ success: false, text: '' });
});

app.get('/api/chat/messages', (req, res) => {
  const key = (req.query.key || '').trim().toUpperCase();
  let list = [];
  if (key) {
    list = chatMessages.filter(m => m.key.toUpperCase() === key || !m.key);
  }
  if (list.length === 0) {
    list = chatMessages;
  }
  return res.json(list);
});

// Legacy note endpoint
app.post('/api/session/notes', (req, res) => {
  const screenshotId = req.body.screenshotId || req.body.ScreenshotId;
  const note = req.body.note || req.body.Note;
  const author = req.body.author || req.body.Author;

  const shot = screenshots.find(s => s.id == screenshotId);
  if (shot) {
    shot.note = note;
    shot.noteAuthor = author || 'Support';
  }

  const msgObj = {
    id: Date.now(),
    key: shot ? shot.key : '',
    sender: 'Support',
    text: note,
    timestamp: new Date().toISOString()
  };
  chatMessages.unshift(msgObj);

  broadcast({
    type: 'CHAT_MESSAGE',
    key: shot ? shot.key : '',
    sender: 'Support',
    text: note,
    timestamp: msgObj.timestamp,
    id: msgObj.id
  });

  return res.json({ success: true, message: 'Đã gửi đáp án qua chat.' });
});

app.get('/api/session/latest-note', (req, res) => {
  return res.redirect('/api/chat/latest?key=' + (req.query.key || ''));
});

// -------------------------------------------------------------
// 5. ADMIN KEY MANAGEMENT API
// -------------------------------------------------------------
app.get('/api/admin/keys', (req, res) => res.json(keys));

app.post('/api/admin/keys', (req, res) => {
  const { type, customDays, note } = req.body;

  let days = 30;
  if (type === 'Tool Ngày') days = 1;
  else if (type === 'Tool Tháng') days = 30;
  else if (type === 'Tool Kỳ') days = customDays ? parseInt(customDays) : 180;

  const typeTag = type === 'Tool Ngày' ? 'DAY' : (type === 'Tool Tháng' ? 'MONTH' : 'TERM');
  const keyStr = generateLongKey(typeTag);

  const newKey = {
    id: keys.length + 1,
    key: keyStr,
    type: type || 'Tool Tháng',
    createdAt: new Date().toISOString(),
    expirationDate: new Date(Date.now() + days * 86400000).toISOString(),
    status: 'Active',
    boundDeviceId: null,
    boundMachineName: null,
    note: note || ''
  };

  keys.unshift(newKey);
  addLog('KEY_CREATED', 'Admin', `Tạo mới Key ${newKey.key} (${newKey.type})`);

  return res.json({ success: true, key: newKey });
});

app.put('/api/admin/keys/:id/toggle-status', (req, res) => {
  const id = parseInt(req.params.id);
  const found = keys.find(k => k.id === id);
  if (!found) return res.status(404).json({ success: false, message: 'Key không tồn tại' });

  found.status = found.status === 'Active' ? 'Disabled' : 'Active';
  addLog('KEY_STATUS_CHANGED', 'Admin', `Đổi trạng thái Key ${found.key} sang ${found.status}`);

  return res.json({ success: true, key: found });
});

app.put('/api/admin/keys/:id/extend', (req, res) => {
  const id = parseInt(req.params.id);
  const { days } = req.body;
  const found = keys.find(k => k.id === id);
  if (!found) return res.status(404).json({ success: false, message: 'Key không tồn tại' });

  const addDays = parseInt(days) || 30;
  const currentExp = new Date(found.expirationDate);
  const baseDate = currentExp > new Date() ? currentExp : new Date();
  found.expirationDate = new Date(baseDate.getTime() + addDays * 86400000).toISOString();

  addLog('KEY_EXTENDED', 'Admin', `Gia hạn Key ${found.key} thêm ${addDays} ngày.`);

  return res.json({ success: true, key: found });
});

app.delete('/api/admin/keys/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const idx = keys.findIndex(k => k.id === id);
  if (idx === -1) return res.status(404).json({ success: false, message: 'Key không tồn tại' });

  const removed = keys.splice(idx, 1)[0];
  addLog('KEY_DELETED', 'Admin', `Xóa Key ${removed.key}`);

  return res.json({ success: true, message: 'Đã xóa Key.' });
});

app.get('/api/admin/stats', (req, res) => {
  const totalKeys = keys.length;
  const activeKeys = keys.filter(k => k.status === 'Active' && new Date(k.expirationDate) > new Date()).length;
  const totalScreenshots = screenshots.length;
  const boundDevices = keys.filter(k => k.boundDeviceId).length;

  res.json({
    totalKeys,
    activeKeys,
    totalScreenshots,
    boundDevices,
    systemUptime: process.uptime()
  });
});

app.get('/api/admin/logs', (req, res) => res.json(auditLogs));

server.listen(PORT, () => {
  console.log(`=================================================`);
  console.log(`  MiniTech Support Backend running on port ${PORT}`);
  console.log(`  Explicit Routes Registered                     `);
  console.log(`=================================================`);
});

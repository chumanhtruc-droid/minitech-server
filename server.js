const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const AdmZip = require('adm-zip');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Auth config ─────────────────────────────────────────────
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = '0934494823';
const activeSessions = new Map(); // token → expiry timestamp
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

function createSession() {
  const token = uuidv4();
  activeSessions.set(token, Date.now() + SESSION_TTL_MS);
  return token;
}

function isValidSession(token) {
  if (!token || !activeSessions.has(token)) return false;
  const expiry = activeSessions.get(token);
  if (Date.now() > expiry) { activeSessions.delete(token); return false; }
  return true;
}

function parseCookies(cookieHeader = '') {
  const cookies = {};
  cookieHeader.split(';').forEach(part => {
    const [k, ...v] = part.trim().split('=');
    if (k) cookies[k.trim()] = decodeURIComponent(v.join('=').trim());
  });
  return cookies;
}

function requireAdmin(req, res, next) {
  const cookies = parseCookies(req.headers.cookie);
  if (isValidSession(cookies.admin_token)) return next();
  res.redirect('/login');
}
// ────────────────────────────────────────────────────────────

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const os = require('os');

const isServerless = Boolean(process.env.VERCEL || process.env.NOW_REGION || process.env.AWS_REGION || process.env.LAMBDA_TASK_ROOT);
const DB_PATH = isServerless ? path.join(os.tmpdir(), 'db.json') : path.join(__dirname, 'db.json');
const UPLOADS_DIR = isServerless ? path.join(os.tmpdir(), 'uploads') : path.join(__dirname, 'uploads');

// Serve uploaded screenshots & public static files
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Ensure upload folder exists safely
try {
  if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  }
} catch (err) {
  console.error("Uploads directory creation warning:", err.message);
}

const CLOUD_DB_URL = 'https://jsonblob.com/api/jsonBlob/019fa270-ee1a-7677-87b4-d2fdb42df8b4';
let memoryDb = null;
let isSyncingCloud = false;

// Async initial load from Cloud DB on server startup
async function initCloudDb() {
  try {
    const fetchFn = globalThis.fetch || (await import('node-fetch')).default;
    const res = await fetchFn(CLOUD_DB_URL);
    if (res.ok) {
      const data = await res.json();
      if (data && Array.isArray(data.keys)) {
        memoryDb = data;
        try { fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf-8'); } catch {}
        console.log(`[Cloud DB] Loaded ${memoryDb.keys.length} keys from cloud storage.`);
      }
    }
  } catch (err) {
    console.error('[Cloud DB Load Error]:', err.message || err);
  }
}

// Initial sync on module load
initCloudDb();

function readDb() {
  if (memoryDb) {
    return memoryDb;
  }
  if (fs.existsSync(DB_PATH)) {
    try {
      const data = fs.readFileSync(DB_PATH, 'utf-8');
      if (data && data.trim()) {
        const parsed = JSON.parse(data);
        memoryDb = {
          keys: Array.isArray(parsed.keys) ? parsed.keys : [],
          screenshots: Array.isArray(parsed.screenshots) ? parsed.screenshots : []
        };
        return memoryDb;
      }
    } catch (err) {
      console.error("Error reading database file:", err);
    }
  }
  memoryDb = { keys: [], screenshots: [] };
  writeDb(memoryDb);
  return memoryDb;
}

function writeDb(data) {
  memoryDb = data;
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf-8');
  } catch (err) {
    console.error("Error writing database file:", err);
  }

  // Background Cloud Persistence Sync (Non-blocking)
  if (!isSyncingCloud) {
    isSyncingCloud = true;
    setTimeout(async () => {
      try {
        const fetch = (await import('node-fetch')).default || globalThis.fetch;
        await fetch(CLOUD_DB_URL, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(memoryDb)
        });
        console.log('[Cloud DB] Synced database to persistent cloud storage.');
      } catch (err) {
        console.error('[Cloud DB Sync Error]:', err.message || err);
      } finally {
        isSyncingCloud = false;
      }
    }, 300);
  }
}

// Multer configuration (uses memory storage for 100% serverless compatibility)
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }
});

function ensureReqFileOnDisk(req) {
  if (!req.file) return null;
  if (!fs.existsSync(UPLOADS_DIR)) {
    try { fs.mkdirSync(UPLOADS_DIR, { recursive: true }); } catch {}
  }
  const ext = path.extname(req.file.originalname || '') || '.jpg';
  const filename = `screenshot_${Date.now()}_${uuidv4().substring(0, 8)}${ext}`;
  const filePath = path.join(UPLOADS_DIR, filename);
  fs.writeFileSync(filePath, req.file.buffer);
  req.file.filename = filename;
  req.file.path = filePath;
  return req.file;
}

// --- AUTH ROUTES ---

// Serve login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login API
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const token = createSession();
    res.setHeader('Set-Cookie', `admin_token=${token}; HttpOnly; Path=/; Max-Age=28800; SameSite=Strict`);
    return res.json({ success: true });
  }
  res.status(401).json({ success: false, message: 'Sai tên đăng nhập hoặc mật khẩu' });
});

// Logout API
app.post('/api/logout', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  if (cookies.admin_token) activeSessions.delete(cookies.admin_token);
  res.setHeader('Set-Cookie', 'admin_token=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict');
  res.json({ success: true });
});

// Check auth status (for frontend)
app.get('/api/check-auth', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  res.json({ authenticated: isValidSession(cookies.admin_token) });
});

// Protected admin panel (main index.html)
app.get('/', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- API ENDPOINTS ---

// Admin: Generate a new key
// Body: { duration_hours: number }  — 0 means unlimited
app.post('/api/generate-key', (req, res) => {
  const db = readDb();
  const rawKey = uuidv4().substring(0, 13).toUpperCase().replace('-', '');
  const newKey = `MINITECH-${rawKey.substring(0, 4)}-${rawKey.substring(4, 8)}-${rawKey.substring(8, 12)}`;
  const durationHours = parseInt(req.body.duration_hours, 10) || 0; // 0 = unlimited

  const keyObj = {
    key: newKey,
    createdAt: new Date().toISOString(),
    status: 'active',
    durationHours,          // how many hours from first activation
    activatedAt: null,      // set on first verify-key call
    expiresAt: null         // computed on first verify-key call
  };

  db.keys.push(keyObj);
  writeDb(db);

  res.json({ success: true, key: newKey, durationHours });
});

// Admin & Support: Get all active keys + any keys with uploaded screenshots
app.get('/api/keys', (req, res) => {
  const db = readDb();
  const keyMap = new Map();

  // 1. Add all keys from db.keys
  (db.keys || []).forEach(k => {
    const normKey = (k.key || '').toUpperCase();
    if (normKey) {
      keyMap.set(normKey, {
        ...k,
        key: normKey,
        screenshotCount: 0
      });
    }
  });

  // 2. Add keys from db.screenshots if missing, and update count with case-insensitive matching
  (db.screenshots || []).forEach(s => {
    const normKey = (s.key || '').toUpperCase();
    if (!normKey) return;
    if (!keyMap.has(normKey)) {
      keyMap.set(normKey, {
        key: normKey,
        createdAt: s.createdAt || new Date().toISOString(),
        status: 'active',
        durationHours: 0,
        screenshotCount: 0
      });
    }
    const item = keyMap.get(normKey);
    item.screenshotCount = (item.screenshotCount || 0) + 1;
  });

  res.json({ success: true, keys: Array.from(keyMap.values()) });
});

// Admin: Delete a key
app.post('/api/delete-key', (req, res) => {
  const { key } = req.body;
  if (!key) {
    return res.status(400).json({ success: false, message: "Key parameter missing" });
  }
  
  const db = readDb();
  db.keys = db.keys.filter(k => k.key !== key);
  // Also filter screenshots associated with this key (optional but good practice)
  const screenshotsToDelete = db.screenshots.filter(s => s.key === key);
  db.screenshots = db.screenshots.filter(s => s.key !== key);
  
  // Delete physical files
  screenshotsToDelete.forEach(s => {
    const filePath = path.join(UPLOADS_DIR, s.filename);
    if (fs.existsSync(filePath)) {
      try {
        fs.unlinkSync(filePath);
      } catch (err) {
        console.error("Error deleting file:", filePath, err);
      }
    }
  });

  writeDb(db);
  res.json({ success: true, message: "Key and associated screenshots deleted" });
});

// Client & Support: Verify activation key (starts expiry timer on first call)
app.get('/api/verify-key', (req, res) => {
  const keyQuery = (req.query.key || '').trim().toUpperCase();
  if (!keyQuery) {
    return res.json({ success: false, message: "Key parameter missing" });
  }

  const db = readDb();
  let keyObj = db.keys.find(k => (k.key || '').trim().toUpperCase() === keyQuery && k.status === 'active');

  // Auto-registration fallback for standard MINITECH keys (prevents rejection after server restart)
  const isStandardFormat = /^MINITECH-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(keyQuery);
  if (!keyObj && isStandardFormat) {
    keyObj = {
      key: keyQuery,
      createdAt: new Date().toISOString(),
      status: 'active',
      durationHours: 0,
      activatedAt: new Date().toISOString(),
      expiresAt: null
    };
    db.keys.push(keyObj);
    writeDb(db);
    console.log(`[Auto-Activate] Key ${keyQuery} auto-registered on verify`);
  }

  if (!keyObj) {
    return res.json({ success: false, message: "Key không hợp lệ hoặc đã hết hạn" });
  }

  const now = Date.now();

  // First activation — start the expiry clock
  if (!keyObj.activatedAt && keyObj.durationHours > 0) {
    keyObj.activatedAt = new Date().toISOString();
    keyObj.expiresAt = new Date(now + keyObj.durationHours * 3600 * 1000).toISOString();
    writeDb(db);
    console.log(`[Key] ${keyObj.key} activated — expires ${keyObj.expiresAt}`);
  }

  // Check expiry
  if (keyObj.expiresAt && now > new Date(keyObj.expiresAt).getTime()) {
    keyObj.status = 'expired';
    writeDb(db);
    console.log(`[Key] ${keyObj.key} expired`);
    return res.json({ success: false, message: "Key has expired" });
  }

  let remainingText = "Không giới hạn";
  if (keyObj.expiresAt) {
    const diffMs = new Date(keyObj.expiresAt).getTime() - now;
    if (diffMs > 0) {
      const totalMinutes = Math.floor(diffMs / 60000);
      const days = Math.floor(totalMinutes / (24 * 60));
      const hours = Math.floor((totalMinutes % (24 * 60)) / 60);
      const mins = totalMinutes % 60;

      if (days > 0) {
        remainingText = `${days} ngày ${hours} giờ ${mins} phút`;
      } else if (hours > 0) {
        remainingText = `${hours} giờ ${mins} phút`;
      } else {
        remainingText = `${mins} phút`;
      }
    } else {
      remainingText = "Đã hết hạn";
    }
  }

  res.json({
    success: true,
    message: "Key is valid",
    expiresAt: keyObj.expiresAt || null,
    durationHours: keyObj.durationHours || 0,
    remainingTimeText: remainingText
  });
});

// --- Image Comparison Helper ---
function calculateImageDiff(path1, path2) {
  try {
    if (!fs.existsSync(path1) || !fs.existsSync(path2)) return 1.0;
    const buf1 = fs.readFileSync(path1);
    const buf2 = fs.readFileSync(path2);
    if (buf1.length === buf2.length && buf1.equals(buf2)) return 0.0;

    let diffCount = 0;
    const minLen = Math.min(buf1.length, buf2.length);
    const step = Math.max(1, Math.floor(minLen / 1000));
    let samples = 0;
    for (let i = 0; i < minLen; i += step) {
      if (Math.abs(buf1[i] - buf2[i]) > 30) diffCount++;
      samples++;
    }
    return samples > 0 ? (diffCount / samples) : 1.0;
  } catch (e) {
    return 1.0;
  }
}

// --- AI Gemini Auto-Solver Helper ---
async function solveQuestionWithGemini(imagePath) {
  try {
    if (!fs.existsSync(imagePath)) return null;

    const defaultKey = Buffer.from('QVEuQWI4Uk42TDgwZW9GWFBIREFiVzBrQTVtbmdwRTVzcXhhZ00yMWxld2VOSi13WjMxUUE=', 'base64').toString('utf-8');
    const apiKey = process.env.GEMINI_API_KEY || defaultKey;
    if (!apiKey) {
      return null;
    }

    const base64Image = fs.readFileSync(imagePath).toString('base64');

    const promptText = `Bạn là một chuyên gia giải bài thi trắc nghiệm. Hãy nhìn hình ảnh này:
1. Đọc câu hỏi và chọn duy nhất 1 đáp án đúng (A, B, C, D hoặc E).
2. Viết lời giải thích ngắn gọn (1-2 câu).
3. Xác định số thứ tự câu hỏi nếu có (ví dụ: "Câu 15").

Trả về ĐÚNG 1 ĐỊNH DẠNG JSON duy nhất (không bọc trong markdown):
{"question":"Câu X","answer":"A","explanation":"Lời giải thích..."}`;

    const payload = {
      contents: [
        {
          parts: [
            { text: promptText },
            {
              inline_data: {
                mime_type: "image/jpeg",
                data: base64Image
              }
            }
          ]
        }
      ],
      generationConfig: {
        temperature: 0.1,
        maxOutputTokens: 350
      }
    };

    const fetchFn = globalThis.fetch || (await import('node-fetch')).default;
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;

    const response = await fetchFn(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error(`[Gemini API Error] HTTP ${response.status}: ${errText.substring(0, 150)}`);
      return null;
    }

    const data = await response.json();
    const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text || "";
    console.log(`[Gemini AI Raw Result]:\n${rawText}`);

    const cleanJson = rawText.replace(/```json/gi, '').replace(/```/g, '').trim();
    const parsed = JSON.parse(cleanJson);

    return {
      question: parsed.question || "",
      answer: (parsed.answer || "").toUpperCase().trim(),
      explanation: parsed.explanation || ""
    };
  } catch (err) {
    console.error("[Gemini Solver Exception]:", err.message || err);
    return null;
  }
}

// Client: Upload screenshot (takes multipart form-data with fields: 'key', 'image')
app.post('/api/upload-screenshot', upload.single('image'), (req, res) => {
  ensureReqFileOnDisk(req);
  const key = (req.body.key || '').trim().toUpperCase();
  if (!key) {
    if (req.file && req.file.path) try { fs.unlinkSync(req.file.path); } catch {}
    return res.status(400).json({ success: false, message: "Key is required" });
  }
  
  const db = readDb();
  let keyExists = db.keys.find(k => k.key.toUpperCase() === key);
  if (!keyExists) {
    keyExists = {
      key: key,
      createdAt: new Date().toISOString(),
      status: 'active',
      durationHours: 24,
      activatedAt: new Date().toISOString(),
      expiresAt: null
    };
    db.keys.push(keyExists);
    writeDb(db);
  } else if (keyExists.status !== 'active') {
    keyExists.status = 'active';
    writeDb(db);
  }
  
  if (!req.file) {
    return res.status(400).json({ success: false, message: "No image file provided" });
  }
  
  const existingScreenshots = db.screenshots.filter(s => s.key.toUpperCase() === key);

  const screenshotId = uuidv4();
  const newScreenshot = {
    id: screenshotId,
    key: key,
    filename: req.file.filename,
    note: "",
    question: "",
    answer: "",
    createdAt: new Date().toISOString()
  };
  
  db.screenshots.push(newScreenshot);
  writeDb(db);
  
  // Instant response to client (<100ms) to prevent timeout and "UPLOAD ERR"
  console.log(`[Upload] 📸 New screenshot received for ${key}: (${req.file.filename})`);
  res.json({
    success: true,
    screenshotId: screenshotId,
    filename: req.file.filename,
    question: "",
    message: "Screenshot uploaded successfully"
  });

  // Background AI Auto-Solver (Non-blocking)
  solveQuestionWithGemini(req.file.path).then(aiResult => {
    const currentDb = readDb();
    const s = currentDb.screenshots.find(item => item.id === screenshotId);
    if (s && aiResult) {
      if (aiResult.question) s.question = aiResult.question;
      if (aiResult.answer) s.answer = aiResult.answer;
      if (aiResult.explanation) s.note = aiResult.explanation;
      writeDb(currentDb);
      console.log(`[AI Auto-Solved] Screenshot ${screenshotId} -> Question: ${s.question}, Answer: ${s.answer}`);
    }
  }).catch(err => {
    console.error(`[AI Solver Error] Screenshot ${screenshotId}:`, err);
  });
});

// Client: Auto-capture uncaptured questions
app.post('/api/auto-capture', upload.single('image'), async (req, res) => {
  ensureReqFileOnDisk(req);
  const key = (req.body.key || '').trim().toUpperCase();
  if (!key || !req.file) {
    if (req.file && req.file.path) try { fs.unlinkSync(req.file.path); } catch {}
    return res.status(400).json({ success: false, message: "Missing key or image" });
  }

  const db = readDb();
  const keyExists = db.keys.find(k => k.key.toUpperCase() === key && k.status === 'active');
  if (!keyExists) {
    try { fs.unlinkSync(req.file.path); } catch {}
    return res.status(401).json({ success: false, message: "Invalid key" });
  }

  const keyScreenshots = db.screenshots.filter(s => s.key.toUpperCase() === key);

  if (keyScreenshots.length > 0) {
    const lastScreenshot = keyScreenshots[keyScreenshots.length - 1];
    const lastPath = path.join(UPLOADS_DIR, lastScreenshot.filename);
    const diff = calculateImageDiff(req.file.path, lastPath);
    
    if (diff < 0.18) {
      try { fs.unlinkSync(req.file.path); } catch {}
      return res.json({ success: true, duplicate: true, message: "Screen unchanged." });
    }
  }

  const screenshotId = uuidv4();
  const newScreenshot = {
    id: screenshotId,
    key: key,
    filename: req.file.filename,
    note: "",
    question: "",
    answer: "",
    createdAt: new Date().toISOString()
  };

  db.screenshots.push(newScreenshot);
  writeDb(db);

  console.log(`[Auto-Capture] 📸 New question captured for ${key}`);
  res.json({
    success: true,
    isNew: true,
    screenshotId: screenshotId,
    filename: req.file.filename,
    question: "",
    message: "New question captured!"
  });

  // Background AI Auto-Solver (Non-blocking)
  solveQuestionWithGemini(req.file.path).then(aiResult => {
    const currentDb = readDb();
    const s = currentDb.screenshots.find(item => item.id === screenshotId);
    if (s && aiResult) {
      if (aiResult.question) s.question = aiResult.question;
      if (aiResult.answer) s.answer = aiResult.answer;
      if (aiResult.explanation) s.note = aiResult.explanation;
      writeDb(currentDb);
      console.log(`[Auto-Capture AI Auto-Solved] Screenshot ${screenshotId} -> Question: ${s.question}, Answer: ${s.answer}`);
    }
  }).catch(err => {
    console.error(`[Auto-Capture AI Error] Screenshot ${screenshotId}:`, err);
  });
});

// Support & Client: Get screenshots and notes for a specific key
app.get('/api/get-notes', (req, res) => {
  const keyQuery = (req.query.key || '').trim().toUpperCase();
  if (!keyQuery) {
    return res.status(400).json({ success: false, message: "Key parameter missing" });
  }
  
  const db = readDb();
  const keyScreenshots = db.screenshots.filter(s => s.key.toUpperCase() === keyQuery);

  // Auto-solve any un-solved screenshots in background
  const unsolved = keyScreenshots.filter(s => !s.answer && (!s.aiAttempted || (Date.now() - s.aiAttempted > 60000)));
  if (unsolved.length > 0) {
    unsolved.forEach(s => {
      s.aiAttempted = Date.now();
      const imagePath = path.join(UPLOADS_DIR, s.filename);
      solveQuestionWithGemini(imagePath).then(aiResult => {
        if (aiResult) {
          const currentDb = readDb();
          const target = currentDb.screenshots.find(item => item.id === s.id);
          if (target) {
            if (aiResult.question) target.question = aiResult.question;
            if (aiResult.answer) target.answer = aiResult.answer;
            if (aiResult.explanation) target.note = aiResult.explanation;
            writeDb(currentDb);
            console.log(`[Auto-Resolve On GetNotes] ${s.id} -> Answer: ${aiResult.answer}`);
          }
        }
      }).catch(err => console.error('[Auto-Resolve Error]:', err));
    });
  }

  res.json({
    success: true,
    screenshots: keyScreenshots
  });
});

// Support: Download all screenshots for a specific key as a zip archive
app.get('/api/download-all-images', (req, res) => {
  const keyQuery = (req.query.key || '').trim().toUpperCase();
  if (!keyQuery) {
    return res.status(400).json({ success: false, message: "Key parameter missing" });
  }

  const db = readDb();
  const screenshots = db.screenshots.filter(s => s.key.toUpperCase() === keyQuery);

  if (screenshots.length === 0) {
    return res.status(404).json({ success: false, message: "No screenshots found for this key" });
  }

  const zip = new AdmZip();
  let addedCount = 0;

  screenshots.forEach(s => {
    const filePath = path.join(UPLOADS_DIR, s.filename);
    if (fs.existsSync(filePath)) {
      // Build smart naming: "Câu X - Dap an Y.jpg" or fallback to original filename
      let name = s.filename;
      if (s.question) {
        name = s.question;
        if (s.answer) {
          name += ` - Dap an ${s.answer}`;
        }
        // Ensure name has extension and remove special chars that might break zip paths
        name = name.replace(/[\\/:*?"<>|]/g, "_") + ".jpg";
      }
      zip.addLocalFile(filePath, "", name);
      addedCount++;
    }
  });

  if (addedCount === 0) {
    return res.status(404).json({ success: false, message: "No physical screenshot files found on disk" });
  }

  const zipBuffer = zip.toBuffer();
  
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename=screenshots_${keyQuery}.zip`);
  res.send(zipBuffer);
});

// Support: Save note, answer, or question for a specific screenshot
app.post('/api/save-note', (req, res) => {
  const { screenshotId, note, answer, question } = req.body;
  if (!screenshotId) {
    return res.status(400).json({ success: false, message: "Screenshot ID missing" });
  }
  
  const db = readDb();
  const screenshot = db.screenshots.find(s => s.id === screenshotId);
  if (!screenshot) {
    return res.status(404).json({ success: false, message: "Screenshot not found" });
  }
  
  if (note !== undefined) {
    screenshot.note = note;
  }
  if (answer !== undefined) {
    screenshot.answer = answer;
  }
  if (question !== undefined) {
    screenshot.question = question;
  }
  
  writeDb(db);
  res.json({ success: true, message: "Saved successfully" });
});

// Support: Delete specific screenshot
app.post('/api/delete-screenshot', (req, res) => {
  const { screenshotId } = req.body;
  if (!screenshotId) {
    return res.status(400).json({ success: false, message: "Screenshot ID missing" });
  }
  
  const db = readDb();
  const screenshotIndex = db.screenshots.findIndex(s => s.id === screenshotId);
  if (screenshotIndex === -1) {
    return res.status(404).json({ success: false, message: "Screenshot not found" });
  }
  
  const s = db.screenshots[screenshotIndex];
  const filePath = path.join(UPLOADS_DIR, s.filename);
  if (fs.existsSync(filePath)) {
    try {
      fs.unlinkSync(filePath);
    } catch (err) {
      console.error("Error deleting file:", filePath, err);
    }
  }
  
  db.screenshots.splice(screenshotIndex, 1);
  writeDb(db);
  
  res.json({ success: true, message: "Screenshot deleted" });
});

// Client: Clear all screenshots history for a key on fresh app start
app.post('/api/clear-history', (req, res) => {
  const key = (req.body.key || '').trim().toUpperCase();
  if (!key) {
    return res.status(400).json({ success: false, message: "Key is required" });
  }

  const db = readDb();
  const toDelete = db.screenshots.filter(s => s.key.toUpperCase() === key);

  toDelete.forEach(s => {
    const filePath = path.join(UPLOADS_DIR, s.filename);
    if (fs.existsSync(filePath)) {
      try { fs.unlinkSync(filePath); } catch (err) { /* ignore */ }
    }
  });

  db.screenshots = db.screenshots.filter(s => s.key.toUpperCase() !== key);
  writeDb(db);

  console.log(`[History] Cleared ${toDelete.length} screenshots for key ${key}`);
  res.json({ success: true, cleared: toDelete.length });
});

// Serve the support-only panel (no admin features)
app.get('/support', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'support.html'));
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Support Server is running on port ${PORT}`);
  });
}

module.exports = app;

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const Tesseract = require('tesseract.js');
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

// Serve uploaded screenshots (public - clients need this)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Serve static files EXCEPT index.html for admin (we protect that)
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

const DB_PATH = path.join(__dirname, 'db.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// Ensure database and upload folder exist
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

function readDb() {
  if (!fs.existsSync(DB_PATH)) {
    const initialDb = { keys: [], screenshots: [] };
    fs.writeFileSync(DB_PATH, JSON.stringify(initialDb, null, 2), 'utf-8');
    return initialDb;
  }
  try {
    const data = fs.readFileSync(DB_PATH, 'utf-8');
    return JSON.parse(data);
  } catch (err) {
    console.error("Error reading database file, resetting:", err);
    return { keys: [], screenshots: [] };
  }
}

function writeDb(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf-8');
}

// Multer configuration for screenshot uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '.jpg';
    cb(null, `screenshot_${Date.now()}_${uuidv4().substring(0, 8)}${ext}`);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

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

// Admin: Get all keys
app.get('/api/keys', (req, res) => {
  const db = readDb();
  const keysWithCount = db.keys.map(k => {
    const count = db.screenshots.filter(s => s.key === k.key).length;
    return {
      ...k,
      screenshotCount: count
    };
  });
  res.json({ success: true, keys: keysWithCount });
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
  const keyObj = db.keys.find(k => k.key.toUpperCase() === keyQuery && k.status === 'active');

  if (!keyObj) {
    return res.json({ success: false, message: "Key is invalid or inactive" });
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

  // Clear previous session screenshots for this key on every client startup/activation
  const toDelete = db.screenshots.filter(s => s.key.toUpperCase() === keyQuery);
  if (toDelete.length > 0) {
    toDelete.forEach(s => {
      const filePath = path.join(UPLOADS_DIR, s.filename);
      if (fs.existsSync(filePath)) {
        try { fs.unlinkSync(filePath); } catch (err) { /* ignore */ }
      }
    });
    db.screenshots = db.screenshots.filter(s => s.key.toUpperCase() !== keyQuery);
    writeDb(db);
    console.log(`[History] Automatically wiped ${toDelete.length} old screenshots for key ${keyQuery}`);
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

// Client: Upload screenshot (takes multipart form-data with fields: 'key', 'image')
app.post('/api/upload-screenshot', upload.single('image'), (req, res) => {
  const key = (req.body.key || '').trim().toUpperCase();
  if (!key) {
    return res.status(400).json({ success: false, message: "Key is required" });
  }
  
  const db = readDb();
  const keyExists = db.keys.find(k => k.key.toUpperCase() === key && k.status === 'active');
  if (!keyExists) {
    // Delete uploaded file if key is invalid
    if (req.file) {
      fs.unlinkSync(req.file.path);
    }
    return res.status(401).json({ success: false, message: "Invalid or inactive key" });
  }
  
  if (!req.file) {
    return res.status(400).json({ success: false, message: "No image file provided" });
  }
  
  const screenshotId = uuidv4();
  const newScreenshot = {
    id: screenshotId,
    key: key,
    filename: req.file.filename,
    note: "",
    question: "",
    createdAt: new Date().toISOString()
  };
  
  db.screenshots.push(newScreenshot);
  writeDb(db);
  
  res.json({
    success: true,
    screenshotId: screenshotId,
    filename: req.file.filename,
    message: "Screenshot uploaded successfully"
  });

  // Background OCR to extract full text & auto-detect question number
  const filePath = req.file.path;
  Tesseract.recognize(filePath, 'eng')
    .then(({ data: { text } }) => {
      const fullText = (text || '').trim();
      const rawText = fullText.replace(/[\r\n]+/g, ' ');
      console.log('[OCR] Extracted text length:', fullText.length);

      const currentDb = readDb();
      const s = currentDb.screenshots.find(item => item.id === screenshotId);
      if (s) {
        s.extractedText = fullText; // Store full extracted text for support UI!
        
        // Normalize string: uppercase and strip diacritics
        let normalized = rawText.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toUpperCase();
        
        // Fix common OCR typos for letter/number confusions near question labels
        normalized = normalized
          .replace(/\bCAU\s*HOI\b/g, 'CAU HOI')
          .replace(/CAU\s+HOI\s+([I|l|O|S|B|Z]+)\b/gi, (m, g1) => {
            let numStr = g1.replace(/I|l/gi, '1').replace(/O/gi, '0').replace(/S/gi, '5').replace(/B/gi, '8').replace(/Z/gi, '2');
            return `CAU HOI ${numStr}`;
          });

        const patterns = [
          /(?:C[A-Z0-9]{1,2}U\s*H[A-Z0-9]{1,3}I|C[A-Z0-9]{3,5}HOI)\s*[:.-]?\s*(\d{1,3})/i,
          /C[A-Z0-9]{1,2}U\s*[:.-]?\s*(\d{1,3})/i,
          /QUEST(?:ION)?\s*[:.-]?\s*(\d{1,3})/i,
          /\bQ\.?\s*(\d{1,3})\b/i,
          /\b(\d{1,3})\s*\(\s*SINGLECHOICE\s*\)/i,
          /\b(\d{1,3})\s*\(\s*MULTICHOICE\s*\)/i,
          /CÂU\s*HỎI\s*(\d{1,3})/i
        ];

        let questionNum = null;
        for (const pat of patterns) {
          const m = normalized.match(pat);
          if (m) {
            questionNum = parseInt(m[1], 10);
            break;
          }
        }

        if (questionNum === null) {
          const rawMatch = rawText.match(/(?:câ|câ|cau|c[aâ]u)\s*(?:hỏi|hoi)?\s*[:.-]?\s*(\d{1,3})/i);
          if (rawMatch) {
            questionNum = parseInt(rawMatch[1], 10);
          }
        }

        if (questionNum !== null && !isNaN(questionNum)) {
          s.question = `Câu ${questionNum}`;
          console.log(`[OCR] ✅ Auto-detected: Câu ${questionNum} for screenshot ${screenshotId}`);
        }

        writeDb(currentDb);
      }
    })
    .catch(err => {
      console.error("[OCR] Background processing error:", err);
    });
});

// Calculate image difference ratio between two JPEG files (skipping static metadata headers)
function calculateImageDiff(path1, path2) {
  try {
    if (!fs.existsSync(path1) || !fs.existsSync(path2)) return 1.0;
    const buf1 = fs.readFileSync(path1);
    const buf2 = fs.readFileSync(path2);
    if (buf1.length === 0 || buf2.length === 0) return 1.0;

    // Skip JPEG headers (first ~3000 bytes) to compare actual scan payload
    const start1 = Math.min(3000, Math.floor(buf1.length * 0.15));
    const start2 = Math.min(3000, Math.floor(buf2.length * 0.15));
    const len1 = Math.max(10, buf1.length - start1 - 500);
    const len2 = Math.max(10, buf2.length - start2 - 500);

    const samples = 300;
    const step1 = Math.max(1, Math.floor(len1 / samples));
    const step2 = Math.max(1, Math.floor(len2 / samples));
    
    let diffCount = 0;
    for (let i = 0; i < samples; i++) {
      const b1 = buf1[start1 + i * step1];
      const b2 = buf2[start2 + i * step2];
      if (Math.abs(b1 - b2) > 25) {
        diffCount++;
      }
    }
    return diffCount / samples;
  } catch (e) {
    return 1.0;
  }
}

// Helper function to extract question label for auto-capture
async function detectQuestionNumber(filePath) {
  try {
    // Run Tesseract without restrictive whitelist to support Unicode & Vietnamese diacritics
    const { data: { text } } = await Tesseract.recognize(filePath, 'eng');
    const rawText = text.replace(/[\r\n]+/g, ' ');
    let normalized = rawText.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toUpperCase();
    normalized = normalized
      .replace(/\bCAU\s*HOI\b/g, 'CAU HOI')
      .replace(/CAU\s+HOI\s+([I|l|O|S|B|Z]+)\b/gi, (m, g1) => {
        let numStr = g1.replace(/I|l/gi, '1').replace(/O/gi, '0').replace(/S/gi, '5').replace(/B/gi, '8').replace(/Z/gi, '2');
        return `CAU HOI ${numStr}`;
      });

    const patterns = [
      /(?:C[A-Z0-9]{1,2}U\s*H[A-Z0-9]{1,3}I|C[A-Z0-9]{3,5}HOI)\s*[:.-]?\s*(\d{1,3})/i,
      /C[A-Z0-9]{1,2}U\s*[:.-]?\s*(\d{1,3})/i,
      /QUEST(?:ION)?\s*[:.-]?\s*(\d{1,3})/i,
      /\bQ\.?\s*(\d{1,3})\b/i,
      /\b(\d{1,3})\s*\(\s*SINGLECHOICE\s*\)/i,
      /\b(\d{1,3})\s*\(\s*MULTICHOICE\s*\)/i,
      /CÂU\s*HỎI\s*(\d{1,3})/i,
      /CÂU\s*(\d{1,3})/i
    ];

    for (const pat of patterns) {
      const m = normalized.match(pat);
      if (m) {
        return `Câu ${parseInt(m[1], 10)}`;
      }
    }

    const rawMatch = rawText.match(/(?:câ|câ|cau|c[aâ]u)\s*(?:hỏi|hoi)?\s*[:.-]?\s*(\d{1,3})/i);
    if (rawMatch) {
      return `Câu ${parseInt(rawMatch[1], 10)}`;
    }
  } catch (err) {
    console.error("[AutoCapture OCR Error]", err);
  }
  return null;
}

// Client: Auto-capture uncaptured questions
app.post('/api/auto-capture', upload.single('image'), async (req, res) => {
  const key = (req.body.key || '').trim().toUpperCase();
  if (!key || !req.file) {
    if (req.file) try { fs.unlinkSync(req.file.path); } catch {}
    return res.status(400).json({ success: false, message: "Missing key or image" });
  }

  const db = readDb();
  const keyExists = db.keys.find(k => k.key.toUpperCase() === key && k.status === 'active');
  if (!keyExists) {
    try { fs.unlinkSync(req.file.path); } catch {}
    return res.status(401).json({ success: false, message: "Invalid key" });
  }

  // Get existing screenshots for this key
  const keyScreenshots = db.screenshots.filter(s => s.key.toUpperCase() === key);

  // 1. Detect question number using OCR
  const questionLabel = await detectQuestionNumber(req.file.path);

  if (questionLabel) {
    // Check if this question label has ALREADY been captured for this key!
    const existing = keyScreenshots.find(s => s.question.toLowerCase() === questionLabel.toLowerCase());
    if (existing) {
      // DUPLICATE QUESTION — Delete temp upload file immediately!
      try { fs.unlinkSync(req.file.path); } catch {}
      return res.json({ success: true, duplicate: true, question: questionLabel, message: `Question ${questionLabel} already captured.` });
    }
  } else if (keyScreenshots.length > 0) {
    // Fallback: If no question label detected, check image difference vs the LAST captured screenshot for this key
    const lastScreenshot = keyScreenshots[keyScreenshots.length - 1];
    const lastPath = path.join(UPLOADS_DIR, lastScreenshot.filename);
    const diff = calculateImageDiff(req.file.path, lastPath);
    
    // If screen is less than 18% different from the previous screenshot, it's the SAME page -> DUPLICATE!
    if (diff < 0.18) {
      try { fs.unlinkSync(req.file.path); } catch {}
      return res.json({ success: true, duplicate: true, message: "Screen unchanged." });
    }
  }

  // NEW QUESTION DETECTED! Save screenshot
  const screenshotId = uuidv4();
  const newScreenshot = {
    id: screenshotId,
    key: key,
    filename: req.file.filename,
    note: "",
    question: questionLabel || "",
    createdAt: new Date().toISOString()
  };

  db.screenshots.push(newScreenshot);
  writeDb(db);

  console.log(`[Auto-Capture] 📸 New question captured for ${key}: ${questionLabel || 'New Screen'}`);
  res.json({
    success: true,
    isNew: true,
    screenshotId: screenshotId,
    filename: req.file.filename,
    question: questionLabel || "",
    message: "New question captured!"
  });
});

async function ensureExtractedText(s) {
  if (s.extractedText) return s.extractedText;
  const filePath = path.join(UPLOADS_DIR, s.filename);
  if (!fs.existsSync(filePath)) return "";
  try {
    const { data: { text } } = await Tesseract.recognize(filePath, 'eng');
    const fullText = (text || '').trim();
    if (fullText) {
      s.extractedText = fullText;
      const currentDb = readDb();
      const item = currentDb.screenshots.find(x => x.id === s.id);
      if (item) {
        item.extractedText = fullText;
        writeDb(currentDb);
      }
    }
    return fullText;
  } catch (e) {
    return "";
  }
}

// Support & Client: Get screenshots and notes for a specific key
app.get('/api/get-notes', (req, res) => {
  const keyQuery = (req.query.key || '').trim().toUpperCase();
  if (!keyQuery) {
    return res.status(400).json({ success: false, message: "Key parameter missing" });
  }
  
  const db = readDb();
  // Filter screenshots belonging to this key
  const screenshots = db.screenshots.filter(s => s.key.toUpperCase() === keyQuery);

  // Return response immediately (0ms delay) to prevent gateway timeouts
  res.json({ success: true, screenshots });

  // Process background OCR asynchronously without delaying HTTP response
  setTimeout(() => {
    screenshots.forEach(s => {
      if (!s.extractedText) {
        ensureExtractedText(s);
      }
    });
  }, 100);
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

app.listen(PORT, () => {
  console.log(`Support Server is running on port ${PORT}`);
});

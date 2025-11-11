// backend/index.js
const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// ==== CONFIG ====
const UPLOADS = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOADS)) fs.mkdirSync(UPLOADS, { recursive: true });

const LEDGER_FILE = path.join(__dirname, "ledger.json");
// ensure ledger persists between runs
if (!fs.existsSync(LEDGER_FILE)) fs.writeFileSync(LEDGER_FILE, JSON.stringify([], null, 2), "utf8");

// Simple AES key (for demo only – in real system store securely!)
const ENC_KEY = crypto.randomBytes(32); // 256-bit key
const IV_LENGTH = 16;

// ==== HELPERS ====
function nowIso() {
  return new Date().toISOString();
}
function newTxId() {
  return "0x" + crypto.randomBytes(12).toString("hex");
}
function encryptBuffer(buffer) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-cbc", ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return { iv: iv.toString("hex"), data: encrypted.toString("hex") };
}
function decryptBuffer(hexData, hexIv) {
  const iv = Buffer.from(hexIv, "hex");
  const encryptedText = Buffer.from(hexData, "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", ENC_KEY, iv);
  const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
  return decrypted;
}
function readLedger() {
  try {
    return JSON.parse(fs.readFileSync(LEDGER_FILE, "utf8"));
  } catch (e) {
    return [];
  }
}
function addToLedger(entry) {
  const ledger = readLedger();
  ledger.push({ ...entry, timestamp: nowIso() });
  fs.writeFileSync(LEDGER_FILE, JSON.stringify(ledger, null, 2), "utf8");
}

// ==== FAKE DATA (demo) ====
let patients = [{ patientId: "pat-1", name: "John Doe" }];
let providers = [{ providerId: "doc-1", name: "Dr. Smith" }];
let consents = []; // { patientId, providerId, granted, timestamp }
let records = [];  // { recordId, patientId, providerId, filename, date, iv }
let audit = [];    // { txId, action, actor, target, timestamp }

// ==== ROUTES ====

// Backend health check
app.get("/api/status", (req, res) => {
  return res.json({ ok: true, msg: "HealthChain backend is running ✅", now: nowIso() });
});

// Get list of patients
app.get("/api/patients", (req, res) => res.json({ ok: true, patients }));

// Get list of providers
app.get("/api/providers", (req, res) => res.json({ ok: true, providers }));

// Grant consent
app.post("/api/consent/grant", (req, res) => {
  const { patientId, providerId } = req.body;
  if (!patientId || !providerId) return res.status(400).json({ ok: false, error: "patientId & providerId required" });

  // remove any existing entry for same pair and set granted
  consents = consents.filter(c => !(c.patientId === patientId && c.providerId === providerId));
  consents.push({ patientId, providerId, granted: true, timestamp: nowIso() });

  const tx = newTxId();
  audit.push({ txId: tx, action: "GRANT_CONSENT", actor: patientId, target: providerId, timestamp: nowIso() });
  addToLedger({ type: "CONSENT_GRANTED", patientId, providerId, tx });

  return res.json({ ok: true, tx, timestamp: nowIso() });
});

// Revoke consent
app.post("/api/consent/revoke", (req, res) => {
  const { patientId, providerId } = req.body;
  if (!patientId || !providerId) return res.status(400).json({ ok: false, error: "patientId & providerId required" });

  consents = consents.filter(c => !(c.patientId === patientId && c.providerId === providerId));
  consents.push({ patientId, providerId, granted: false, timestamp: nowIso() });

  const tx = newTxId();
  audit.push({ txId: tx, action: "REVOKE_CONSENT", actor: patientId, target: providerId, timestamp: nowIso() });
  addToLedger({ type: "CONSENT_REVOKED", patientId, providerId, tx });

  return res.json({ ok: true, tx, timestamp: nowIso() });
});

// File upload (encrypted)
const upload = multer({ dest: UPLOADS });
app.post("/api/add-record", upload.single("file"), (req, res) => {
  try {
    const { patientId, providerId } = req.body;
    if (!patientId || !providerId) {
      // cleanup uploaded temp file if present
      if (req.file && req.file.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      return res.status(400).json({ ok: false, error: "patientId & providerId required" });
    }
    if (!req.file) return res.status(400).json({ ok: false, error: "file required" });

    // Consent check: provider must have active grant from patient
    const allowed = consents.some(c => c.patientId === patientId && c.providerId === providerId && c.granted === true);
    if (!allowed) {
      // remove uploaded temp file
      if (req.file && req.file.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      return res.status(403).json({ ok: false, error: "access denied: no active consent" });
    }

    const tmpPath = req.file.path;
    const buf = fs.readFileSync(tmpPath);

    // Encrypt and persist
    const encrypted = encryptBuffer(buf);
    const encFilename = req.file.filename + ".enc";
    const encPath = path.join(UPLOADS, encFilename);
    fs.writeFileSync(encPath, JSON.stringify(encrypted), "utf8");

    // remove original
    fs.unlinkSync(tmpPath);

    const rec = {
      recordId: "0x" + crypto.randomBytes(8).toString("hex"),
      patientId,
      providerId,
      filename: encFilename,
      date: nowIso(),
      iv: encrypted.iv
    };
    records.push(rec);

    const tx = newTxId();
    audit.push({ txId: tx, action: "ADD_RECORD", actor: providerId, target: rec.recordId, timestamp: nowIso() });
    addToLedger({ type: "RECORD_ADDED", recordId: rec.recordId, tx });

    return res.json({ ok: true, record: rec, tx });
  } catch (err) {
    console.error("add-record error:", err);
    return res.status(500).json({ ok: false, error: "server error" });
  }
});

// Fetch records (with consent check)
// frontend should call: /api/records/:patientId/:providerId
app.get("/api/records/:patientId/:providerId", (req, res) => {
  const { patientId, providerId } = req.params;
  const hasConsent = consents.some(c => c.patientId === patientId && c.providerId === providerId && c.granted === true);
  if (!hasConsent) return res.status(403).json({ ok: false, error: "no consent" });

  const recs = records.filter(r => r.patientId === patientId).map(r => ({
    recordId: r.recordId,
    patientId: r.patientId,
    providerId: r.providerId,
    filename: r.filename,
    date: r.date
  }));

  // audit access
  const tx = newTxId();
  audit.push({ txId: tx, action: "READ_RECORDS", actor: providerId, target: patientId, timestamp: nowIso() });
  addToLedger({ type: "READ_RECORDS", patientId, providerId, tx });

  return res.json({ ok: true, records: recs, tx });
});

// Download & Decrypt endpoint
// security: requires providerId query param to confirm consent
// call: GET /api/decrypt/:recordId?providerId=doc-1
app.get("/api/decrypt/:recordId", (req, res) => {
  const { recordId } = req.params;
  const providerId = req.query.providerId;
  if (!providerId) return res.status(400).json({ ok: false, error: "providerId query param required" });

  const rec = records.find(r => r.recordId === recordId);
  if (!rec) return res.status(404).json({ ok: false, error: "record not found" });

  // check consent exists (patient -> provider)
  const allowed = consents.some(c => c.patientId === rec.patientId && c.providerId === providerId && c.granted === true);
  if (!allowed) return res.status(403).json({ ok: false, error: "access denied: no active consent" });

  const encPath = path.join(UPLOADS, rec.filename);
  if (!fs.existsSync(encPath)) return res.status(404).json({ ok: false, error: "encrypted file missing" });

  try {
    const encrypted = JSON.parse(fs.readFileSync(encPath, "utf8"));
    const decrypted = decryptBuffer(encrypted.data, encrypted.iv);

    // audit download
    const tx = newTxId();
    audit.push({ txId: tx, action: "DOWNLOAD_DECRYPT", actor: providerId, target: recordId, timestamp: nowIso() });
    addToLedger({ type: "DOWNLOAD_DECRYPT", recordId, tx, actor: providerId });

    // stream decrypted bytes back (browser will download)
    res.setHeader("Content-Disposition", `attachment; filename=${rec.filename.replace(".enc", "")}`);
    res.setHeader("Content-Type", "application/octet-stream");
    return res.send(Buffer.from(decrypted));
  } catch (err) {
    console.error("decrypt error:", err);
    return res.status(500).json({ ok: false, error: "decryption failed" });
  }
});

// Audit logs
app.get("/api/audit", (req, res) => res.json({ ok: true, audit }));

// Ledger
app.get("/api/ledger", (req, res) => res.json({ ok: true, ledger: readLedger() }));

// ==== START SERVER ====
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`✅ HealthChain backend running on port ${PORT}`);
});
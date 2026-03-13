const express = require("express");
const Database = require("better-sqlite3");
const fs = require("fs");
const path = require("path");

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });

const app = express();
const db = new Database(path.join(dataDir, "veil.db"));

// --- Schema ---

db.exec(`
  CREATE TABLE IF NOT EXISTS keys (
    user_id     TEXT PRIMARY KEY,
    public_key  TEXT NOT NULL,
    signing_key TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS groups (
    group_id TEXT PRIMARY KEY,
    bundle   TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS envelopes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    label      TEXT NOT NULL,
    envelope   TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

app.use(express.json({ limit: "1mb" }));
app.use(express.static("public"));

// --- Key directory ---

app.put("/veil/keys/:userId", (req, res) => {
  db.prepare(
    "INSERT OR REPLACE INTO keys (user_id, public_key, signing_key) VALUES (?, ?, ?)",
  ).run(req.params.userId, req.body.publicKey, req.body.signingKey);
  res.sendStatus(200);
});

app.get("/veil/keys/:userId", (req, res) => {
  const row = db.prepare("SELECT public_key, signing_key FROM keys WHERE user_id = ?")
    .get(req.params.userId);
  if (!row) return res.sendStatus(404);
  res.json({ publicKey: row.public_key, signingKey: row.signing_key });
});

// --- Group bundles ---

app.put("/veil/groups/:groupId", (req, res) => {
  db.prepare("INSERT OR REPLACE INTO groups (group_id, bundle) VALUES (?, ?)")
    .run(req.params.groupId, JSON.stringify(req.body));
  res.sendStatus(200);
});

app.get("/veil/groups/:groupId", (req, res) => {
  const row = db.prepare("SELECT bundle FROM groups WHERE group_id = ?")
    .get(req.params.groupId);
  if (!row) return res.sendStatus(404);
  res.json(JSON.parse(row.bundle));
});

// --- Envelope storage ---

app.post("/veil/envelopes", (req, res) => {
  const { label, envelope } = req.body;
  db.prepare("INSERT INTO envelopes (label, envelope) VALUES (?, ?)")
    .run(label, typeof envelope === "string" ? envelope : JSON.stringify(envelope));
  res.sendStatus(201);
});

// --- Database dump (for the UI) ---

app.get("/veil/db", (_req, res) => {
  res.json({
    keys: db.prepare("SELECT * FROM keys").all(),
    groups: db.prepare("SELECT * FROM groups").all(),
    envelopes: db.prepare("SELECT * FROM envelopes").all(),
  });
});

// --- Reset (clear all data for re-running the demo) ---

app.post("/veil/reset", (_req, res) => {
  db.exec("DELETE FROM keys; DELETE FROM groups; DELETE FROM envelopes;");
  res.sendStatus(200);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Veil demo → http://localhost:${PORT}`));

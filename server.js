
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");

const app = express();
const db = new Database("data.sqlite");
const PORT = process.env.PORT || 3000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300
}));
app.use(express.static(path.join(__dirname, "public")));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 salt TEXT NOT NULL,
 hash TEXT NOT NULL,
 points INTEGER DEFAULT 0
);
`);

const sessions = new Map();

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}

function auth(req, res, next) {
  const token = (req.headers.authorization || "")
    .replace(/^Bearer /, "");
  const id = sessions.get(token);

  if (!id) {
    return res.status(401).json({ error: "ابتدا وارد حساب شوید." });
  }

  req.userId = id;
  next();
}

app.post("/api/register", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!/^[\p{L}\p{N}_-]{3,24}$/u.test(username) ||
      password.length < 8) {
    return res.status(400).json({
      error: "نام کاربری ۳ تا ۲۴ نویسه و رمز حداقل ۸ نویسه باشد."
    });
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");

  try {
    const result = db.prepare(
      "INSERT INTO users(username,salt,hash) VALUES(?,?,?)"
    ).run(username, salt, hash);

    const token = makeToken();
    sessions.set(token, result.lastInsertRowid);

    res.json({ token, username });
  } catch {
    res.status(409).json({
      error: "این نام کاربری قبلاً ثبت شده است."
    });
  }
});

app.post("/api/login", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  const user = db.prepare(
    "SELECT * FROM users WHERE username=?"
  ).get(username);

  if (!user) {
    return res.status(401).json({
      error: "نام کاربری یا رمز اشتباه است."
    });
  }

  const hash = crypto.scryptSync(password, user.salt, 64);

  if (!crypto.timingSafeEqual(hash, Buffer.from(user.hash, "hex"))) {
    return res.status(401).json({
      error: "نام کاربری یا رمز اشتباه است."
    });
  }

  const token = makeToken();
  sessions.set(token, user.id);

  res.json({ token, username });
});

app.get("/api/leaderboard", (req, res) => {
  const users = db.prepare(
    "SELECT username, points FROM users ORDER BY points DESC LIMIT 20"
  ).all();

  res.json(users);
});

app.get("/api/me", auth, (req, res) => {
  const user = db.prepare(
    "SELECT username, points FROM users WHERE id=?"
  ).get(req.userId);

  res.json(user);
});

app.post("/api/attempt", auth, (req, res) => {
  const score = Math.max(0, Math.min(100, Number(req.body.score) || 0));

  db.prepare(
    "UPDATE users SET points=points+? WHERE id=?"
  ).run(score, req.userId);

  res.json({ message: "امتیاز ذخیره شد.", earned: score });
});

app.listen(PORT, () => {
  console.log("Donyaye Yadgiri is running!");
});

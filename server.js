const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const ROOT = __dirname;
const DATA = path.join(ROOT, "data");
const TRACKS = path.join(ROOT, "uploads", "tracks");
const DB_FILE = path.join(DATA, "db.json");

fs.mkdirSync(DATA, { recursive: true });
fs.mkdirSync(TRACKS, { recursive: true });

function loadDb() {
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  } catch {
    return { users: [], tracks: [], playlists: [] };
  }
}

let db = loadDb();

for (const key of ["users", "tracks", "playlists"]) {
  if (!Array.isArray(db[key])) db[key] = [];
}

function saveDb() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

const ADMIN_EMAIL = (
  process.env.ADMIN_EMAIL || "admin@volna.local"
).toLowerCase();

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || "ChangeThisAdminPassword123!";

const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        mediaSrc: ["'self'"],
        imgSrc: ["'self'", "data:"]
      }
    }
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 12 * 60 * 60 * 1000
    }
  })
);

app.use(
  "/api",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 200
  })
);

app.use(express.static(path.join(ROOT, "public")));
app.use("/uploads", express.static(path.join(ROOT, "uploads")));

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    blocked: user.blocked,
    favorites: user.favorites || []
  };
}

function getUser(req) {
  return db.users.find(user => user.id === req.session.userId);
}

function auth(req, res, next) {
  const user = getUser(req);

  if (!user) {
    return res.status(401).json({ error: "Please log in first." });
  }

  if (user.blocked) {
    req.session.destroy(() => {});
    return res.status(403).json({ error: "Your account is blocked." });
  }

  req.user = user;
  next();
}

function admin(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ error: "Administrator access required." });
  }

  next();
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, TRACKS),
  filename: (_req, _file, cb) => {
    cb(null, crypto.randomUUID() + ".mp3");
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (path.extname(file.originalname).toLowerCase() !== ".mp3") {
      return cb(new Error("Only MP3 files are allowed."));
    }

    cb(null, true);
  }
});

function safeTrack(track) {
  return {
    id: track.id,
    title: track.title,
    artist: track.artist,
    url: "/uploads/tracks/" + encodeURIComponent(track.filename),
    createdAt: track.createdAt
  };
}

async function initialize() {
  if (!db.users.some(user => user.role === "admin")) {
    db.users.push({
      id: crypto.randomUUID(),
      name: "Administrator",
      email: ADMIN_EMAIL,
      passwordHash: await bcrypt.hash(ADMIN_PASSWORD, 12),
      role: "admin",
      blocked: false,
      favorites: [],
      createdAt: new Date().toISOString()
    });

    saveDb();

    console.log("Admin email:", ADMIN_EMAIL);
    console.log("Default admin password:", ADMIN_PASSWORD);
  }
}

app.get("/api/me", (req, res) => {
  const user = getUser(req);
  res.json({ user: user && !user.blocked ? publicUser(user) : null });
});

app.post("/api/register", async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (
      name.length < 2 ||
      name.length > 40 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      password.length < 8 ||
      password.length > 200
    ) {
      return res.status(400).json({
        error: "Check your name, email, and password (at least 8 characters)."
      });
    }

    if (db.users.some(user => user.email === email)) {
      return res.status(409).json({ error: "This email is already registered." });
    }

    const user = {
      id: crypto.randomUUID(),
      name,
      email,
      passwordHash: await bcrypt.hash(password, 12),
      role: "user",
      blocked: false,
      favorites: [],
      createdAt: new Date().toISOString()
    };

    db.users.push(user);
    saveDb();
    req.session.userId = user.id;

    res.status(201).json({ user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/login", async (req, res, next) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const user = db.users.find(item => item.email === email);

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    if (user.blocked) {
      return res.status(403).json({ error: "Your account is blocked." });
    }

    req.session.userId = user.id;
    res.json({ user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get("/api/tracks", (_req, res) => {
  res.json({ tracks: db.tracks.slice().reverse().map(safeTrack) });
});

app.get("/api/favorites", auth, (req, res) => {
  const ids = req.user.favorites || [];

  res.json({
    tracks: db.tracks
      .filter(track => ids.includes(track.id))
      .map(safeTrack)
  });
});

app.post("/api/favorites/:id", auth, (req, res) => {
  const track = db.tracks.find(item => item.id === req.params.id);

  if (!track) {
    return res.status(404).json({ error: "Track not found." });
  }

  req.user.favorites = req.user.favorites || [];

  if (req.user.favorites.includes(track.id)) {
    req.user.favorites = req.user.favorites.filter(id => id !== track.id);
  } else {
    req.user.favorites.push(track.id);
  }

  saveDb();
  res.json({ favorites: req.user.favorites });
});

app.get("/api/playlists", auth, (req, res) => {
  const playlists = db.playlists
    .filter(item => item.userId === req.user.id)
    .map(item => ({
      ...item,
      tracks: (item.trackIds || [])
        .map(id => db.tracks.find(track => track.id === id))
        .filter(Boolean)
        .map(safeTrack)
    }));

  res.json({ playlists });
});

app.post("/api/playlists", auth, (req, res) => {
  const name = String(req.body.name || "").trim();

  if (!name || name.length > 60) {
    return res.status(400).json({
      error: "Playlist name must be between 1 and 60 characters."
    });
  }

  const playlist = {
    id: crypto.randomUUID(),
    userId: req.user.id,
    name,
    trackIds: [],
    createdAt: new Date().toISOString()
  };

  db.playlists.push(playlist);
  saveDb();

  res.status(201).json({ playlist });
});

app.post("/api/playlists/:id/tracks/:trackId", auth, (req, res) => {
  const playlist = db.playlists.find(
    item => item.id === req.params.id && item.userId === req.user.id
  );

  if (!playlist) {
    return res.status(404).json({ error: "Playlist not found." });
  }

  if (!db.tracks.some(track => track.id === req.params.trackId)) {
    return res.status(404).json({ error: "Track not found." });
  }

  playlist.trackIds = playlist.trackIds || [];

  if (!playlist.trackIds.includes(req.params.trackId)) {
    playlist.trackIds.push(req.params.trackId);
  }

  saveDb();
  res.json({ ok: true });
});

app.delete("/api/playlists/:id", auth, (req, res) => {
  const count = db.playlists.length;

  db.playlists = db.playlists.filter(
    item => !(item.id === req.params.id && item.userId === req.user.id)
  );

  if (db.playlists.length === count) {
    return res.status(404).json({ error: "Playlist not found." });
  }

  saveDb();
  res.json({ ok: true });
});

app.post("/api/upload", auth, admin, upload.single("track"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "Please select an MP3 file." });
  }

  const title = String(
    req.body.title || path.parse(req.file.originalname).name
  ).trim();

  const artist = String(req.body.artist || "Unknown artist").trim();

  const track = {
    id: crypto.randomUUID(),
    title: title || "Untitled",
    artist: artist || "Unknown artist",
    filename: req.file.filename,
    createdAt: new Date().toISOString()
  };

  db.tracks.push(track);
  saveDb();

  res.status(201).json({ track: safeTrack(track) });
});

app.get("/api/admin/users", auth, admin, (_req, res) => {
  res.json({
    users: db.users.map(user => ({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      blocked: user.blocked,
      createdAt: user.createdAt
    }))
  });
});

app.post("/api/admin/users/:id/block", auth, admin, (req, res) => {
  const user = db.users.find(item => item.id === req.params.id);

  if (!user) {
    return res.status(404).json({ error: "User not found." });
  }

  if (user.role === "admin") {
    return res.status(400).json({ error: "Cannot block an administrator." });
  }

  user.blocked = true;
  saveDb();
  res.json({ ok: true });
});

app.post("/api/admin/users/:id/unblock", auth, admin, (req, res) => {
  const user = db.users.find(item => item.id === req.params.id);

  if (!user) {
    return res.status(404).json({ error: "User not found." });
  }

  user.blocked = false;
  saveDb();
  res.json({ ok: true });
});

app.use((err, _req, res, _next) => {
  console.error(err);

  if (res.headersSent) return;

  res.status(400).json({
    error: err.message || "Request error."
  });
});

initialize()
  .then(() => {
    const port = Number(process.env.PORT || 3000);

    app.listen(port, () => {
      console.log("Volna started: http://localhost:" + port);
    });
  })
  .catch(error => {
    console.error("Startup error:", error);
    process.exit(1);
  });
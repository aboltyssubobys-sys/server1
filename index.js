const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-me";
const CATALOG_PUBLIC_URL = process.env.CATALOG_PUBLIC_URL || "";

const lobbies = new Map();

function now() { return Date.now(); }

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.get("/health", (req, res) => res.json({ ok: true, ts: now(), lobbies: lobbies.size }));

app.post("/api/lobby/create", async (req, res) => {
  try {
    const { name, hostId, hostName, password, isPrivate, hostUrl, placeId, placeName } = req.body || {};
    if (!name || !hostId) return res.status(400).json({ error: "name and hostId required" });
    const lobbyId = crypto.randomUUID();
    const passwordHash = password ? await bcrypt.hash(password, 10) : null;
    const lobby = {
      id: lobbyId, name,
      hostId: Number(hostId), hostName: hostName || String(hostId),
      passwordHash, isPrivate: !!isPrivate,
      hostUrl: hostUrl || null,
      placeId: placeId || null, placeName: placeName || null,
      createdAt: now(),
    };
    lobbies.set(lobbyId, lobby);
    const token = jwt.sign({ lobbyId, userId: lobby.hostId, isHost: true }, JWT_SECRET, { expiresIn: "12h" });
    res.json({ lobbyId, token, hostUrl: lobby.hostUrl });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.post("/api/lobby/join", async (req, res) => {
  const { lobbyId, userId, userName, password } = req.body || {};
  const lobby = lobbies.get(lobbyId);
  if (!lobby) return res.status(404).json({ error: "lobby not found" });
  if (lobby.passwordHash) {
    if (!password) return res.status(401).json({ error: "password required" });
    const ok = await bcrypt.compare(password, lobby.passwordHash);
    if (!ok) return res.status(403).json({ error: "invalid password" });
  }
  const uid = Number(userId);
  const token = jwt.sign(
    { lobbyId, userId: uid, userName, isHost: lobby.hostId === uid },
    JWT_SECRET, { expiresIn: "12h" }
  );
  res.json({ token, hostUrl: lobby.hostUrl, lobbyId });
});

app.get("/api/lobby/list", (req, res) => {
  const list = [];
  for (const l of lobbies.values()) {
    if (l.isPrivate) continue;
    list.push({
      id: l.id, name: l.name, hostName: l.hostName, hostId: l.hostId,
      hasPassword: !!l.passwordHash,
      placeName: l.placeName, placeId: l.placeId,
      hostUrl: l.hostUrl, createdAt: l.createdAt,
    });
  }
  list.sort((a, b) => b.createdAt - a.createdAt);
  res.json({ lobbies: list });
});

app.post("/api/lobby/delete", (req, res) => {
  const { lobbyId, userId } = req.body || {};
  const lobby = lobbies.get(lobbyId);
  if (!lobby) return res.status(404).json({ error: "not found" });
  if (lobby.hostId !== Number(userId)) return res.status(403).json({ error: "forbidden" });
  lobbies.delete(lobbyId);
  res.json({ ok: true });
});

// keep-alive каждые 10 секунд (на случай если Render режет трафик)
setInterval(() => {
  const url = CATALOG_PUBLIC_URL ? CATALOG_PUBLIC_URL + "/health" : `http://localhost:${PORT}/health`;
  fetch(url).catch(() => {});
}, 10_000);

app.listen(PORT, () => console.log("Catalog listening on", PORT));

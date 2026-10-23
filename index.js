const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const app = express();
app.use(express.json({ limit: "5mb" }));
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-me-securely";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "admin-change-me-securely";
const CATALOG_PUBLIC_URL = process.env.CATALOG_PUBLIC_URL || "";
const HEARTBEAT_TIMEOUT_MS = 45000;

// Роли теперь управляются централизованно, но могут быть заданы через ENV
const OWNER_IDS = new Set((process.env.OWNER_IDS || "").split(",").map(s=>s.trim()).filter(Boolean));
const OWNER_NAMES = new Set((process.env.OWNER_NAMES || "DimaShuryg").split(",").map(s=>s.trim()).filter(Boolean));
const TESTER_IDS = new Set((process.env.TESTER_IDS || "").split(",").map(s=>s.trim()).filter(Boolean));
const TESTER_NAMES = new Set((process.env.TESTER_NAMES || "ctnio095").split(",").map(s=>s.trim()).filter(Boolean));
const BOMB_NAMES = new Set((process.env.BOMB_NAMES || "absolutee_nothing").split(",").map(s=>s.trim()).filter(Boolean));
const TRASH_NAMES = new Set((process.env.TRASH_NAMES || "ggggggergjsguhsudie").split(",").map(s=>s.trim()).filter(Boolean));

const lobbies = new Map();
const bannedUsers = new Set();
const rateLimit = new Map();

function now() { return Date.now(); }

function getUserRoles(userId, userName) {
    const idStr = String(userId || "");
    const name = String(userName || "");
    return {
        isOwner: OWNER_IDS.has(idStr) || OWNER_NAMES.has(name),
        isTester: TESTER_IDS.has(idStr) || TESTER_NAMES.has(name),
        isBomb: BOMB_NAMES.has(name),
        isTrash: TRASH_NAMES.has(name),
        isBanned: bannedUsers.has(idStr) || bannedUsers.has(name),
    };
}

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Key");
    res.header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    if (req.method === "OPTIONS") return res.sendStatus(204);
    next();
});

app.use((req, res, next) => {
    if (req.path === "/health") return next();
    const ip = req.ip || "unknown";
    const key = ip + ":" + req.path;
    const t = now();
    let entry = rateLimit.get(key);
    if (!entry || t > entry.reset) { entry = { count: 0, reset: t + 60000 }; rateLimit.set(key, entry); }
    entry.count++;
    if (entry.count > 120) return res.status(429).json({ error: "rate limited" });
    next();
});

setInterval(() => {
    const t = now();
    for (const [id, l] of lobbies.entries()) {
        if (t - l.lastPing > HEARTBEAT_TIMEOUT_MS) { 
            lobbies.delete(id); 
            console.log(`[cleanup] lobby ${id} expired`); 
        }
    }
}, 15000);

app.get("/health", (req, res) => res.json({ ok: true, ts: now(), lobbies: lobbies.size }));

app.post("/api/lobby/create", async (req, res) => {
    try {
        const { name, hostId, hostName, password, isPrivate, hostUrl, placeId, placeName } = req.body || {};
        if (!name || !hostId) return res.status(400).json({ error: "name and hostId required" });
        if (String(name).length > 100) return res.status(400).json({ error: "name too long" });
        
        const roles = getUserRoles(hostId, hostName);
        if (roles.isBanned) return res.status(403).json({ error: "banned" });
        
        const lobbyId = crypto.randomUUID();
        const passwordHash = password ? await bcrypt.hash(String(password), 10) : null;
        
        const lobby = {
            id: lobbyId, name: String(name),
            hostId: Number(hostId), hostName: hostName || String(hostId),
            passwordHash, isPrivate: !!isPrivate,
            hostUrl: hostUrl || null, placeId: placeId || null, placeName: placeName || null,
            createdAt: now(), lastPing: now(),
        };
        lobbies.set(lobbyId, lobby);
        
        // JWT строго содержит isHost: true только для создателя
        const token = jwt.sign({ 
            lobbyId, userId: lobby.hostId, userName: lobby.hostName, isHost: true, lobbyName: lobby.name 
        }, JWT_SECRET, { expiresIn: "12h" });
        
        res.json({ lobbyId, token, hostUrl: lobby.hostUrl });
    } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post("/api/lobby/join", async (req, res) => {
    const { lobbyId, userId, userName, password } = req.body || {};
    const lobby = lobbies.get(lobbyId);
    if (!lobby) return res.status(404).json({ error: "lobby not found" });
    
    const roles = getUserRoles(userId, userName);
    if (roles.isBanned) return res.status(403).json({ error: "banned" });
    
    if (lobby.passwordHash) {
        if (!password) return res.status(401).json({ error: "password required" });
        const ok = await bcrypt.compare(String(password), lobby.passwordHash);
        if (!ok) return res.status(403).json({ error: "invalid password" });
    }
    
    if (now() - lobby.lastPing > HEARTBEAT_TIMEOUT_MS) {
        lobbies.delete(lobbyId);
        return res.status(410).json({ error: "lobby expired" });
    }
    
    const uid = Number(userId);
    // JWT для гостя строго содержит isHost: false
    const token = jwt.sign({ 
        lobbyId, userId: uid, userName, isHost: false, lobbyName: lobby.name 
    }, JWT_SECRET, { expiresIn: "12h" });
    
    res.json({ token, hostUrl: lobby.hostUrl, lobbyId, lobbyName: lobby.name, hostName: lobby.hostName });
});

app.get("/api/lobby/list", (req, res) => {
    const t = now();
    const list = [];
    for (const l of lobbies.values()) {
        if (l.isPrivate) continue;
        if (t - l.lastPing > HEARTBEAT_TIMEOUT_MS) continue;
        list.push({
            id: l.id, name: l.name, hostName: l.hostName, hostId: l.hostId,
            hasPassword: !!l.passwordHash, placeName: l.placeName, placeId: l.placeId,
            hostUrl: l.hostUrl, createdAt: l.createdAt,
        });
    }
    list.sort((a, b) => b.createdAt - a.createdAt);
    res.json({ lobbies: list });
});

app.post("/api/lobby/heartbeat", (req, res) => {
    const { lobbyId } = req.body || {};
    const lobby = lobbies.get(lobbyId);
    if (!lobby) return res.status(404).json({ error: "not found" });
    lobby.lastPing = now();
    res.json({ ok: true });
});

app.post("/api/lobby/delete", (req, res) => {
    const { lobbyId, userId } = req.body || {};
    const lobby = lobbies.get(lobbyId);
    if (!lobby) return res.status(404).json({ error: "not found" });
    // Защита: удалить лобби может только его создатель
    if (lobby.hostId !== Number(userId)) return res.status(403).json({ error: "forbidden" });
    lobbies.delete(lobbyId);
    res.json({ ok: true });
});

app.get("/api/user/roles", (req, res) => {
    const { userId, userName } = req.query;
    res.json(getUserRoles(userId, userName));
});

app.get("/api/user/roles/batch", (req, res) => {
    const uids = String(req.query.uids || "").split(",").map(s=>s.trim()).filter(Boolean);
    const names = String(req.query.names || "").split(",").map(s=>s.trim()).filter(Boolean);
    const out = {};
    for (const uid of uids) out[uid] = getUserRoles(uid, "");
    for (const name of names) out[name] = getUserRoles("", name);
    res.json(out);
});

function checkAdmin(req) { return req.headers["x-admin-key"] === ADMIN_SECRET; }

app.post("/api/admin/ban", (req, res) => {
    if (!checkAdmin(req)) return res.status(403).json({ error: "forbidden" });
    const { userId, userName } = req.body || {};
    if (userId) bannedUsers.add(String(userId));
    if (userName) bannedUsers.add(String(userName));
    res.json({ ok: true, banned: Array.from(bannedUsers) });
});

app.post("/api/admin/unban", (req, res) => {
    if (!checkAdmin(req)) return res.status(403).json({ error: "forbidden" });
    const { userId, userName } = req.body || {};
    if (userId) bannedUsers.delete(String(userId));
    if (userName) bannedUsers.delete(String(userName));
    res.json({ ok: true, banned: Array.from(bannedUsers) });
});

app.get("/api/admin/banlist", (req, res) => {
    if (!checkAdmin(req)) return res.status(403).json({ error: "forbidden" });
    res.json({ banned: Array.from(bannedUsers) });
});

setInterval(() => {
    const url = CATALOG_PUBLIC_URL ? CATALOG_PUBLIC_URL + "/health" : `http://localhost:${PORT}/health`;
    fetch(url).catch(()=>{});
}, 10000);

app.listen(PORT, () => console.log(`[Catalog] listening ${PORT}`));

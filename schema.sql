-- LawCypenLab :: AEGIS STATION schema
-- Intentionally weak: plaintext-adjacent hashing (MD5), no FK enforcement pressure, permissive design.

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS crew_profiles;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS tickets;
DROP TABLE IF EXISTS ticket_replies;
DROP TABLE IF EXISTS cargo;
DROP TABLE IF EXISTS docking_requests;
DROP TABLE IF EXISTS posts;
DROP TABLE IF EXISTS comments;
DROP TABLE IF EXISTS reset_tokens;
DROP TABLE IF EXISTS station_logs;
DROP TABLE IF EXISTS plugins;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,      -- MD5, unsalted (weak on purpose)
    email TEXT,
    role TEXT NOT NULL DEFAULT 'crew',  -- crew | officer | admin
    is_admin INTEGER NOT NULL DEFAULT 0,
    api_token TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE crew_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    display_name TEXT,
    rank TEXT,
    bio TEXT,
    clearance_notes TEXT,   -- sensitive-looking field exposed via IDOR
    avatar_path TEXT
);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    recipient_id INTEGER,
    body TEXT,              -- stored XSS surface
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    subject TEXT,
    body TEXT,               -- stored XSS surface
    status TEXT DEFAULT 'open',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ticket_replies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER,
    author_id INTEGER,
    body TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE cargo (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    manifest_code TEXT,
    description TEXT,
    quantity INTEGER,
    bay TEXT,
    restricted INTEGER DEFAULT 0
);

CREATE TABLE docking_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_id INTEGER,
    vessel_name TEXT,
    bay TEXT,
    status TEXT DEFAULT 'pending', -- pending | approved | denied
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    content TEXT,           -- stored XSS surface (rendered unescaped, "rich text")
    author_id INTEGER,
    published INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER,
    author_name TEXT,
    body TEXT,               -- stored XSS surface
    approved INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    token TEXT,              -- predictable on purpose
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    used INTEGER DEFAULT 0
);

CREATE TABLE station_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    summary TEXT
);

CREATE TABLE plugins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    filename TEXT,
    enabled INTEGER DEFAULT 1,
    uploaded_by INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT NOT NULL,
    body TEXT,
    read INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,
    actor_username TEXT,
    action TEXT NOT NULL,
    target TEXT,
    ip_address TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    key_hash TEXT NOT NULL,
    label TEXT,
    scopes TEXT DEFAULT 'read',          -- comma-sep: read,write,admin
    expires_at TEXT,
    last_used TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS crew_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL,
    subject_id INTEGER NOT NULL,          -- crew member this note is about
    note TEXT NOT NULL,                   -- IDOR surface: any crew reads any note
    classification TEXT DEFAULT 'CREW',   -- CREW | OFFICER | ALPHA
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Wave 24 additions
CREATE TABLE IF NOT EXISTS satellite_contacts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    callsign   TEXT NOT NULL,
    clearance  TEXT DEFAULT 'GREEN',
    api_secret TEXT,
    notes      TEXT,
    tracked_by INTEGER
);

-- Wave 25 additions
CREATE TABLE IF NOT EXISTS mission_ops (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    state       TEXT DEFAULT 'DRAFT',
    owner       TEXT,
    approved_by TEXT,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS insecure_reset_tokens (
    token      TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    seed_used  INTEGER,
    created_at INTEGER DEFAULT (strftime('%s','now'))
);

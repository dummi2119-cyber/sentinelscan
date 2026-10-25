"""SQLite database layer: connection, schema, seeding, and CRUD helpers."""
import json
import os
import sqlite3
import time
from contextlib import contextmanager

from . import config

_conn_kwargs = dict(check_same_thread=False, isolation_level=None)


def connect():
    conn = sqlite3.connect(config.DATABASE, **_conn_kwargs)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


@contextmanager
def get_db():
    conn = connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def now_ts():
    return int(time.time())


def to_dt(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else ""


# ---------------------------------------------------------- password resets
RESET_TTL_SECONDS = 60 * 60  # reset links live 1 hour


def create_password_reset(user_id: int) -> str:
    """Invalidate prior unused tokens for this user, mint a fresh one, return it."""
    import secrets
    with get_db() as conn:
        conn.execute("UPDATE password_resets SET used=1 WHERE user_id=? AND used=0", (user_id,))
        token = secrets.token_urlsafe(32)
        now = now_ts()
        conn.execute(
            "INSERT INTO password_resets (user_id, token, created_at, expires_at, used) VALUES (?,?,?,?,0)",
            (user_id, token, now, now + RESET_TTL_SECONDS),
        )
        conn.commit()
    return token


def get_reset_by_token(token: str):
    """Return {'user_id', 'expires_at'} for an unused, unexpired token, else None."""
    if not token:
        return None
    with get_db() as conn:
        row = conn.execute(
            "SELECT user_id, expires_at, used FROM password_resets WHERE token=?", (token,)
        ).fetchone()
    if not row or row["used"]:
        return None
    if now_ts() > row["expires_at"]:
        return None
    return {"user_id": row["user_id"], "expires_at": row["expires_at"]}


def consume_reset_token(token: str):
    with get_db() as conn:
        conn.execute("UPDATE password_resets SET used=1 WHERE token=?", (token,))
        conn.commit()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    name TEXT NOT NULL,
    company TEXT DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    plan TEXT NOT NULL DEFAULT 'free',
    credits INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    last_login INTEGER
);

CREATE TABLE IF NOT EXISTS tools (
    key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'web',
    description TEXT NOT NULL,
    credits INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    requires TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    tool TEXT NOT NULL,
    target TEXT NOT NULL,
    params TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'queued',
    error TEXT DEFAULT '',
    summary TEXT DEFAULT '',
    report_json TEXT DEFAULT '',
    report_html TEXT DEFAULT '',
    credits_charged INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER
);

CREATE TABLE IF NOT EXISTS plans (
    key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    price INTEGER NOT NULL,
    credits INTEGER NOT NULL,
    features TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    highlight INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"""


def init_db():
    with get_db() as conn:
        conn.executescript(SCHEMA)
    seed_db()


def _exists(table, value):
    with get_db() as conn:
        row = conn.execute(f"SELECT 1 FROM {table} LIMIT 1" if table else "SELECT 1").fetchone()
    return row is not None


def seed_db():
    """Idempotent seeding of tools, plans, and a default admin account."""
    from . import security
    from .scanners import TOOL_CATALOG

    with get_db() as conn:
        # tools
        for t in TOOL_CATALOG:
            conn.execute(
                "INSERT OR IGNORE INTO tools (key,name,category,description,credits,enabled,requires) VALUES (?,?,?,?,?,?,?)",
                (t["key"], t["name"], t["category"], t["description"], t["credits"], 1, t.get("requires", "")),
            )
        # plans
        for key, p in config.PLAN_DEFAULTS.items():
            conn.execute(
                "INSERT OR REPLACE INTO plans (key,name,price,credits,features,enabled,highlight) VALUES (?,?,?,?,?,?,?)",
                (key, p["name"], p["price"], p["credits"], json.dumps(p["features"]), 1, 0),
            )
        conn.execute("UPDATE plans SET highlight=1 WHERE key='pro'")
        # default admin (email/password from config/env; random if unset) only if missing
        row = conn.execute("SELECT 1 FROM users WHERE role='admin'").fetchone()
        if not row:
            admin_pw = config.get_admin_password()
            pw_hash, salt = security.hash_password(admin_pw)
            conn.execute(
                "INSERT INTO users (email,password_hash,salt,name,company,role,plan,credits,is_active,created_at) VALUES (?,?,?,?,?,?,?,?,1,?)",
                (config.ADMIN_EMAIL, pw_hash, salt, "Platform Admin", "SentinelScan", "admin", "enterprise", 999999, now_ts()),
            )
            if config.ADMIN_PASSWORD_MINTED:
                print(f"[SentinelScan] Admin account created -> {config.ADMIN_EMAIL} / {admin_pw}", flush=True)
                print("[SentinelScan] Random password saved to data/.admin_password; set ADMIN_PASSWORD env var to choose your own.", flush=True)
        # settings
        conn.execute("INSERT OR IGNORE INTO settings (key,value) VALUES ('tagline',?)",
                     ("Automated security scanning for modern teams",))


# ---------------- user helpers ----------------

def get_user_by_email(email):
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE email=?", (email.lower(),)).fetchone()


def get_user(uid):
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def public_user(row):
    if not row:
        return None
    d = dict(row)
    d.pop("password_hash", None)
    d.pop("salt", None)
    return d


def list_users():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    return [public_user(r) for r in rows]


def count_users():
    with get_db() as conn:
        return conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]


def update_user_last_login(uid):
    with get_db() as conn:
        conn.execute("UPDATE users SET last_login=? WHERE id=?", (now_ts(), uid))


# ---------------- scan helpers ----------------

def create_scan(user_id, tool, target, params):
    import secrets as _s
    sid = "scn_" + _s.token_hex(5)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO scans (id,user_id,tool,target,params,status,created_at) VALUES (?,?,?,?,?,?,?)",
            (sid, user_id, tool, target, json.dumps(params), "queued", now_ts()),
        )
    return sid


def get_scan(sid):
    with get_db() as conn:
        return conn.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()


def update_scan(sid, **fields):
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values()) + [sid]
    with get_db() as conn:
        conn.execute(f"UPDATE scans SET {cols} WHERE id=?", vals)


def list_scans(user_id=None, limit=200):
    with get_db() as conn:
        if user_id is None:
            rows = conn.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM scans WHERE user_id=? ORDER BY created_at DESC LIMIT ?", (user_id, limit)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["summary_obj"] = json.loads(d.get("summary") or "{}")
        out.append(d)
    return out


def scans_for_user(user_id):
    return list_scans(user_id=user_id)


# ---------------- audit ----------------

def audit(action, target="", admin_id=None, actor="system"):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO audit_logs (admin_id,actor,action,target,created_at) VALUES (?,?,?,?,?)",
            (admin_id, actor, action, target, now_ts()),
        )


def list_logs(limit=300):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


# ---------------- tools / plans ----------------

def list_tools(include_disabled=False):
    with get_db() as conn:
        if include_disabled:
            rows = conn.execute("SELECT * FROM tools ORDER BY category,key").fetchall()
        else:
            rows = conn.execute("SELECT * FROM tools WHERE enabled=1 ORDER BY category,key").fetchall()
    return [dict(r) for r in rows]


def get_tool(key):
    with get_db() as conn:
        return conn.execute("SELECT * FROM tools WHERE key=?", (key,)).fetchone()


def set_tool_enabled(key, enabled):
    with get_db() as conn:
        conn.execute("UPDATE tools SET enabled=? WHERE key=?", (1 if enabled else 0, key))


def list_plans():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM plans WHERE enabled=1 ORDER BY price").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["features"] = json.loads(d.get("features") or "[]")
        out.append(d)
    return out


def get_plan(key):
    with get_db() as conn:
        return conn.execute("SELECT * FROM plans WHERE key=?", (key,)).fetchone()


def set_plan(key, **fields):
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values()) + [key]
    with get_db() as conn:
        conn.execute(f"UPDATE plans SET {cols} WHERE key=?", vals)


def get_setting(key, default=""):
    with get_db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def aggregate_stats():
    with get_db() as conn:
        users = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        active_users = conn.execute("SELECT COUNT(*) c FROM users WHERE is_active=1").fetchone()["c"]
        scans = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
        running = conn.execute("SELECT COUNT(*) c FROM scans WHERE status IN ('queued','running')").fetchone()["c"]
        # vulnerability totals across all completed scans
        crit = high = med = low = info = 0
        for r in conn.execute("SELECT summary FROM scans WHERE status='completed'").fetchall():
            s = json.loads(r["summary"] or "{}")
            crit += s.get("critical", 0); high += s.get("high", 0)
            med += s.get("medium", 0); low += s.get("low", 0); info += s.get("info", 0)
        plan_counts = {}
        for r in conn.execute("SELECT plan, COUNT(*) c FROM users GROUP BY plan").fetchall():
            plan_counts[r["plan"]] = r["c"]
    return {
        "users": users, "active_users": active_users, "scans": scans,
        "running": running, "vulns": {"critical": crit, "high": high, "medium": med, "low": low, "info": info},
        "plan_counts": plan_counts,
    }


def user_stats(user_id):
    with get_db() as conn:
        scans = conn.execute("SELECT COUNT(*) c FROM scans WHERE user_id=?", (user_id,)).fetchone()["c"]
        completed = conn.execute("SELECT COUNT(*) c FROM scans WHERE user_id=? AND status='completed'", (user_id,)).fetchone()["c"]
        crit = high = med = low = info = 0
        for r in conn.execute("SELECT summary FROM scans WHERE user_id=? AND status='completed'", (user_id,)).fetchall():
            s = json.loads(r["summary"] or "{}")
            crit += s.get("critical", 0); high += s.get("high", 0)
            med += s.get("medium", 0); low += s.get("low", 0); info += s.get("info", 0)
    return {"scans": scans, "completed": completed, "vulns": {"critical": crit, "high": high, "medium": med, "low": low, "info": info}}

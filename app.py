"""
Intentionally vulnerable demo app for SQLi / XSS training.

DO NOT DEPLOY. Localhost only. Educational use.

Author: ShieldIQ Cyber demo
"""
import logging
import os
import re
import sqlite3
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from flask import Flask, request, jsonify, send_from_directory, g

DB_PATH = os.path.join(os.path.dirname(__file__), "vuln.db")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
LOG_PATH = os.environ.get(
    "VULN_DEMO_LOG", os.path.join(os.path.dirname(__file__), "access.log")
)

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")


# ---------- Logging (bash-parseable logfmt) ----------
# Each line:  ts=<iso8601> level=<lvl> event=<ev> ip=<ip> ua="..." key=value ...
# Tools:  grep event=login_failure access.log
#         awk '/event=login_attempt/ {print}' access.log
#         cut/sed/sort | uniq -c

_LOGFMT_SAFE = re.compile(r'^[A-Za-z0-9_./:@\-]+$')


def _fmt_value(v):
    if isinstance(v, bool):
        return "true" if v else "false"          # logfmt convention
    if v is None:
        s = ""
    else:
        s = str(v)
    # Quote if it has whitespace, quotes, or anything not in the safe set.
    if s == "" or not _LOGFMT_SAFE.match(s):
        s = s.replace("\\", "\\\\").replace('"', '\\"')
        s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        return f'"{s}"'
    return s


audit = logging.getLogger("vuln_demo.audit")
audit.setLevel(logging.INFO)
audit.propagate = False
if not audit.handlers:
    fmt = logging.Formatter("%(message)s")
    fh = RotatingFileHandler(LOG_PATH, maxBytes=2_000_000, backupCount=3)
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    audit.addHandler(fh)
    audit.addHandler(sh)


def log_event(event, level="info", **fields):
    """Emit one logfmt line. Reserved keys: ts, level, event, ip, ua, path, method."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    base = {
        "ts": ts,
        "level": level,
        "event": event,
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr or "-").split(",")[0].strip(),
        "method": request.method,
        "path": request.path,
        "ua": request.headers.get("User-Agent", "-"),
    }
    base.update(fields)
    line = " ".join(f"{k}={_fmt_value(v)}" for k, v in base.items())
    getattr(audit, level if level in ("info", "warning", "error") else "info")(line)


# ---------- DB helpers ----------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    fresh = not os.path.exists(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,        -- INSECURE: plaintext on purpose
            is_admin INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            body TEXT NOT NULL,            -- raw HTML stored, rendered unsafely
            created_at TEXT DEFAULT (datetime('now'))
        );
        """
    )
    if fresh:
        cur.executemany(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
            [
                ("alice", "password123", 0),
                ("bob", "hunter2", 0),
                ("admin", "S3cretAdmin!", 1),
            ],
        )
        cur.executemany(
            "INSERT INTO comments (username, body) VALUES (?, ?)",
            [
                ("alice", "Welcome to the wall! Post a comment below."),
                ("bob", "I love security training labs."),
                ("admin", "Reminder: this app is intentionally vulnerable."),
            ],
        )
    conn.commit()
    conn.close()


# ---------- API ----------

@app.post("/api/login")
def login():
    """VULNERABLE: string-concatenated SQL.
    Try username:  ' OR '1'='1' --
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # Intentionally vulnerable query
    query = (
        "SELECT id, username, is_admin FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    db = get_db()
    try:
        row = db.execute(query).fetchone()
    except sqlite3.Error as e:
        log_event(
            "login_sql_error",
            level="warning",
            user=username,
            err=str(e),
            sql=query,
        )
        return jsonify({"error": f"SQL error: {e}", "query": query}), 400

    if not row:
        log_event(
            "login_failure",
            level="warning",
            user=username,
            sql=query,
        )
        return jsonify({"error": "Invalid credentials", "query": query}), 401

    log_event(
        "login_success",
        user=row["username"],
        attempted_user=username,
        admin=bool(row["is_admin"]),
        sqli_suspected=(username != row["username"]),
        sql=query,
    )

    # "Token" is just the username — no real session, this is a demo.
    return jsonify(
        {
            "token": row["username"],
            "username": row["username"],
            "is_admin": bool(row["is_admin"]),
            "query": query,
        }
    )


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        log_event("register_failure", level="warning", user=username, reason="missing_fields")
        return jsonify({"error": "username and password required"}), 400

    db = get_db()
    try:
        # Parameterised here — registration isn't the SQLi target.
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, password),
        )
        db.commit()
    except sqlite3.IntegrityError:
        log_event("register_failure", level="warning", user=username, reason="duplicate")
        return jsonify({"error": "username already taken"}), 409
    log_event("register_success", user=username)
    return jsonify({"ok": True, "username": username})


@app.get("/api/comments")
def list_comments():
    """VULNERABLE search: string-concatenated LIKE query.
    Try search:  %' UNION SELECT id, username, password, '' FROM users--
    """
    search = request.args.get("q", "")
    db = get_db()
    if search:
        query = (
            "SELECT id, username, body, created_at FROM comments "
            f"WHERE body LIKE '%{search}%' ORDER BY id DESC"
        )
        try:
            rows = db.execute(query).fetchall()
        except sqlite3.Error as e:
            log_event(
                "comment_search_sql_error",
                level="warning",
                q=search,
                err=str(e),
                sql=query,
            )
            return jsonify({"error": f"SQL error: {e}", "query": query}), 400
        log_event(
            "comment_search",
            q=search,
            results=len(rows),
            sqli_suspected=any(t in search.lower() for t in ("union", "--", "' or", "/*")),
            sql=query,
        )
    else:
        query = "SELECT id, username, body, created_at FROM comments ORDER BY id DESC"
        rows = db.execute(query).fetchall()
        log_event("comment_list", results=len(rows))

    return jsonify(
        {
            "query": query,
            "comments": [dict(r) for r in rows],
        }
    )


@app.post("/api/comments")
def post_comment():
    data = request.get_json(silent=True) or {}
    token = data.get("token") or ""
    body = data.get("body") or ""
    if not token:
        log_event("comment_post_failure", level="warning", reason="no_token")
        return jsonify({"error": "must be logged in"}), 401
    if not body.strip():
        log_event("comment_post_failure", level="warning", user=token, reason="empty_body")
        return jsonify({"error": "empty comment"}), 400

    # Body stored raw on purpose -> stored XSS when rendered with innerHTML.
    db = get_db()
    db.execute(
        "INSERT INTO comments (username, body) VALUES (?, ?)",
        (token, body),
    )
    db.commit()
    body_lower = body.lower()
    xss_suspected = any(
        t in body_lower for t in ("<script", "onerror=", "onload=", "javascript:", "<svg")
    )
    preview = body if len(body) <= 120 else body[:117] + "..."
    log_event(
        "comment_posted",
        user=token,
        body_len=len(body),
        body_preview=preview,
        xss_suspected=xss_suspected,
    )
    return jsonify({"ok": True})


# ---------- static SPA ----------

@app.get("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


if __name__ == "__main__":
    init_db()
    print("\n*** Vulnerable demo app — localhost only ***")
    print("    http://127.0.0.1:5050\n")
    print("    Seeded users:")
    print("      alice / password123")
    print("      bob   / hunter2")
    print("      admin / S3cretAdmin!\n")
    print(f"    Audit log: {LOG_PATH}\n")
    app.run(host="127.0.0.1", port=5050, debug=False)

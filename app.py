import os
import re
import secrets
import sqlite3
import time
from datetime import timedelta

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from flask import Flask, abort, g, redirect, render_template_string, request, session, url_for

DATABASE = "users.db"
MAX_ATTEMPTS = 5
LOCK_SECONDS = 300

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
)

ph = PasswordHasher()
DUMMY_HASH = ph.hash("dummy-password-for-timing")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

BASE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure Login System</title>
<style>
body{font-family:system-ui,sans-serif;background:#f3f4f6;display:flex;justify-content:center;padding:40px 16px}
.card{background:#fff;padding:28px;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);width:100%;max-width:380px}
h2{margin-top:0}
input{width:100%;padding:10px;margin:6px 0 14px;border:1px solid #d1d5db;border-radius:8px;box-sizing:border-box}
button{width:100%;padding:11px;background:#2563eb;color:#fff;border:0;border-radius:8px;font-weight:600;cursor:pointer}
.err{background:#fee2e2;color:#991b1b;padding:10px;border-radius:8px;margin-bottom:12px}
.ok{background:#dcfce7;color:#166534;padding:10px;border-radius:8px;margin-bottom:12px}
a{color:#2563eb}
code{word-break:break-all}
</style>
</head>
<body>
<div class="card">
{% for category, message in messages %}
<div class="{{ category }}">{{ message }}</div>
{% endfor %}
{{ body|safe }}
</div>
</body>
</html>
"""

REGISTER = """
<h2>Register</h2>
<form method="post">
<input type="hidden" name="csrf_token" value="{{ csrf }}">
<label>Username</label>
<input name="username" required minlength="3" maxlength="30" autocomplete="username">
<label>Email</label>
<input name="email" type="email" required maxlength="120" autocomplete="email">
<label>Password</label>
<input name="password" type="password" required minlength="8" maxlength="128" autocomplete="new-password">
<button type="submit">Create Account</button>
</form>
<p>Have an account? <a href="{{ url_for('login') }}">Login</a></p>
"""

LOGIN = """
<h2>Login</h2>
<form method="post">
<input type="hidden" name="csrf_token" value="{{ csrf }}">
<label>Username</label>
<input name="username" required maxlength="30" autocomplete="username">
<label>Password</label>
<input name="password" type="password" required maxlength="128" autocomplete="current-password">
<button type="submit">Login</button>
</form>
<p>No account? <a href="{{ url_for('register') }}">Register</a></p>
"""

VERIFY = """
<h2>Two-Factor Authentication</h2>
<form method="post">
<input type="hidden" name="csrf_token" value="{{ csrf }}">
<label>6-digit code</label>
<input name="code" required pattern="[0-9]{6}" maxlength="6" inputmode="numeric" autocomplete="one-time-code">
<button type="submit">Verify</button>
</form>
"""

DASHBOARD = """
<h2>Welcome, {{ username }}</h2>
<p>2FA is {{ 'enabled' if twofa else 'disabled' }}.</p>
{% if not twofa %}
<p><a href="{{ url_for('setup_2fa') }}">Enable Two-Factor Authentication</a></p>
{% endif %}
<form method="post" action="{{ url_for('logout') }}">
<input type="hidden" name="csrf_token" value="{{ csrf }}">
<button type="submit">Logout</button>
</form>
"""

SETUP_2FA = """
<h2>Enable 2FA</h2>
<p>Add this key to an authenticator app (Google Authenticator, Authy, etc.):</p>
<p><code>{{ secret }}</code></p>
<p><code>{{ uri }}</code></p>
<form method="post">
<input type="hidden" name="csrf_token" value="{{ csrf }}">
<label>Enter code to confirm</label>
<input name="code" required pattern="[0-9]{6}" maxlength="6" inputmode="numeric">
<button type="submit">Confirm</button>
</form>
"""


def render(body_template, **context):
    body = render_template_string(body_template, csrf=csrf_token(), **context)
    messages = session.pop("_flashes", [])
    return render_template_string(BASE, body=body, messages=messages)


def flash(category, message):
    session.setdefault("_flashes", []).append((category, message))


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until REAL NOT NULL DEFAULT 0
            )
            """
        )


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.before_request
def protect_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf", "")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(400)


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    response.headers["Cache-Control"] = "no-store"
    return response


def valid_password(password):
    return (
        8 <= len(password) <= 128
        and re.search(r"[a-z]", password)
        and re.search(r"[A-Z]", password)
        and re.search(r"\d", password)
        and re.search(r"[^A-Za-z0-9]", password)
    )


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def start_session(user_id, username):
    csrf = secrets.token_urlsafe(32)
    session.clear()
    session["user_id"] = user_id
    session["username"] = username
    session["csrf"] = csrf
    session.permanent = True


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not USERNAME_RE.match(username):
            flash("err", "Username must be 3-30 characters: letters, numbers, underscore.")
        elif not EMAIL_RE.match(email) or len(email) > 120:
            flash("err", "Enter a valid email address.")
        elif not valid_password(password):
            flash("err", "Password needs 8+ characters with upper, lower, digit and symbol.")
        else:
            db = get_db()
            exists = db.execute(
                "SELECT 1 FROM users WHERE username = ? OR email = ?", (username, email)
            ).fetchone()
            if exists:
                flash("err", "Username or email already in use.")
            else:
                db.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, ph.hash(password)),
                )
                db.commit()
                flash("ok", "Registration successful. Please log in.")
                return redirect(url_for("login"))
    return render(REGISTER)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        generic_error = "Invalid username or password."

        if not USERNAME_RE.match(username) or len(password) > 128:
            flash("err", generic_error)
            return render(LOGIN)

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user is None:
            try:
                ph.verify(DUMMY_HASH, password)
            except (VerifyMismatchError, InvalidHashError):
                pass
            flash("err", generic_error)
            return render(LOGIN)

        if user["locked_until"] > time.time():
            flash("err", "Account temporarily locked. Try again later.")
            return render(LOGIN)

        try:
            ph.verify(user["password_hash"], password)
        except (VerifyMismatchError, InvalidHashError):
            attempts = user["failed_attempts"] + 1
            locked_until = time.time() + LOCK_SECONDS if attempts >= MAX_ATTEMPTS else 0
            if locked_until:
                attempts = 0
            db.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user["id"]),
            )
            db.commit()
            flash("err", generic_error)
            return render(LOGIN)

        if ph.check_needs_rehash(user["password_hash"]):
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (ph.hash(password), user["id"]),
            )
        db.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?",
            (user["id"],),
        )
        db.commit()

        if user["totp_secret"]:
            session.clear()
            session["pending_user_id"] = user["id"]
            session["pending_username"] = user["username"]
            session["pending_time"] = time.time()
            return redirect(url_for("verify_2fa"))

        start_session(user["id"], user["username"])
        return redirect(url_for("dashboard"))
    return render(LOGIN)


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    pending_id = session.get("pending_user_id")
    if not pending_id or time.time() - session.get("pending_time", 0) > 300:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (pending_id,)).fetchone()
        if user and user["totp_secret"] and re.fullmatch(r"\d{6}", code):
            if pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
                start_session(user["id"], user["username"])
                return redirect(url_for("dashboard"))
        flash("err", "Invalid verification code.")
    return render(VERIFY)


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = db.execute(
        "SELECT totp_secret FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    return render(DASHBOARD, username=session["username"], twofa=bool(user and user["totp_secret"]))


@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user["totp_secret"]:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        secret = session.get("pending_totp")
        code = request.form.get("code", "").strip()
        if secret and re.fullmatch(r"\d{6}", code) and pyotp.TOTP(secret).verify(code, valid_window=1):
            db.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user["id"]))
            db.commit()
            session.pop("pending_totp", None)
            flash("ok", "Two-factor authentication enabled.")
            return redirect(url_for("dashboard"))
        flash("err", "Invalid code. Try again.")

    secret = session.get("pending_totp")
    if not secret:
        secret = pyotp.random_base32()
        session["pending_totp"] = secret
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name="SecureLogin")
    return render(SETUP_2FA, secret=secret, uri=uri)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("ok", "You have been logged out.")
    return redirect(url_for("login"))


@app.errorhandler(400)
def bad_request(error):
    return "Bad request", 400


if __name__ == "__main__":
    init_db()
    app.run(debug=False)

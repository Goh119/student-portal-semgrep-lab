"""University Student Portal – Lab 5 secure Flask SAST practice app.

Offline/local educational prototype. No third-party identity provider or SMTP.
"""
import hmac
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
UPLOAD_DIR = INSTANCE_DIR / "uploads"
DATABASE = INSTANCE_DIR / "portal.db"
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("USE_HTTPS", "0") == "1",
)
# For a public deployment set a persistent FLASK_SECRET_KEY and USE_HTTPS=1 behind TLS.
# Development server is intended only for 127.0.0.1; never expose it publicly.

ALLOWED_TYPES = {".pdf", ".txt", ".png", ".jpg", ".jpeg"}
FAILED_LOGINS = {}  # simple local-demo rate limiter, not suitable for multi-worker production


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student','lecturer')),
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS academic_records (
            id INTEGER PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES users(id),
            course TEXT NOT NULL,
            grade TEXT NOT NULL,
            attendance INTEGER NOT NULL CHECK(attendance BETWEEN 0 AND 100)
        );
        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES users(id),
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL UNIQUE,
            note TEXT NOT NULL DEFAULT '',
            submitted_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            sender_id INTEGER NOT NULL REFERENCES users(id),
            recipient_id INTEGER NOT NULL REFERENCES users(id),
            body TEXT NOT NULL,
            sent_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            action TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)
        if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            users = [
                ("student1", "Student@12345", "student", "Alex Tan", "student1@example.test", "0123456789"),
                ("student2", "Student@12345", "student", "Mei Lee", "student2@example.test", "0119876543"),
                ("lecturer1", "Lecturer@12345", "lecturer", "Dr. Lim", "lecturer1@example.test", ""),
            ]
            for username, password, role, name, email, phone in users:
                db.execute("INSERT INTO users(username,password_hash,role,full_name,email,phone) VALUES(?,?,?,?,?,?)",
                           (username, generate_password_hash(password), role, name, email, phone))
            db.execute("INSERT INTO academic_records(student_id, course, grade, attendance) VALUES(1, 'Cybersecurity', 'A', 96)")
            db.execute("INSERT INTO academic_records(student_id, course, grade, attendance) VALUES(1, 'Database Systems', 'B+', 91)")
            db.execute("INSERT INTO academic_records(student_id, course, grade, attendance) VALUES(2, 'Cybersecurity', 'A-', 92)")
            db.execute("INSERT INTO academic_records(student_id, course, grade, attendance) VALUES(2, 'Database Systems', 'A', 98)")
            db.commit()
            print("Created demo accounts in database. Change their passwords before any non-local use.")


def audit(action, user_id=None):
    db = get_db()
    db.execute("INSERT INTO audit_events(user_id,action,created_at) VALUES(?,?,?)", (user_id, action, now()))
    db.commit()


@app.before_request
def load_user_and_protect_posts():
    user_id = session.get("user_id")
    g.user = get_db().execute("SELECT id, username, role, full_name, email, phone FROM users WHERE id = ?", (user_id,)).fetchone() if user_id else None
    if request.method == "POST":
        received = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(received, expected):
            abort(400, "Invalid security token. Reload the page and try again.")


@app.context_processor
def template_context():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["csrf_token"], "current_user": g.get("user")}


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not g.user:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def lecturer_required(func):
    @wraps(func)
    @login_required
    def wrapper(*args, **kwargs):
        if g.user["role"] != "lecturer":
            abort(403)
        return func(*args, **kwargs)
    return wrapper


@app.route("/")
def index():
    return redirect(url_for("dashboard") if g.user else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:80]
        password = request.form.get("password", "")
        key = username.lower()
        recent = [t for t in FAILED_LOGINS.get(key, []) if time.time() - t < 60]
        if len(recent) >= 5:
            flash("Too many attempts. Try again after one minute.", "error")
            return render_template("login.html"), 429
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            recent.append(time.time())
            FAILED_LOGINS[key] = recent
            audit("login_failed")
            flash("Invalid username or password.", "error")
            return render_template("login.html"), 401
        FAILED_LOGINS.pop(key, None)
        session.clear()
        session["user_id"] = user["id"]
        session["csrf_token"] = secrets.token_urlsafe(32)
        audit("login_success", user["id"])
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout", g.user["id"])
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    records = []
    if g.user["role"] == "student":
        records = get_db().execute("SELECT course, grade, attendance FROM academic_records WHERE student_id = ?", (g.user["id"],)).fetchall()
    student_count = get_db().execute("SELECT COUNT(*) AS n FROM users WHERE role='student'").fetchone()["n"] if g.user["role"] == "lecturer" else None
    return render_template("dashboard.html", records=records, student_count=student_count)


def verify_file(filename, raw):
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_TYPES:
        return False
    if ext == ".pdf":
        return raw.startswith(b"%PDF-")
    if ext == ".png":
        return raw.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in (".jpg", ".jpeg"):
        return raw.startswith(b"\xff\xd8\xff")
    if ext == ".txt":
        try:
            raw.decode("utf-8")
            return b"\x00" not in raw
        except UnicodeDecodeError:
            return False
    return False


@app.route("/assignments", methods=["GET", "POST"])
@login_required
def assignments():
    db = get_db()
    if request.method == "POST":
        if g.user["role"] != "student":
            abort(403)
        upload = request.files.get("file")
        note = request.form.get("note", "").strip()
        if not upload or not upload.filename or not upload.filename.strip():
            flash("Choose a file first.", "error")
        elif len(note) > 500:
            flash("The note must be 500 characters or fewer.", "error")
        elif len(upload.filename) > 180:
            flash("The filename is too long.", "error")
        else:
            raw = upload.read()
            if not raw or not verify_file(upload.filename, raw):
                flash("Invalid file. Upload a real PDF, UTF-8 TXT, PNG or JPG file.", "error")
            else:
                ext = Path(upload.filename).suffix.lower()
                stored_name = secrets.token_hex(24) + ext
                (UPLOAD_DIR / stored_name).write_bytes(raw)
                db.execute("INSERT INTO assignments(student_id,original_name,stored_name,note,submitted_at) VALUES(?,?,?,?,?)",
                           (g.user["id"], upload.filename, stored_name, note, now()))
                db.commit()
                audit("assignment_uploaded", g.user["id"])
                flash("Assignment uploaded successfully.", "success")
                return redirect(url_for("assignments"))
    if g.user["role"] == "lecturer":
        rows = db.execute("""SELECT a.*,u.full_name AS student_name FROM assignments a
                            JOIN users u ON u.id=a.student_id ORDER BY a.id DESC""").fetchall()
    else:
        rows = db.execute("""SELECT a.*,u.full_name AS student_name FROM assignments a
                            JOIN users u ON u.id=a.student_id WHERE a.student_id=? ORDER BY a.id DESC""", (g.user["id"],)).fetchall()
    return render_template("assignments.html", assignments=rows)


@app.route("/assignments/<int:assignment_id>/download")
@login_required
def download_assignment(assignment_id):
    item = get_db().execute("SELECT * FROM assignments WHERE id=?", (assignment_id,)).fetchone()
    if not item:
        abort(404)
    if g.user["role"] != "lecturer" and item["student_id"] != g.user["id"]:
        abort(403)
    audit("assignment_downloaded", g.user["id"])
    return send_from_directory(str(UPLOAD_DIR), item["stored_name"], as_attachment=True, download_name=item["original_name"], mimetype="application/octet-stream")


@app.route("/messages", methods=["GET", "POST"])
@login_required
def messages():
    db = get_db()
    if request.method == "POST":
        try:
            recipient_id = int(request.form.get("recipient_id", "0"))
        except ValueError:
            abort(400)
        body = request.form.get("body", "").strip()
        recipient = db.execute("SELECT id,role FROM users WHERE id=?", (recipient_id,)).fetchone()
        if not recipient or recipient_id == g.user["id"] or recipient["role"] == g.user["role"]:
            flash("Choose a valid student/lecturer recipient.", "error")
        elif not body or len(body) > 2000:
            flash("Message must contain 1–2000 characters.", "error")
        else:
            db.execute("INSERT INTO messages(sender_id,recipient_id,body,sent_at) VALUES(?,?,?,?)",
                       (g.user["id"], recipient_id, body, now()))
            db.commit()
            audit("message_sent", g.user["id"])
            flash("Message sent.", "success")
            return redirect(url_for("messages"))
    users = db.execute("SELECT id,full_name,role FROM users WHERE role != ? ORDER BY full_name", (g.user["role"],)).fetchall()
    rows = db.execute("""SELECT m.*,s.full_name AS sender_name,r.full_name AS recipient_name
                         FROM messages m JOIN users s ON s.id=m.sender_id
                         JOIN users r ON r.id=m.recipient_id
                         WHERE m.sender_id=? OR m.recipient_id=? ORDER BY m.id DESC""",
                      (g.user["id"], g.user["id"])).fetchall()
    return render_template("messages.html", users=users, messages=rows)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        if not (1 <= len(full_name) <= 100) or not (3 <= len(email) <= 200) or "@" not in email or len(phone) > 30:
            flash("Check the name, email and phone fields.", "error")
        else:
            # Never accept a user_id or role value from the submitted form.
            get_db().execute("UPDATE users SET full_name=?,email=?,phone=? WHERE id=?",
                             (full_name, email, phone, g.user["id"]))
            get_db().commit()
            audit("profile_updated", g.user["id"])
            flash("Your profile has been updated.", "success")
            return redirect(url_for("profile"))
    return render_template("profile.html")


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", message="You are not allowed to access this page."), 403


@app.errorhandler(404)
def missing(_error):
    return render_template("error.html", message="Page or assignment not found."), 404


@app.errorhandler(413)
def too_large(_error):
    return render_template("error.html", message="File is too large (maximum 5 MB)."), 413


@app.errorhandler(400)
def invalid_request(_error):
    return render_template("error.html", message="Invalid request. Refresh the page and try again."), 400


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

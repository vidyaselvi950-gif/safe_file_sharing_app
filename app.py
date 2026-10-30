import os, secrets, sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
KEY_FILE = os.path.join(BASE_DIR, ".encryption_key")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
os.makedirs(STORAGE_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {
    "pdf","txt","doc","docx","xls","xlsx","ppt","pptx",
    "jpg","jpeg","png","gif","zip","csv"
}

def utcnow():
    return datetime.now(timezone.utc)

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        original_name TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        size INTEGER NOT NULL,
        uploaded_at TEXT NOT NULL,
        FOREIGN KEY(owner_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        expires_at TEXT NOT NULL,
        max_downloads INTEGER NOT NULL DEFAULT 5,
        downloads INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(file_id) REFERENCES files(id)
    );
    """)
    conn.commit()
    conn.close()

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    else:
        key = AESGCM.generate_key(bit_length=256)
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        try:
            os.chmod(KEY_FILE, 0o600)
        except OSError:
            pass
    if len(key) != 32:
        raise RuntimeError("Invalid encryption key in .encryption_key")
    return key

AES_KEY = load_key()

def encrypt_file(data):
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(AES_KEY).encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt_file(data):
    if len(data) < 13:
        raise ValueError("Invalid encrypted file")
    nonce, ciphertext = data[:12], data[12:]
    return AESGCM(AES_KEY).decrypt(nonce, ciphertext, None)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def get_user_file(file_id, user_id):
    conn = db()
    row = conn.execute(
        "SELECT * FROM files WHERE id=? AND owner_id=?", (file_id, user_id)
    ).fetchone()
    conn.close()
    return row

@app.context_processor
def inject_user():
    return {"current_user": session.get("username")}

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) > 50:
            flash("Username must be 3–50 characters.", "error")
            return render_template("register.html")
        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return render_template("register.html")
        conn = db()
        try:
            conn.execute(
                "INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                (username, generate_password_hash(password), utcnow().isoformat())
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("Username already exists.", "error")
            return render_template("register.html")
        conn.close()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    conn = db()
    files = conn.execute(
        "SELECT * FROM files WHERE owner_id=? ORDER BY uploaded_at DESC",
        (session["user_id"],)
    ).fetchall()
    shares = conn.execute("""
        SELECT s.*, f.original_name
        FROM shares s JOIN files f ON f.id=s.file_id
        WHERE f.owner_id=?
        ORDER BY s.created_at DESC
    """, (session["user_id"],)).fetchall()
    conn.close()
    return render_template("dashboard.html", files=files, shares=shares)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        flash("Please select a file.", "error")
        return redirect(url_for("dashboard"))
    if not allowed_file(uploaded.filename):
        flash("File type is not allowed.", "error")
        return redirect(url_for("dashboard"))

    original = secure_filename(uploaded.filename)
    if not original:
        flash("Invalid filename.", "error")
        return redirect(url_for("dashboard"))

    raw = uploaded.read()
    if not raw:
        flash("Empty files are not allowed.", "error")
        return redirect(url_for("dashboard"))

    encrypted = encrypt_file(raw)
    stored_name = secrets.token_hex(24) + ".bin"
    with open(os.path.join(STORAGE_DIR, stored_name), "wb") as f:
        f.write(encrypted)

    conn = db()
    conn.execute(
        "INSERT INTO files(owner_id,original_name,stored_name,size,uploaded_at) VALUES(?,?,?,?,?)",
        (session["user_id"], original, stored_name, len(raw), utcnow().isoformat())
    )
    conn.commit()
    conn.close()
    flash("File uploaded and encrypted successfully.", "success")
    return redirect(url_for("dashboard"))

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    file = get_user_file(file_id, session["user_id"])
    if not file:
        abort(404)
    path = os.path.join(STORAGE_DIR, file["stored_name"])
    try:
        with open(path, "rb") as f:
            decrypted = decrypt_file(f.read())
    except (OSError, ValueError):
        abort(404)

    temp_name = secrets.token_hex(16) + "_" + file["original_name"]
    temp_path = os.path.join(STORAGE_DIR, temp_name)
    with open(temp_path, "wb") as f:
        f.write(decrypted)

    response = send_file(temp_path, as_attachment=True, download_name=file["original_name"])
    @response.call_on_close
    def cleanup():
        try:
            os.remove(temp_path)
        except OSError:
            pass
    return response

@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    file = get_user_file(file_id, session["user_id"])
    if not file:
        abort(404)
    conn = db()
    conn.execute("DELETE FROM shares WHERE file_id=?", (file_id,))
    conn.execute("DELETE FROM files WHERE id=?", (file_id,))
    conn.commit()
    conn.close()
    try:
        os.remove(os.path.join(STORAGE_DIR, file["stored_name"]))
    except OSError:
        pass
    flash("File and its sharing links were deleted.", "success")
    return redirect(url_for("dashboard"))

@app.route("/share/<int:file_id>", methods=["GET", "POST"])
@login_required
def create_share(file_id):
    file = get_user_file(file_id, session["user_id"])
    if not file:
        abort(404)

    if request.method == "POST":
        try:
            hours = int(request.form.get("hours", "24"))
            max_downloads = int(request.form.get("max_downloads", "5"))
        except ValueError:
            flash("Invalid share settings.", "error")
            return redirect(url_for("create_share", file_id=file_id))

        if not 1 <= hours <= 168:
            flash("Expiry must be between 1 and 168 hours.", "error")
            return redirect(url_for("create_share", file_id=file_id))
        if not 1 <= max_downloads <= 100:
            flash("Download limit must be between 1 and 100.", "error")
            return redirect(url_for("create_share", file_id=file_id))

        share_password = request.form.get("share_password", "")
        if share_password and len(share_password) < 6:
            flash("Share password must contain at least 6 characters.", "error")
            return redirect(url_for("create_share", file_id=file_id))

        token = secrets.token_urlsafe(32)
        password_hash = generate_password_hash(share_password) if share_password else None
        expires = utcnow() + timedelta(hours=hours)

        conn = db()
        conn.execute("""
            INSERT INTO shares(file_id,token,password_hash,expires_at,max_downloads,downloads,created_at)
            VALUES(?,?,?,?,?,?,?)
        """, (file_id, token, password_hash, expires.isoformat(),
              max_downloads, 0, utcnow().isoformat()))
        conn.commit()
        conn.close()

        link = url_for("shared_file", token=token, _external=True)
        return render_template("share_created.html", file=file, link=link, expires=expires)

    return render_template("share.html", file=file)

@app.route("/s/<token>", methods=["GET", "POST"])
def shared_file(token):
    conn = db()
    share = conn.execute("""
        SELECT s.*, f.original_name, f.stored_name, f.size
        FROM shares s JOIN files f ON f.id=s.file_id
        WHERE s.token=?
    """, (token,)).fetchone()
    conn.close()

    if not share:
        return render_template("share_error.html", message="Share link not found."), 404

    try:
        expired = utcnow() >= datetime.fromisoformat(share["expires_at"])
    except ValueError:
        expired = True

    if expired:
        return render_template("share_error.html", message="This share link has expired."), 410

    if share["downloads"] >= share["max_downloads"]:
        return render_template("share_error.html", message="This share link has reached its download limit."), 410

    if request.method == "POST":
        password = request.form.get("password", "")
        if share["password_hash"] and not check_password_hash(share["password_hash"], password):
            flash("Incorrect share password.", "error")
            return render_template("shared.html", share=share, protected=True)
        if share["password_hash"] is None:
            pass
        conn = db()
        conn.execute("UPDATE shares SET downloads=downloads+1 WHERE id=?", (share["id"],))
        conn.commit()
        conn.close()

        path = os.path.join(STORAGE_DIR, share["stored_name"])
        try:
            with open(path, "rb") as f:
                decrypted = decrypt_file(f.read())
        except (OSError, ValueError):
            return render_template("share_error.html", message="The stored file is unavailable."), 404

        temp_name = secrets.token_hex(16) + "_" + share["original_name"]
        temp_path = os.path.join(STORAGE_DIR, temp_name)
        with open(temp_path, "wb") as f:
            f.write(decrypted)

        response = send_file(temp_path, as_attachment=True, download_name=share["original_name"])
        @response.call_on_close
        def cleanup():
            try:
                os.remove(temp_path)
            except OSError:
                pass
        return response

    return render_template("shared.html", share=share, protected=bool(share["password_hash"]))

@app.errorhandler(413)
def too_large(e):
    flash("File is too large. Maximum size is 25 MB.", "error")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    init_db()
    app.run(debug=False,use_reloader=False)

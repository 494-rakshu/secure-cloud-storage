from flask import Flask, render_template, request, redirect, session, send_file, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from flask_mail import Mail, Message
from dotenv import load_dotenv

import sqlite3
import os
import uuid
import datetime
import io
import re
import random

# ================= LOAD ENV =================
load_dotenv()

# ================= HELPERS =================
def generate_otp():
    return str(random.randint(100000, 999999))

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ================= ADMIN =================
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")


# ================= APP INIT =================
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)

DB_PATH = os.path.join(INSTANCE_DIR, "database.db")


# ================= MAIL CONFIG =================
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = app.config["MAIL_USERNAME"]

mail = Mail(app)


# ================= ENCRYPTION =================
FERNET_KEY = os.getenv("FERNET_KEY")

if not FERNET_KEY:
    raise ValueError("FERNET_KEY environment variable not set")

fernet = Fernet(FERNET_KEY.encode())


# ================= CONFIG =================
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg",
    "pdf", "txt",
    "ppt", "pptx"
}

# ================= DATABASE INIT =================
# ================= DATABASE INIT =================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # USERS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        status TEXT DEFAULT 'Active',
        last_login TEXT
    )
    """)

    # FILES TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        stored_name TEXT,
        username TEXT,
        upload_date TEXT
    )
    """)

    # LOGS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        email TEXT,
        filename TEXT,
        action TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()


def migrate_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]

    if "status" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'Active'")

    if "last_login" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN last_login TEXT")

    conn.commit()
    conn.close()


# ⚠️ REMOVE THIS FROM HERE (MOVE TO END OF FILE)
# if __name__ == "__main__":
#     init_db()


# ================= HOME =================
@app.route("/")
def home():
    return render_template("home.html")

# ================= REGISTER =================
# ================= REGISTER =================
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        # Email Validation
        email_pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'

        if not re.match(email_pattern, email):
            return "Please enter a valid email address"

        # Strong Password Validation
        if len(password) < 8:
            return "Password must be at least 8 characters"

        if not re.search(r"[A-Z]", password):
            return "Password must contain an uppercase letter"

        if not re.search(r"[a-z]", password):
            return "Password must contain a lowercase letter"

        if not re.search(r"\d", password):
            return "Password must contain a number"

        if not re.search(r"[@$!%*?&]", password):
            return "Password must contain a special character"

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            return "Email already registered"

        hashed_password = generate_password_hash(password)

        cursor.execute(
            "INSERT INTO users(name,email,password) VALUES(?,?,?)",
            (name, email, hashed_password)
        )

        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")


# ================= LOGIN =================
@app.route("/login", methods=["GET", "POST"])
def login():

    print("LOGIN ROUTE HIT")

    # safe init
    session.setdefault("login_attempts", 0)

    if request.method == "POST":

        # if OTP already active → force verify page
        if session.get("otp_lock"):
            return redirect("/verify_otp")

        if session["login_attempts"] >= 5:
            return """
            Account temporarily locked.<br><br>
            Too many failed login attempts.
            """

        email = request.form["email"]
        password = request.form["password"]

        # ================= ADMIN LOGIN =================
        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:

            session.clear()
            session["admin"] = True
            session["user_name"] = "Admin"
            session["email"] = ADMIN_EMAIL
            session["login_attempts"] = 0

            return redirect("/admin")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT name, email, password, status 
            FROM users 
            WHERE email=?
        """, (email,))

        user = cursor.fetchone()

        if not user:
            conn.close()
            session["login_attempts"] += 1
            remaining = 5 - session["login_attempts"]
            return f"Invalid Email or Password.<br><br>Attempts Remaining: {remaining}"

        # BLOCKED USER
        if user[3] == "Blocked":
            conn.close()
            return render_template("blocked.html")

        # PASSWORD CHECK
        if check_password_hash(user[2], password):

            session["login_attempts"] = 0

            # update last login
            cursor.execute("""
                UPDATE users 
                SET last_login=? 
                WHERE email=?
            """, (
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                email
            ))
            conn.commit()

            # OTP
            otp = str(random.randint(100000, 999999))

            session["otp"] = otp
            session["otp_time"] = datetime.datetime.now().timestamp()
            session["otp_attempts"] = 0
            session["otp_lock"] = True

            session["temp_name"] = user[0]
            session["temp_email"] = user[1]

            try:
                msg = Message(
                    subject="SecureCloud Login OTP",
                    recipients=[user[1]]
                )

                msg.body = f"""
Hello {user[0]},

Your OTP for SecureCloud login is: {otp}

This OTP is valid for 2 minutes.

If this wasn't you, please ignore this email.
"""

                mail.send(msg)

            except Exception as e:
                conn.close()
                return f"Email sending failed: {repr(e)}"

            conn.close()
            return redirect("/verify_otp")

        conn.close()
        session["login_attempts"] += 1
        remaining = 5 - session["login_attempts"]

        return f"""
        Invalid Email or Password.<br><br>
        Attempts Remaining: {remaining}
        """

    return render_template("login.html")



@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form["email"]

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        )

        user = cursor.fetchone()
        conn.close()

        if not user:
            return "Email not registered."

        otp = generate_otp()

        session["reset_email"] = email
        session["reset_otp"] = otp
        session["reset_otp_time"] = datetime.datetime.now().timestamp()

        try:
            msg = Message(
                subject="SecureCloud Password Reset OTP",
                recipients=[email]
            )

            msg.body = f"""
Your SecureCloud password reset OTP is: {otp}

This OTP is valid for 2 minutes.
"""

            mail.send(msg)

        except Exception as e:
            return f"Email sending failed: {str(e)}"

        return redirect("/verify_reset_otp")

    return render_template("forgot_password.html")



@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():

    if "reset_email" not in session:
        return redirect("/forgot_password")

    if request.method == "POST":

        new_password = request.form["password"]

        hashed_password = generate_password_hash(new_password)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE users SET password=? WHERE email=?",
            (hashed_password, session["reset_email"])
        )

        conn.commit()
        conn.close()

        session.pop("reset_email", None)
        session.pop("reset_otp", None)
        session.pop("reset_otp_time", None)

        return redirect("/login")

    return render_template("reset_password.html")

@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():

    if "otp" not in session:
        return redirect("/login")

    if "otp_attempts" not in session:
        session["otp_attempts"] = 0

    if request.method == "POST":

        current_time = datetime.datetime.now().timestamp()

        if current_time - session["otp_time"] > 120:

            session.pop("otp", None)
            session.pop("otp_time", None)
            session.pop("temp_name", None)
            session.pop("temp_email", None)
            session.pop("otp_attempts", None)
            session.pop("otp_lock", None)

            return "OTP Expired. Please login again."

        entered_otp = request.form["otp"]

        if entered_otp == session["otp"]:

            session["user_name"] = session["temp_name"]
            session["email"] = session["temp_email"]

            session["login_attempts"] = 0
            session["otp_attempts"] = 0

            session.pop("otp_lock", None)

            # LOG LOGIN
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO logs (username, email, filename, action, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (
                session["user_name"],
                session["email"],
                "LOGIN",
                "LOGIN",
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))

            conn.commit()
            conn.close()

            session.pop("otp", None)
            session.pop("otp_time", None)
            session.pop("temp_name", None)
            session.pop("temp_email", None)
            session.pop("otp_attempts", None)
            session.pop("otp_lock", None)

            return redirect("/dashboard")

        # WRONG OTP
        session["otp_attempts"] += 1

        if session["otp_attempts"] >= 3:

            session.pop("otp", None)
            session.pop("otp_time", None)
            session.pop("temp_name", None)
            session.pop("temp_email", None)
            session.pop("otp_attempts", None)
            session.pop("otp_lock", None)

            return "Too many incorrect OTP attempts. Please login again."

        remaining = 3 - session["otp_attempts"]

        return f"Invalid OTP.<br><br>Attempts Remaining: {remaining}"

    return render_template("verify_otp.html")


@app.route("/verify_reset_otp", methods=["GET", "POST"])
def verify_reset_otp():

    if "reset_otp" not in session:
        return redirect("/forgot_password")

    if request.method == "POST":

        entered_otp = request.form["otp"]

        current_time = datetime.datetime.now().timestamp()

        if current_time - session["reset_otp_time"] > 120:

            session.pop("reset_otp", None)
            session.pop("reset_otp_time", None)
            session.pop("reset_email", None)

            return "OTP Expired. Please try again."

        if entered_otp == session["reset_otp"]:
            return redirect("/reset_password")

        return "Invalid OTP"

    return render_template("verify_reset_otp.html")

# ================= DASHBOARD =================
@app.route("/dashboard")
def dashboard():

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ----------------------------
    # TOTAL FILES
    # ----------------------------
    cursor.execute(
        "SELECT COUNT(*) FROM files WHERE username=?",
        (session["user_name"],)
    )
    total_files = cursor.fetchone()[0]

    # ----------------------------
    # ACTIVITY COUNTS
    # ----------------------------
    cursor.execute(
        "SELECT COUNT(*) FROM logs WHERE username=? AND action='UPLOAD'",
        (session["user_name"],)
    )
    upload_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM logs WHERE username=? AND action='DOWNLOAD'",
        (session["user_name"],)
    )
    download_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM logs WHERE username=? AND action='DELETE'",
        (session["user_name"],)
    )
    delete_count = cursor.fetchone()[0]

    activity_count = upload_count + download_count + delete_count

    # ----------------------------
    # LAST ACTIVITY
    # ----------------------------
    cursor.execute("""
        SELECT action, filename, timestamp 
        FROM logs 
        WHERE username=? 
        ORDER BY timestamp DESC 
        LIMIT 1
    """, (session["user_name"],))

    last = cursor.fetchone()

    if last:
        last_activity = f"{last[0]} - {last[1]}"
    else:
        last_activity = "No activity yet"

    # ----------------------------
    # RECENT LOGS
    # ----------------------------
    cursor.execute("""
        SELECT action, filename, timestamp 
        FROM logs 
        WHERE username=? 
        ORDER BY timestamp DESC 
        LIMIT 5
    """, (session["user_name"],))

    recent_logs = cursor.fetchall()

    # ----------------------------
    # STORAGE CALCULATION
    # ----------------------------
    total_size = 0

    cursor.execute(
        "SELECT stored_name FROM files WHERE username=?",
        (session["user_name"],)
    )

    files = cursor.fetchall()

    for f in files:
        try:
            path = os.path.join(app.config["UPLOAD_FOLDER"], f[0])
            if os.path.exists(path):
                total_size += os.path.getsize(path)
        except Exception:
            continue

    storage_mb = round(total_size / (1024 * 1024), 2)

    conn.close()

    return render_template(
        "dashboard.html",
        user_name=session["user_name"],
        total_files=total_files,
        storage_mb=storage_mb,
        activity_count=activity_count,
        upload_count=upload_count,
        download_count=download_count,
        delete_count=delete_count,
        last_activity=last_activity,
        recent_logs=recent_logs
    )
# ================= UPLOAD =================
@app.route("/upload", methods=["GET", "POST"])
def upload_file():

    if "user_name" not in session:
        return redirect("/login")

    if request.method == "POST":

        if "file" not in request.files:
            return "No file selected"

        file = request.files["file"]

        if file.filename == "":
            return "No file selected"

        if file and allowed_file(file.filename):

            original_name = secure_filename(file.filename)

            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            # Check duplicate file
            cursor.execute(
                "SELECT * FROM files WHERE filename=? AND username=?",
                (original_name, session["user_name"])
            )

            if cursor.fetchone():
                conn.close()
                return "File already uploaded!"

            # Create unique filename
            unique_name = str(uuid.uuid4()) + "_" + original_name

            # Ensure upload folder exists (important for Render)
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

            path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)

            # Encrypt file safely
            file_data = file.read()
            encrypted_data = fernet.encrypt(file_data)

            with open(path, "wb") as f:
                f.write(encrypted_data)

            upload_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Store file record
            cursor.execute("""
                INSERT INTO files
                (filename, stored_name, username, upload_date)
                VALUES (?, ?, ?, ?)
            """, (
                original_name,
                unique_name,
                session["user_name"],
                upload_date
            ))

            # Activity log
            cursor.execute("""
                INSERT INTO logs
                (username, email, filename, action, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (
                session["user_name"],
                session["email"],
                original_name,
                "UPLOAD",
                upload_date
            ))

            conn.commit()
            conn.close()

            session["message"] = "✅ File uploaded successfully!"

            return redirect("/dashboard")

        return "Invalid file type"

    return render_template("upload.html")


@app.route("/upload_ajax", methods=["POST"])
def upload_ajax():

    file = request.files.get("file")
    user = session.get("user_name")

    if not file:
        return jsonify({"status": "error", "message": "No file selected"})

    if not user:
        return jsonify({"status": "error", "message": "Unauthorized"})

    if file.filename == "":
        return jsonify({"status": "error", "message": "No file selected"})

    # ✅ ADD FILE TYPE CHECK (IMPORTANT FIX)
    if not allowed_file(file.filename):
        return jsonify({"status": "error", "message": "Invalid file type"})

    filename = secure_filename(file.filename)

    unique_name = str(uuid.uuid4()) + "_" + filename

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)

    # Encrypt the file
    encrypted_data = fernet.encrypt(file.read())

    with open(path, "wb") as f:
        f.write(encrypted_data)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    upload_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # FILE TABLE ENTRY
    cur.execute("""
        INSERT INTO files (filename, stored_name, username, upload_date)
        VALUES (?, ?, ?, ?)
    """, (
        filename,
        unique_name,
        user,
        upload_time
    ))

    # ✅ ADD LOG ENTRY (VERY IMPORTANT FIX)
    cur.execute("""
        INSERT INTO logs (username, email, filename, action, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        user,
        session.get("email", ""),
        filename,
        "UPLOAD",
        upload_time
    ))

    conn.commit()
    conn.close()

    return jsonify({"status": "success", "message": "File uploaded successfully"})

# ================= FILES =================
@app.route("/files")
def files():

    if "user_name" not in session:
        return redirect("/login")

    search = request.args.get("search", "").strip()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT filename, stored_name, upload_date
        FROM files
        WHERE username=? AND filename LIKE ?
        ORDER BY upload_date DESC
    """, (
        session["user_name"],
        "%" + search + "%"
    ))

    rows = cursor.fetchall()

    conn.close()

    columns = ["filename", "stored_name", "upload_date"]
    data = [dict(zip(columns, row)) for row in rows]

    return render_template(
        "files.html",
        files=data,
        search=search
    )

@app.route("/profile")
def profile():

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get user details
    cursor.execute(
        "SELECT name, email FROM users WHERE email=?",
        (session["email"],)
    )
    user = cursor.fetchone()

    # Get total uploaded files count
    cursor.execute(
        "SELECT COUNT(*) FROM files WHERE username=?",
        (session["user_name"],)
    )
    total_files = cursor.fetchone()[0]

    # Calculate storage usage
    total_size = 0

    cursor.execute(
        "SELECT stored_name FROM files WHERE username=?",
        (session["user_name"],)
    )
    files = cursor.fetchall()

    for file_record in files:
        path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            file_record[0]
        )

        if os.path.exists(path):
            total_size += os.path.getsize(path)

    storage_mb = round(total_size / (1024 * 1024), 2)

    conn.close()

    return render_template(
        "profile.html",
        user=user,
        total_files=total_files,
        storage_mb=storage_mb
    )

@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT name, email FROM users WHERE email=?",
        (session["email"],)
    )
    user = cursor.fetchone()

    # Safety check (should rarely happen)
    if not user:
        conn.close()
        session.clear()
        return redirect("/login")

    if request.method == "POST":

        new_name = request.form["name"].strip()

        # Prevent empty names
        if not new_name:
            conn.close()
            return "Name cannot be empty"

        cursor.execute(
            "UPDATE users SET name=? WHERE email=?",
            (new_name, session["email"])
        )

        conn.commit()
        conn.close()

        # Update session so the new name appears everywhere
        session["user_name"] = new_name

        return redirect("/profile")

    conn.close()

    return render_template(
        "edit_profile.html",
        user=user
    )


@app.route("/storage")
def storage():

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Total files uploaded by the user
    cursor.execute(
        "SELECT COUNT(*) FROM files WHERE username=?",
        (session["user_name"],)
    )
    total_files = cursor.fetchone()[0]

    # Calculate storage used
    total_size = 0

    cursor.execute(
        "SELECT stored_name FROM files WHERE username=?",
        (session["user_name"],)
    )
    files = cursor.fetchall()

    for file_record in files:
        path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            file_record[0]
        )

        # Ignore missing files safely
        if os.path.exists(path):
            total_size += os.path.getsize(path)

    storage_mb = round(total_size / (1024 * 1024), 2)

    # Maximum storage limit used for UI display
    max_storage = 1024 # MB

    used_percent = min(
        (storage_mb / max_storage) * 100,
        100
    )

    conn.close()

    return render_template(
        "storage.html",
        total_files=total_files,
        storage_mb=storage_mb,
        used_percent=used_percent
    )

# ================= SECURITY LOGS =================
@app.route("/security")
def security():

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT filename, action, timestamp
        FROM logs
        WHERE username=?
        ORDER BY id DESC
    """, (
        session["user_name"],
    ))

    logs = cursor.fetchall()

    conn.close()

    return render_template(
        "security.html",
        logs=logs
    )

# ================= DOWNLOAD =================
@app.route("/download/<stored_name>")
def download_file(stored_name):

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # IMPORTANT: verify ownership
    cursor.execute("""
        SELECT filename
        FROM files
        WHERE stored_name=? AND username=?
    """, (
        stored_name,
        session["user_name"]
    ))

    result = cursor.fetchone()

    if not result:
        conn.close()
        return "File not found"

    original_name = result[0]

    # Log download activity
    cursor.execute("""
        INSERT INTO logs (username, email, filename, action, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        session["user_name"],
        session["email"],
        original_name,
        "DOWNLOAD",
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        stored_name
    )

    # Check if physical file exists
    if not os.path.exists(file_path):
        return "File not found"

    try:
        with open(file_path, "rb") as f:
            encrypted = f.read()

        decrypted = fernet.decrypt(encrypted)

    except Exception:
        return "Unable to decrypt file"

    return send_file(
        io.BytesIO(decrypted),
        as_attachment=True,
        download_name=original_name,
        mimetype="application/octet-stream"
    )

# ================= DELETE =================
@app.route("/delete/<stored_name>")
def delete_file(stored_name):

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Verify ownership and get original filename
    cursor.execute("""
        SELECT filename
        FROM files
        WHERE stored_name=? AND username=?
    """, (
        stored_name,
        session["user_name"]
    ))

    result = cursor.fetchone()

    if not result:
        conn.close()
        return "File not found"

    original_name = result[0]

    # Delete physical file
    path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        stored_name
    )

    if os.path.exists(path):
        os.remove(path)

    # Log DELETE activity
    cursor.execute("""
        INSERT INTO logs
        (username, email, filename, action, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        session["user_name"],
        session["email"],
        original_name,
        "DELETE",
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    # Delete database record
    cursor.execute("""
        DELETE FROM files
        WHERE stored_name=? AND username=?
    """, (
        stored_name,
        session["user_name"]
    ))

    conn.commit()
    conn.close()

    return redirect("/files")
# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ================= ADMIN LOGIN =================
@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":

        email = request.form["email"].strip()
        password = request.form["password"]

        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:

            session["admin"] = True

            # Keep admin session data consistent
            session["user_name"] = "Admin"
            session["email"] = ADMIN_EMAIL

            return redirect("/admin")

        return render_template(
            "admin_login.html",
            error="Invalid Credentials"
        )

    return render_template("admin_login.html")

# ================= ADMIN DASHBOARD =================
@app.route("/admin")
def admin():

    if "admin" not in session:
        return redirect("/admin_login")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ================= STATISTICS =================

    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM files")
    total_files = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs")
    total_activities = cursor.fetchone()[0]

    # Calculate total storage used
    total_storage = 0

    cursor.execute("SELECT stored_name FROM files")
    stored_files = cursor.fetchall()

    for file_record in stored_files:
        path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            file_record[0]
        )

        if os.path.exists(path):
            total_storage += os.path.getsize(path)

    storage_mb = round(total_storage / (1024 * 1024), 2)

    # ================= USER TABLE =================

    cursor.execute("""
        SELECT name,
               email,
               COALESCE(last_login, 'Never'),
               status
        FROM users
    """)

    users_raw = cursor.fetchall()

    enhanced_users = []

    for user in users_raw:

        name = user[0]
        email = user[1]
        last_login = user[2]
        status = user[3]

        # IMPORTANT FIX: count by email instead of name
        cursor.execute(
            "SELECT COUNT(*) FROM files WHERE username=?",
            (name,)
        )

        file_count = cursor.fetchone()[0]

        enhanced_users.append(
            (name, email, file_count, last_login, status)
        )

    # ================= RECENT ACTIVITIES =================

    cursor.execute("""
        SELECT username,
               email,
               action,
               filename,
               timestamp
        FROM logs
        ORDER BY timestamp DESC
        LIMIT 10
    """)

    recent_logs = cursor.fetchall()

    conn.close()

    return render_template(
        "admin.html",
        total_users=total_users,
        total_files=total_files,
        total_activities=total_activities,
        storage_mb=storage_mb,
        users=enhanced_users,
        recent_logs=recent_logs
    )

@app.route("/admin_logout")
def admin_logout():

    session.clear()

    return redirect("/admin_login")


@app.route("/block_user/<email>")
def block_user(email):

    # IMPORTANT: Only admins should access this route
    if "admin" not in session:
        return redirect("/admin_login")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE users SET status='Blocked' WHERE email=?",
        (email,)
    )

    conn.commit()
    conn.close()

    return redirect("/admin")


@app.route("/unblock_user/<email>")
def unblock_user(email):

    # Only admins can unblock users
    if "admin" not in session:
        return redirect("/admin_login")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE users SET status='Active' WHERE email=?",
        (email,)
    )

    conn.commit()
    conn.close()

    return redirect("/admin")

@app.route("/delete_user/<email>")
def delete_user(email):

    # Only admins can delete users
    if "admin" not in session:
        return redirect("/admin_login")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Get user's name before deleting
    cur.execute(
        "SELECT name FROM users WHERE email=?",
        (email,)
    )

    user = cur.fetchone()

    if not user:
        conn.close()
        return redirect("/admin")

    username = user[0]

    # Delete the user
    cur.execute(
        "DELETE FROM users WHERE email=?",
        (email,)
    )

    conn.commit()
    conn.close()

    return redirect("/admin")


@app.route("/activity_log")
def activity_log():

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT action,
               filename,
               timestamp
        FROM logs
        WHERE username=?
        ORDER BY timestamp DESC
    """, (
        session["user_name"],
    ))

    logs = cursor.fetchall()

    conn.close()

    return render_template(
        "activity_log.html",
        logs=logs
    )
# ================= DATABASE STARTUP =================
with app.app_context():
    init_db()
    migrate_db()


# ================= LOCAL RUN =================
if __name__ == "__main__":
    app.run(debug=True)
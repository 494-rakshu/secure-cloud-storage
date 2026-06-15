from flask import Flask, render_template, request, redirect, session, send_file, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import sqlite3
import os
import uuid
import datetime
import io
import re
import random

# ================= ADMIN =================
ADMIN_EMAIL = "admin@securecloud.com"
ADMIN_PASSWORD = "admin123"

# ================= APP INIT =================
app = Flask(__name__)
app.secret_key = "secure_cloud_storage"

# ================= ENCRYPTION =================
with open("secret.key", "rb") as key_file:
    key = key_file.read()

fernet = Fernet(key)

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
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        stored_name TEXT,
        username TEXT,
        upload_date TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        filename TEXT,
        action TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ================= HELPERS =================
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ================= HOME =================
@app.route("/")
def home():
    return render_template("home.html")

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

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        # Check duplicate email
        cursor.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        )

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

    if "login_attempts" not in session:
        session["login_attempts"] = 0

    if request.method == "POST":

        if session["login_attempts"] >= 5:
            return """
            Account temporarily locked.<br><br>
            Too many failed login attempts.
            """

        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT name, email, password FROM users WHERE email=?",
            (email,)
        )

        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):

            # Reset failed attempts
            session["login_attempts"] = 0

            # Generate OTP
            otp = str(random.randint(100000, 999999))

            session["otp"] = otp
            session["otp_time"] = datetime.datetime.now().timestamp()

            session["temp_name"] = user[0]
            session["temp_email"] = user[1]

            print("\n========================")
            print("LOGIN OTP:", otp)
            print("========================\n")

            return redirect("/verify_otp")

        # Failed login
        session["login_attempts"] += 1

        remaining = 5 - session["login_attempts"]

        return f"""
        Invalid Email or Password.<br><br>
        Attempts Remaining: {remaining}
        """

    return render_template("login.html")


@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():

    if "otp" not in session:
        return redirect("/login")

    if "otp_attempts" not in session:
        session["otp_attempts"] = 0

    if request.method == "POST":

        # OTP expires after 2 minutes
        current_time = datetime.datetime.now().timestamp()

        if current_time - session["otp_time"] > 120:

            session.pop("otp", None)
            session.pop("otp_time", None)
            session.pop("temp_name", None)
            session.pop("temp_email", None)
            session.pop("otp_attempts", None)

            return "OTP Expired. Please login again."

        entered_otp = request.form["otp"]

        if entered_otp == session["otp"]:

            session["user_name"] = session["temp_name"]
            session["email"] = session["temp_email"]

            # Reset counters
            session["login_attempts"] = 0
            session["otp_attempts"] = 0

            # Log login activity
            conn = sqlite3.connect("database.db")
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO logs
                (username, filename, action, timestamp)
                VALUES (?, ?, ?, ?)
            """, (
                session["user_name"],
                "LOGIN",
                "LOGIN",
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))

            conn.commit()
            conn.close()

            # Remove temporary OTP data
            session.pop("otp", None)
            session.pop("otp_time", None)
            session.pop("temp_name", None)
            session.pop("temp_email", None)

            return redirect("/dashboard")

        # Wrong OTP
        session["otp_attempts"] += 1

        if session["otp_attempts"] >= 3:

            session.pop("otp", None)
            session.pop("otp_time", None)
            session.pop("temp_name", None)
            session.pop("temp_email", None)
            session.pop("otp_attempts", None)

            return """
            Too many incorrect OTP attempts.
            Please login again.
            """

        remaining = 3 - session["otp_attempts"]

        return f"""
        Invalid OTP.<br><br>
        Attempts Remaining: {remaining}
        """

    return render_template("verify_otp.html")



# ================= DASHBOARD =================
@app.route("/dashboard")
def dashboard():

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # ----------------------------
    # TOTAL FILES
    # ----------------------------
    cursor.execute("SELECT COUNT(*) FROM files WHERE username=?", (session["user_name"],))
    total_files = cursor.fetchone()[0]

    # ----------------------------
    # ACTIVITY COUNTS (SPLIT)
    # ----------------------------
    cursor.execute("SELECT COUNT(*) FROM logs WHERE username=? AND action='UPLOAD'", (session["user_name"],))
    upload_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE username=? AND action='DOWNLOAD'", (session["user_name"],))
    download_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE username=? AND action='DELETE'", (session["user_name"],))
    delete_count = cursor.fetchone()[0]

    # TOTAL ACTIVITY
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
    last_activity = f"{last[0]} - {last[1]}" if last else "No activity yet"

    # ----------------------------
    # RECENT 5 LOGS (PREVIEW)
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

    cursor.execute("SELECT stored_name FROM files WHERE username=?", (session["user_name"],))
    files = cursor.fetchall()

    for f in files:
        path = os.path.join(app.config["UPLOAD_FOLDER"], f[0])
        if os.path.exists(path):
            total_size += os.path.getsize(path)

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

            conn = sqlite3.connect("database.db")
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

            path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                unique_name
            )

            # Encrypt file
            encrypted_data = fernet.encrypt(
                file.read()
            )

            with open(path, "wb") as f:
                f.write(encrypted_data)

            upload_date = datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

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
                (username, action, filename, timestamp)
                VALUES (?, ?, ?, ?)
            """, (
                session["user_name"],
                "UPLOAD",
                original_name,
                upload_date
            ))

            conn.commit()
            conn.close()

            # Success message
            session["message"] = "✅ File uploaded successfully!"

            return redirect("/dashboard")

        return "Invalid file type"

    return render_template("upload.html")
# ================= FILES =================
@app.route("/files")
def files():

    if "user_name" not in session:
        return redirect("/login")

    search = request.args.get("search", "")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT filename, stored_name, upload_date
        FROM files
        WHERE username=? AND filename LIKE ?
    """, (session["user_name"], "%" + search + "%"))

    rows = cursor.fetchall()
    conn.close()

    columns = ["filename", "stored_name", "upload_date"]
    data = [dict(zip(columns, row)) for row in rows]

    return render_template("files.html", files=data, search=search)

@app.route("/profile")
def profile():
    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT name, email FROM users WHERE email=?", (session["email"],))
    user = cursor.fetchone()

    cursor.execute("SELECT COUNT(*) FROM files WHERE username=?", (session["user_name"],))
    total_files = cursor.fetchone()[0]

    total_size = 0
    cursor.execute("SELECT stored_name FROM files WHERE username=?", (session["user_name"],))
    files = cursor.fetchall()

    for f in files:
        path = os.path.join(app.config["UPLOAD_FOLDER"], f[0])
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

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT name, email FROM users WHERE email=?", (session["email"],))
    user = cursor.fetchone()

    if request.method == "POST":

        new_name = request.form["name"]

        cursor.execute(
            "UPDATE users SET name=? WHERE email=?",
            (new_name, session["email"])
        )

        conn.commit()
        conn.close()

        session["user_name"] = new_name

        return redirect("/profile")

    conn.close()

    return render_template("edit_profile.html", user=user)


@app.route("/storage")
def storage():
    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # total files
    cursor.execute("SELECT COUNT(*) FROM files WHERE username=?", (session["user_name"],))
    total_files = cursor.fetchone()[0]

    # calculate storage used
    total_size = 0

    cursor.execute("SELECT stored_name FROM files WHERE username=?", (session["user_name"],))
    files = cursor.fetchall()

    for f in files:
        path = os.path.join(app.config["UPLOAD_FOLDER"], f[0])
        if os.path.exists(path):
            total_size += os.path.getsize(path)

    storage_mb = round(total_size / (1024 * 1024), 2)

    # optional: assume max limit (for UI)
    max_storage = 100  # MB
    used_percent = min((storage_mb / max_storage) * 100, 100)

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

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT filename, action, timestamp
        FROM logs
        WHERE username=?
        ORDER BY id DESC
    """, (session["user_name"],))

    logs = cursor.fetchall()
    conn.close()

    return render_template("security.html", logs=logs)

# ================= DOWNLOAD =================
@app.route("/download/<stored_name>")
def download_file(stored_name):

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT filename FROM files WHERE stored_name=?",
        (stored_name,)
    )

    result = cursor.fetchone()

    if not result:
        conn.close()
        return "File not found"

    original_name = result[0]

    cursor.execute("""
        INSERT INTO logs (username, filename, action, timestamp)
        VALUES (?, ?, ?, ?)
    """, (
        session["user_name"],
        original_name,
        "DOWNLOAD",
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)

    with open(file_path, "rb") as f:
        encrypted = f.read()

    decrypted = fernet.decrypt(encrypted)

    return send_file(
        io.BytesIO(decrypted),
        as_attachment=True,
        download_name=str(original_name),
        mimetype="application/octet-stream"
    )

# ================= DELETE =================
@app.route("/delete/<stored_name>")
def delete_file(stored_name):

    if "user_name" not in session:
        return redirect("/login")

    path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)

    if os.path.exists(path):
        os.remove(path)

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM files WHERE stored_name=? AND username=?",
        (stored_name, session["user_name"])
    )

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

        email = request.form["email"]
        password = request.form["password"]

        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/admin")

        return render_template("admin_login.html", error="Invalid Credentials")

    return render_template("admin_login.html")

# ================= ADMIN DASHBOARD =================
@app.route("/admin")
def admin():

    if "admin" not in session:
        return redirect("/admin_login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM users")
    users = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM files")
    files = cursor.fetchone()[0]

    cursor.execute("SELECT name, email FROM users")
    user_list = cursor.fetchall()

    cursor.execute("SELECT filename, username FROM files")
    file_list = cursor.fetchall()

    conn.close()

    return render_template(
        "admin.html",
        total_users=users,
        total_files=files,
        users=user_list,
        files=file_list
    )

@app.route("/activity_log")
def activity_log():
    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT action, filename, timestamp
        FROM logs
        WHERE username=?
        ORDER BY timestamp DESC
    """, (session["user_name"],))

    logs = cursor.fetchall()
    conn.close()

    return render_template("activity_log.html", logs=logs)

# ================= RUN =================
if __name__ == "__main__":
    app.run(debug=True)
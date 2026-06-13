from flask import Flask, render_template, request, redirect, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import uuid
import datetime

app = Flask(__name__)
app.secret_key = "secure_cloud_storage"

UPLOAD_FOLDER = "uploads"

# ✅ FIX: PPT + PPTX ADDED HERE
ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg",
    "pdf", "txt",
    "ppt", "pptx"
}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
def home():
    return render_template("home.html")


# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users(name,email,password) VALUES(?,?,?)",
            (name, email, hashed_password)
        )

        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")


# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user[3], password):

            session["user_name"] = user[1]

            login_time = datetime.datetime.now()

            conn2 = sqlite3.connect("database.db")
            cursor2 = conn2.cursor()

            cursor2.execute(
                "INSERT INTO logs (username, time) VALUES (?, ?)",
                (user[1], str(login_time))
            )

            conn2.commit()
            conn2.close()
            conn.close()

            return redirect("/dashboard")

        conn.close()
        return "Invalid Email or Password"

    return render_template("login.html")


# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM files WHERE username=?", (session["user_name"],))
    total_files = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE username=?", (session["user_name"],))
    login_records = cursor.fetchone()[0]

    total_size = 0

    cursor.execute("SELECT stored_name FROM files WHERE username=?", (session["user_name"],))
    files = cursor.fetchall()

    for file in files:
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file[0])
        if os.path.exists(filepath):
            total_size += os.path.getsize(filepath)

    storage_mb = round(total_size / (1024 * 1024), 2)

    conn.close()

    return render_template(
        "dashboard.html",
        user_name=session["user_name"],
        total_files=total_files,
        storage_mb=storage_mb,
        login_records=login_records
    )


# ---------------- UPLOAD ----------------
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

            cursor.execute(
                "SELECT * FROM files WHERE filename=? AND username=?",
                (original_name, session["user_name"])
            )

            existing = cursor.fetchone()

            if existing:
                conn.close()
                return "File already uploaded!"

            unique_name = str(uuid.uuid4()) + "_" + original_name
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)

            file.save(filepath)

            upload_date = datetime.datetime.now().strftime("%d %b %Y, %I:%M %p")

            cursor.execute(
                """
                INSERT INTO files
                (filename, stored_name, username, upload_date)
                VALUES (?, ?, ?, ?)
                """,
                (original_name, unique_name, session["user_name"], upload_date)
            )

            conn.commit()
            conn.close()

            return redirect("/files")

        return "Invalid file type"

    return render_template("upload.html")


# ---------------- FILES ----------------
@app.route("/files")
def files():

    search = request.args.get("search", "")

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT filename, stored_name, upload_date
        FROM files
        WHERE username=?
        AND filename LIKE ?
        """,
        (session["user_name"], "%" + search + "%")
    )

    data = cursor.fetchall()
    conn.close()

    return render_template("files.html", files=data, search=search)


# ---------------- STORAGE ----------------
@app.route("/storage")
def storage():

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT filename FROM files WHERE username=?", (session["user_name"],))
    files = cursor.fetchall()

    conn.close()

    file_count = len(files)

    storage_used_kb = file_count * 120
    storage_used_mb = round(storage_used_kb / 1024, 2)

    return render_template(
        "storage.html",
        file_count=file_count,
        storage_used_mb=storage_used_mb
    )


# ---------------- SECURITY LOGS ----------------
@app.route("/security")
def security():

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT username, time FROM logs WHERE username=? ORDER BY id DESC",
        (session["user_name"],)
    )

    logs = cursor.fetchall()
    conn.close()

    return render_template("security.html", logs=logs)


# ---------------- DOWNLOAD ----------------
@app.route("/download/<filename>")
def download_file(filename):

    if "user_name" not in session:
        return redirect("/login")

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename,
        as_attachment=True
    )


# ---------------- DELETE ----------------
@app.route("/delete/<stored_name>")
def delete_file(stored_name):

    if "user_name" not in session:
        return redirect("/login")

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)

    if os.path.exists(filepath):
        os.remove(filepath)

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM files WHERE stored_name=? AND username=?",
        (stored_name, session["user_name"])
    )

    conn.commit()
    conn.close()

    return redirect("/files")


# ---------------- FORGOT PASSWORD ----------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form["email"]
        new_password = request.form["password"]

        hashed_password = generate_password_hash(new_password)

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE users SET password=? WHERE email=?",
            (hashed_password, email)
        )

        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("forgot_password.html")


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.pop("user_name", None)
    return redirect("/login")


# ---------------- PROFILE ----------------
@app.route("/profile")
def profile():

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT name, email FROM users WHERE name=?",
        (session["user_name"],)
    )

    user = cursor.fetchone()

    cursor.execute(
        "SELECT COUNT(*) FROM files WHERE username=?",
        (session["user_name"],)
    )

    total_files = cursor.fetchone()[0]

    total_size = 0

    cursor.execute(
        "SELECT stored_name FROM files WHERE username=?",
        (session["user_name"],)
    )

    files = cursor.fetchall()

    for file in files:
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file[0])
        if os.path.exists(filepath):
            total_size += os.path.getsize(filepath)

    storage_mb = round(total_size / (1024 * 1024), 2)

    conn.close()

    return render_template(
        "profile.html",
        user=user,
        total_files=total_files,
        storage_mb=storage_mb
    )


if __name__ == "__main__":
    app.run(debug=True)
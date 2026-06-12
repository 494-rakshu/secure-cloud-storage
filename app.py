from flask import Flask, render_template, request, redirect, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import uuid

app = Flask(__name__)
app.secret_key = "secure_cloud_storage"

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf", "txt"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
def home():
    return render_template("home.html")


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


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        )

        user = cursor.fetchone()

        if user and check_password_hash(user[3], password):

            # -------------------------
            # SESSION LOGIN
            # -------------------------
            session["user_name"] = user[1]

            # -------------------------
            # LOGIN TIME LOGGING
            # -------------------------
            import datetime
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


@app.route("/dashboard")
def dashboard():

    if "user_name" not in session:
        return redirect("/login")

    return render_template("dashboard.html", user_name=session["user_name"])


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

            # duplicate check
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

            # store UNIQUE filename (IMPORTANT FIX)
            cursor.execute(
                "INSERT INTO files(filename, stored_name, username) VALUES(?, ?, ?)",
                (original_name, unique_name, session["user_name"])
            )

            conn.commit()
            conn.close()

            return redirect("/files")

        return "Invalid file type"

    return render_template("upload.html")


@app.route("/files")
def files():

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT filename, stored_name FROM files WHERE username=?",
        (session["user_name"],)
    )

    data = cursor.fetchall()
    conn.close()

    return render_template("files.html", files=data)

@app.route("/storage")
def storage():

    if "user_name" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT filename FROM files WHERE username=?",
        (session["user_name"],)
    )

    files = cursor.fetchall()
    conn.close()

    file_count = len(files)

    # estimate storage (fake realistic value for project)
    storage_used_kb = file_count * 120  # assume avg file size 120KB
    storage_used_mb = round(storage_used_kb / 1024, 2)

    return render_template(
        "storage.html",
        file_count=file_count,
        storage_used_mb=storage_used_mb
    )


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

@app.route("/download/<filename>")
def download_file(filename):

    if "user_name" not in session:
        return redirect("/login")

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename,
        as_attachment=True
    )


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


@app.route("/logout")
def logout():

    session.pop("user_name", None)
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)
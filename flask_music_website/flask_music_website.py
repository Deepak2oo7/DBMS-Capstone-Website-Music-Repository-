"""
flask_music_website.py
------------------------------------------------------------------
A simple Flask + MySQL "Music Repository" web application.

Features:
    1. User signup / login / logout (session based auth)
    2. A user-owned "Music Track" library (CRUD)
    3. MP3 file upload (stored on local disk, path stored in DB)
    4. Optional album image upload for each track
    5. A "Play History" table that logs every time a track is played
       (acts as a simple version/listen history for that song)
    6. In-browser audio player with a seek slider (HTML5 <audio>)

Everything lives in this one file on purpose (as requested) so it is
easy to read top-to-bottom. Templates / static files still need their
own folders because that is how Flask finds them.

Folder structure expected next to this file:

    flask_music_website.py
    templates/
        base.html
        login.html
        signup.html
        dashboard.html
        track_form.html
        track_history.html
    static/
        css/style.css
        js/script.js
        uploads/tracks/   <- uploaded mp3 files land here
        uploads/albums/   <- uploaded album images land here
------------------------------------------------------------------
"""

import os
import datetime

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import mysql.connector
from mysql.connector import Error as MySQLError


# ============================================================
# 1. APP CONFIGURATION
# ============================================================
app = Flask(__name__)

# Secret key is required by Flask to sign the session cookie.
# In production, load this from an environment variable instead.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-secret-key")

# ---- MySQL connection settings -------------------------------------------
# Edit these to match your local MySQL server before running the app.
DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "user": os.environ.get("DB_USER", "root"),
    "password": os.environ.get("DB_PASSWORD", "welcome@123"),
    "database": os.environ.get("DB_NAME", "music_repo_db"),
}

# ---- File upload settings --------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TRACK_UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads", "tracks")
ALBUM_UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads", "albums")
ALLOWED_TRACK_EXTENSIONS = {"mp3"}
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
MAX_CONTENT_LENGTH = 25 * 1024 * 1024  # 25 MB upload limit (mp3 + image)

app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# Make sure the upload folders exist when the app starts.
os.makedirs(TRACK_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ALBUM_UPLOAD_FOLDER, exist_ok=True)


# ============================================================
# 2. DATABASE HELPERS
# ============================================================
def get_db():
    """
    Open a fresh MySQL connection.
    We open/close a connection per-request instead of holding one
    connection open forever - simpler and safer for a small app.
    """
    return mysql.connector.connect(**DB_CONFIG)


def init_db():
    """
    Create the database (if missing) and the three tables we need:
        users          -> our "userModel"
        music_tracks   -> each uploaded song, owned by a user
        play_history   -> one row per time a track was played (the
                          "version history of songs played")
    Run once automatically when the app starts.
    """
    # Step 1: connect WITHOUT selecting a database, so we can create it.
    conn = mysql.connector.connect(
        host=DB_CONFIG["host"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
    )
    cursor = conn.cursor()
    cursor.execute(
        f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']} "
        "CHARACTER SET utf8mb4"
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Step 2: connect to the real database and create tables.
    conn = get_db()
    cursor = conn.cursor()

    # ---- users table (the "userModel") ----
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(80) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            created_at DATETIME NOT NULL
        ) ENGINE=InnoDB
    """)

    # ---- music_tracks table ----
    # user_id is a FOREIGN KEY back to users.id, exactly as requested.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS music_tracks (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            title VARCHAR(150) NOT NULL,
            genre VARCHAR(80),
            track_path VARCHAR(255) NOT NULL,
            album_image_path VARCHAR(255),
            created_at DATETIME NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB
    """)

    # ---- play_history table ----
    # Logs every play event for a track -> a simple "version history"
    # of when/how many times a song was played, per user.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS play_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            track_id INT NOT NULL,
            user_id INT NOT NULL,
            played_at DATETIME NOT NULL,
            FOREIGN KEY (track_id) REFERENCES music_tracks(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB
    """)

    conn.commit()
    cursor.close()
    conn.close()


def allowed_file(filename, allowed_extensions):
    """Check a filename has one of the allowed extensions."""
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in allowed_extensions
    )


# ============================================================
# 3. AUTH HELPERS
# ============================================================
def current_user():
    """Return the logged-in user's row (dict) or None."""
    if "user_id" not in session:
        return None
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, name FROM users WHERE id = %s", (session["user_id"],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user


def login_required(view_func):
    """
    Decorator: redirect to /login if nobody is logged in.
    Put @login_required under @app.route(...) on any protected page.
    """
    from functools import wraps

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped


# Make the current user available inside every template automatically.
@app.context_processor
def inject_user():
    return {"logged_in_user": current_user()}


# ============================================================
# 4. AUTH ROUTES: signup / login / logout
# ============================================================
@app.route("/")
def home():
    """Root route: send logged-in users to the dashboard, others to login."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Create a new user account."""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # ---- basic validation ----
        if not name or not password:
            flash("Name and password are required.", "error")
            return redirect(url_for("signup"))
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("signup"))

        hashed_password = generate_password_hash(password)

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (name, password, created_at) VALUES (%s, %s, %s)",
                (name, hashed_password, datetime.datetime.now()),
            )
            conn.commit()
        except MySQLError:
            # Most likely a duplicate username (UNIQUE constraint).
            flash("That username is already taken.", "error")
            return redirect(url_for("signup"))
        finally:
            cursor.close()
            conn.close()

        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log an existing user in and start a session."""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        # check_password_hash safely compares the hash, never plain text.
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            flash(f"Welcome back, {user['name']}!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Clear the session and log the user out."""
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# ============================================================
# 5. DASHBOARD (READ - list all tracks owned by the user)
# ============================================================
@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT id, title, genre, track_path, album_image_path, created_at
        FROM music_tracks
        WHERE user_id = %s
        ORDER BY created_at DESC
        """,
        (session["user_id"],),
    )
    tracks = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("dashboard.html", tracks=tracks)


# ============================================================
# 6. TRACK CREATE
# ============================================================
@app.route("/track/new", methods=["GET", "POST"])
@login_required
def track_new():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        genre = request.form.get("genre", "").strip()
        mp3_file = request.files.get("mp3_file")
        album_image = request.files.get("album_image")  # optional

        if not title or not mp3_file or mp3_file.filename == "":
            flash("Title and an MP3 file are required.", "error")
            return redirect(url_for("track_new"))

        if not allowed_file(mp3_file.filename, ALLOWED_TRACK_EXTENSIONS):
            flash("Only .mp3 files are allowed for tracks.", "error")
            return redirect(url_for("track_new"))

        # ---- save the mp3 file to disk with a unique-ish filename ----
        safe_name = secure_filename(mp3_file.filename)
        unique_name = f"{session['user_id']}_{int(datetime.datetime.now().timestamp())}_{safe_name}"
        disk_path = os.path.join(TRACK_UPLOAD_FOLDER, unique_name)
        mp3_file.save(disk_path)
        # Store a path RELATIVE to /static so templates can build a URL easily.
        track_path = f"uploads/tracks/{unique_name}"

        # ---- optional album image ----
        album_image_path = None
        if album_image and album_image.filename != "":
            if allowed_file(album_image.filename, ALLOWED_IMAGE_EXTENSIONS):
                safe_img_name = secure_filename(album_image.filename)
                unique_img_name = f"{session['user_id']}_{int(datetime.datetime.now().timestamp())}_{safe_img_name}"
                album_image.save(os.path.join(ALBUM_UPLOAD_FOLDER, unique_img_name))
                album_image_path = f"uploads/albums/{unique_img_name}"
            else:
                flash("Album image ignored: unsupported file type.", "error")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO music_tracks
                (user_id, title, genre, track_path, album_image_path, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (session["user_id"], title, genre, track_path, album_image_path,
             datetime.datetime.now()),
        )
        conn.commit()
        cursor.close()
        conn.close()

        flash("Track uploaded successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("track_form.html", mode="new", track=None)


# ============================================================
# 7. TRACK UPDATE
# ============================================================
@app.route("/track/<int:track_id>/edit", methods=["GET", "POST"])
@login_required
def track_edit(track_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM music_tracks WHERE id = %s AND user_id = %s",
        (track_id, session["user_id"]),
    )
    track = cursor.fetchone()

    if track is None:
        cursor.close()
        conn.close()
        abort(404)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        genre = request.form.get("genre", "").strip()
        mp3_file = request.files.get("mp3_file")          # optional replace
        album_image = request.files.get("album_image")    # optional replace

        if not title:
            flash("Title is required.", "error")
            return redirect(url_for("track_edit", track_id=track_id))

        track_path = track["track_path"]
        album_image_path = track["album_image_path"]

        # ---- replace mp3 file only if a new one was uploaded ----
        if mp3_file and mp3_file.filename != "":
            if not allowed_file(mp3_file.filename, ALLOWED_TRACK_EXTENSIONS):
                flash("Only .mp3 files are allowed for tracks.", "error")
                return redirect(url_for("track_edit", track_id=track_id))
            safe_name = secure_filename(mp3_file.filename)
            unique_name = f"{session['user_id']}_{int(datetime.datetime.now().timestamp())}_{safe_name}"
            mp3_file.save(os.path.join(TRACK_UPLOAD_FOLDER, unique_name))
            track_path = f"uploads/tracks/{unique_name}"

        # ---- replace album image only if a new one was uploaded ----
        if album_image and album_image.filename != "":
            if allowed_file(album_image.filename, ALLOWED_IMAGE_EXTENSIONS):
                safe_img_name = secure_filename(album_image.filename)
                unique_img_name = f"{session['user_id']}_{int(datetime.datetime.now().timestamp())}_{safe_img_name}"
                album_image.save(os.path.join(ALBUM_UPLOAD_FOLDER, unique_img_name))
                album_image_path = f"uploads/albums/{unique_img_name}"
            else:
                flash("Album image ignored: unsupported file type.", "error")

        cursor2 = conn.cursor()
        cursor2.execute(
            """
            UPDATE music_tracks
            SET title = %s, genre = %s, track_path = %s, album_image_path = %s
            WHERE id = %s AND user_id = %s
            """,
            (title, genre, track_path, album_image_path, track_id, session["user_id"]),
        )
        conn.commit()
        cursor2.close()
        cursor.close()
        conn.close()

        flash("Track updated.", "success")
        return redirect(url_for("dashboard"))

    cursor.close()
    conn.close()
    return render_template("track_form.html", mode="edit", track=track)


# ============================================================
# 8. TRACK DELETE
# ============================================================
@app.route("/track/<int:track_id>/delete", methods=["POST"])
@login_required
def track_delete(track_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM music_tracks WHERE id = %s AND user_id = %s",
        (track_id, session["user_id"]),
    )
    track = cursor.fetchone()
    if track is None:
        cursor.close()
        conn.close()
        abort(404)

    # Remove the row (play_history rows cascade-delete automatically).
    cursor2 = conn.cursor()
    cursor2.execute(
        "DELETE FROM music_tracks WHERE id = %s AND user_id = %s",
        (track_id, session["user_id"]),
    )
    conn.commit()
    cursor2.close()
    cursor.close()
    conn.close()

    # Best-effort: remove the physical files too.
    for rel_path in (track["track_path"], track["album_image_path"]):
        if rel_path:
            full_path = os.path.join(BASE_DIR, "static", rel_path)
            if os.path.exists(full_path):
                os.remove(full_path)

    flash("Track deleted.", "success")
    return redirect(url_for("dashboard"))


# ============================================================
# 9. PLAY HISTORY (logs a play + shows history for a track)
# ============================================================
@app.route("/track/<int:track_id>/log-play", methods=["POST"])
@login_required
def track_log_play(track_id):
    """
    Called automatically (via JS) when the user presses play in the
    browser. Inserts one row into play_history -> this is the
    "version history of songs played".
    """
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT id FROM music_tracks WHERE id = %s AND user_id = %s",
        (track_id, session["user_id"]),
    )
    track = cursor.fetchone()
    if track is None:
        cursor.close()
        conn.close()
        return {"status": "error", "message": "Track not found"}, 404

    cursor2 = conn.cursor()
    cursor2.execute(
        "INSERT INTO play_history (track_id, user_id, played_at) VALUES (%s, %s, %s)",
        (track_id, session["user_id"], datetime.datetime.now()),
    )
    conn.commit()
    cursor2.close()
    cursor.close()
    conn.close()
    return {"status": "ok"}


@app.route("/track/<int:track_id>/history")
@login_required
def track_history(track_id):
    """Show the full play history (every play event) for one track."""
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM music_tracks WHERE id = %s AND user_id = %s",
        (track_id, session["user_id"]),
    )
    track = cursor.fetchone()
    if track is None:
        cursor.close()
        conn.close()
        abort(404)

    cursor.execute(
        """
        SELECT id, played_at FROM play_history
        WHERE track_id = %s AND user_id = %s
        ORDER BY played_at DESC
        """,
        (track_id, session["user_id"]),
    )
    history = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("track_history.html", track=track, history=history)


# ============================================================
# 10. RUN THE APP
# ============================================================
if __name__ == "__main__":
    init_db()          # create DB/tables automatically on first run
    app.run(debug=True)

import sqlite3
from pathlib import Path

DATABASE = Path(__file__).resolve().with_name("attendance.db")


def get_db():
    return sqlite3.connect(str(DATABASE))


def init_db():

    db = get_db()
    cursor = db.cursor()

    # Students table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL
        )
    """)

    # Attendance table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT,
            date TEXT,
            status TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY COLLATE NOCASE,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            is_verified INTEGER NOT NULL DEFAULT 1
        )
    """)

    user_columns = {
        row[1] for row in cursor.execute("PRAGMA table_info(users)").fetchall()
    }
    if "is_verified" not in user_columns:
        cursor.execute(
            "ALTER TABLE users ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 1"
        )

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pending_signups (
            email TEXT PRIMARY KEY COLLATE NOCASE,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            otp_hash TEXT NOT NULL,
            expires_at REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_otps (
            email TEXT PRIMARY KEY COLLATE NOCASE,
            otp_hash TEXT NOT NULL,
            expires_at REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        )
    """)

    db.commit()
    db.close()


def create_user(email, name, password_hash, *, is_verified=True):
    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO users (email, name, password_hash, is_verified)
            VALUES (?, ?, ?, ?)
            """,
            (email, name, password_hash, int(is_verified)),
        )
        db.commit()
    finally:
        db.close()


def get_user(email):
    db = get_db()
    try:
        return db.execute(
            "SELECT email, name, password_hash, is_verified FROM users WHERE email = ?",
            (email,),
        ).fetchone()
    finally:
        db.close()


def save_pending_signup(email, name, password_hash, otp_hash, expires_at, created_at):
    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO pending_signups
                (email, name, password_hash, otp_hash, expires_at, attempts, created_at)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(email) DO UPDATE SET
                name = excluded.name,
                password_hash = excluded.password_hash,
                otp_hash = excluded.otp_hash,
                expires_at = excluded.expires_at,
                attempts = 0,
                created_at = excluded.created_at
            """,
            (email, name, password_hash, otp_hash, expires_at, created_at),
        )
        db.commit()
    finally:
        db.close()


def get_pending_signup(email):
    db = get_db()
    try:
        return db.execute(
            """
            SELECT email, name, password_hash, otp_hash, expires_at, attempts, created_at
            FROM pending_signups WHERE email = ?
            """,
            (email,),
        ).fetchone()
    finally:
        db.close()


def increment_signup_otp_attempts(email):
    db = get_db()
    try:
        db.execute(
            "UPDATE pending_signups SET attempts = attempts + 1 WHERE email = ?",
            (email,),
        )
        db.commit()
    finally:
        db.close()


def activate_pending_signup(email):
    db = get_db()
    try:
        pending = db.execute(
            """
            SELECT name, password_hash FROM pending_signups WHERE email = ?
            """,
            (email,),
        ).fetchone()
        if pending is None:
            return False

        db.execute(
            """
            INSERT INTO users (email, name, password_hash, is_verified)
            VALUES (?, ?, ?, 1)
            """,
            (email, pending[0], pending[1]),
        )
        db.execute("DELETE FROM pending_signups WHERE email = ?", (email,))
        db.commit()
        return True
    finally:
        db.close()


def delete_pending_signup(email):
    db = get_db()
    try:
        db.execute("DELETE FROM pending_signups WHERE email = ?", (email,))
        db.commit()
    finally:
        db.close()


def save_password_reset_otp(email, otp_hash, expires_at, created_at):
    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO password_reset_otps (email, otp_hash, expires_at, attempts, created_at)
            VALUES (?, ?, ?, 0, ?)
            ON CONFLICT(email) DO UPDATE SET
                otp_hash = excluded.otp_hash,
                expires_at = excluded.expires_at,
                attempts = 0,
                created_at = excluded.created_at
            """,
            (email, otp_hash, expires_at, created_at),
        )
        db.commit()
    finally:
        db.close()


def get_password_reset_otp(email):
    db = get_db()
    try:
        return db.execute(
            """
            SELECT otp_hash, expires_at, attempts, created_at
            FROM password_reset_otps WHERE email = ?
            """,
            (email,),
        ).fetchone()
    finally:
        db.close()


def increment_password_reset_attempts(email):
    db = get_db()
    try:
        db.execute(
            "UPDATE password_reset_otps SET attempts = attempts + 1 WHERE email = ?",
            (email,),
        )
        db.commit()
    finally:
        db.close()


def delete_password_reset_otp(email):
    db = get_db()
    try:
        db.execute("DELETE FROM password_reset_otps WHERE email = ?", (email,))
        db.commit()
    finally:
        db.close()


def update_user_password(email, password_hash):
    db = get_db()
    try:
        cursor = db.execute(
            "UPDATE users SET password_hash = ? WHERE email = ?",
            (password_hash, email),
        )
        db.commit()
        return cursor.rowcount > 0
    finally:
        db.close()
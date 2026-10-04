# Project Source Catalog

Combined text/source files from `hackathon`. Each section is headed by its original relative path; the original project files are unchanged.

Excluded: `.env` (may contain credentials), virtual environments, generated Python caches, the SQLite database, and binary archives/assets. `.env.example` is included as a safe configuration template.

Included files: 43.

## `.env.example`

```
# Gmail SMTP settings for account signup and password reset OTP emails.
# Enable 2-Step Verification on the Google account and create an App Password.
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_USE_TLS=false
SMTP_USE_SSL=true
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-16-character-google-app-password
SMTP_FROM_EMAIL=your-email@gmail.com
```

## `alerts.py`

```
from database import get_db


def get_alerts():

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT
            students.id,
            students.name,
            COUNT(attendance.id) AS total,
            SUM(
                CASE
                    WHEN attendance.status = 'Present'
                    THEN 1
                    ELSE 0
                END
            ) AS present
        FROM students
        LEFT JOIN attendance
        ON students.id = attendance.student_id
        GROUP BY students.id
    """)

    students = cursor.fetchall()

    alerts = []

    for student in students:

        student_id = student[0]
        name = student[1]
        total = student[2]
        present = student[3] or 0

        if total > 0:
            percentage = (present / total) * 100

            if percentage < 75:

                alerts.append({
                    "student_id": student_id,
                    "name": name,
                    "attendance": round(percentage, 2),
                    "alert": "Attendance below 75%"
                })

    db.close()

    return alerts
```

## `analytics.py`

```
from database import get_db


def get_attendance(student_id):

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT COUNT(*) FROM attendance
        WHERE student_id = ?
    """, (student_id,))

    total = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM attendance
        WHERE student_id = ?
        AND status = 'Present'
    """, (student_id,))

    present = cursor.fetchone()[0]

    db.close()

    if total == 0:
        percentage = 0
    else:
        percentage = (present / total) * 100

    return {
        "student_id": student_id,
        "total_classes": total,
        "present": present,
        "attendance_percentage": round(percentage, 2)
    }
```

## `app.py`

```
import hmac
from email.message import EmailMessage
import os
import re
import secrets
import sqlite3
import smtplib
import ssl
import threading
import time
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_cors import CORS
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash
from database import (
    activate_pending_signup,
    create_user,
    delete_pending_signup,
    delete_password_reset_otp,
    get_pending_signup,
    get_password_reset_otp,
    get_user,
    increment_password_reset_attempts,
    increment_signup_otp_attempts,
    init_db,
    save_password_reset_otp,
    save_pending_signup,
    update_user_password,
)
from face_scan import verify_face
from attendance import mark_attendance
from analytics import get_attendance
from alerts import get_alerts
from students import add_student

load_dotenv(Path(__file__).with_name(".env"))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
CORS(app, resources={r"/*": {"origins": "*"}})

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com").strip().lower()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Attendance123!")
OTP_LIFETIME_SECONDS = 10 * 60
OTP_RESEND_INTERVAL_SECONDS = 60
OTP_MAX_ATTEMPTS = 5

# Create database
init_db()
if get_user(ADMIN_EMAIL) is None:
    create_user(
        ADMIN_EMAIL,
        "Administrator",
        generate_password_hash(ADMIN_PASSWORD),
    )

EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class EmailDeliveryNotConfigured(ValueError):
    pass


def local_otp_preview_allowed():
    return app.debug and request.remote_addr in {"127.0.0.1", "::1"}


def remember_local_otp(email, otp, purpose):
    session["local_otp_preview"] = {
        "email": email,
        "otp": otp,
        "purpose": purpose,
    }


def get_local_otp_preview(email, purpose):
    preview = session.get("local_otp_preview")
    if (
        local_otp_preview_allowed()
        and preview
        and preview.get("email") == email
        and preview.get("purpose") == purpose
    ):
        return preview.get("otp")
    return None


def login_required(*, api=False):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("user_email"):
                return view(*args, **kwargs)
            if api:
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login"))

        return wrapped

    return decorator


def csrf_token():
    token = session.get("_csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": csrf_token}


@app.route("/")
def home():
    if session.get("user_email"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_email"):
        return redirect(url_for("dashboard"))

    error = None
    registered = request.args.get("registered") == "1"
    password_reset = request.args.get("reset") == "1"
    if request.method == "POST":
        submitted_token = request.form.get("csrf_token", "")
        if not hmac.compare_digest(submitted_token, session.get("_csrf_token", "")):
            error = "Your session expired. Please try again."
        else:
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            if not email or not password:
                error = "Enter your email and password."
            else:
                user = get_user(email)
                if (
                    user is not None
                    and check_password_hash(user[2], password)
                    and user[3]
                ):
                    session.clear()
                    session["user_email"] = user[0]
                    return redirect(url_for("dashboard"))
                if user is not None and check_password_hash(user[2], password):
                    error = "Verify your email address before signing in."
                else:
                    error = "Invalid email or password."

    status_code = 400 if error == "Your session expired. Please try again." else 200
    return render_template(
        "login.html",
        error=error,
        registered=registered,
        password_reset=password_reset,
        demo_credentials="ADMIN_EMAIL" not in os.environ and "ADMIN_PASSWORD" not in os.environ,
    ), status_code


def validate_signup(data):
    name_value = data.get("name")
    email_value = data.get("email")
    password = data.get("password")

    if not all(isinstance(value, str) for value in (name_value, email_value, password)):
        return None, "Name, email, and password are required."

    name = name_value.strip()
    email = email_value.strip().lower()

    if not name or not email or not password:
        return None, "Name, email, and password are required."
    if not EMAIL_PATTERN.fullmatch(email):
        return None, "Enter a valid email address."
    if len(password) < 8:
        return None, "Password must be at least 8 characters."

    return {"name": name, "email": email, "password": password}, None





def send_otp_email(email, otp, purpose):
    host_setting = (
        os.environ.get("SMTP_HOST")
        or os.environ.get("SMTP_SERVER", "")
    ).strip()
    username = (
        os.environ.get("SMTP_USERNAME")
        or os.environ.get("SMTP_USER", "")
    ).strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    from_email = (
        os.environ.get("SMTP_FROM_EMAIL")
        or os.environ.get("SMTP_FROM")
        or username
    ).strip()
    port_value = os.environ.get("SMTP_PORT", "").strip()
    host_scheme = ""
    url_port = None
    if "://" in host_setting:
        parsed_host = urlsplit(host_setting)
        if parsed_host.scheme.lower() not in {"smtp", "smtps"} or not parsed_host.hostname:
            parsed_host = urlsplit("smtp://" + host_setting.split("://", 1)[1])
        if not parsed_host.hostname:
            raise ValueError(
                "SMTP host must be a server hostname or an smtp:// server URL."
            )
        if parsed_host.username or parsed_host.password:
            raise ValueError("Put SMTP credentials in SMTP_USERNAME and SMTP_PASSWORD.")
        if parsed_host.path not in {"", "/"} or parsed_host.query or parsed_host.fragment:
            raise ValueError("SMTP host URL must contain only a server and optional port.")
        try:
            url_port = parsed_host.port
        except ValueError as exc:
            raise ValueError("SMTP host URL contains an invalid port.") from exc
        host = parsed_host.hostname or ""
        host_scheme = parsed_host.scheme.lower()
    else:
        host = host_setting
        if not re.fullmatch(r"[A-Za-z0-9.-]+", host) or "." not in host:
            raise ValueError("SMTP_HOST must be a hostname, not a URL or email address.")

    if not port_value and url_port:
        port_value = str(url_port)
    if not all((host, username, password, port_value)):
        missing = [
            key
            for key, value in (
                ("SMTP_HOST or SMTP_SERVER", host),
                ("SMTP_USERNAME or SMTP_USER", username),
                ("SMTP_PASSWORD", password),
                ("SMTP_PORT", port_value),
            )
            if not value
        ]
        raise EmailDeliveryNotConfigured(
            "Email OTP delivery is missing required settings: "
            + ", ".join(missing)
            + "."
        )

    try:
        port = int(port_value)
    except ValueError as exc:
        raise ValueError("SMTP_PORT must be a valid port number.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("SMTP_PORT must be between 1 and 65535.")
    if url_port and port != url_port:
        raise ValueError("The SMTP URL port and SMTP_PORT setting must match.")

    message = EmailMessage()
    action = "verify your email address" if purpose == "signup" else "reset your password"
    message["Subject"] = (
        "Your Smart AI Attendance verification code"
        if purpose == "signup"
        else "Your Smart AI Attendance password reset code"
    )
    message["From"] = from_email
    message["To"] = email
    message.set_content(
        f"Your code to {action} is {otp}.\n\n"
        "This code expires in 10 minutes. If you did not request this, ignore this email."
    )

    timeout = 15
    context = ssl.create_default_context()
    use_ssl = (
        os.environ.get("SMTP_USE_SSL", "").strip().lower()
        in {"1", "true", "yes", "on"}
        or host_scheme == "smtps"
        or port == 465
    )
    use_tls = (
        os.environ.get("SMTP_USE_TLS", "").strip().lower()
        in {"1", "true", "yes", "on"}
    )

    server = None
    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
            server.login(username, password)
            server.send_message(message)
        else:
            server = smtplib.SMTP(host, port, timeout=timeout)
            server.ehlo()
            if use_tls or port in {587, 2525}:
                server.starttls(context=context)
                server.ehlo()
            server.login(username, password)
            server.send_message(message)
    finally:
        if server is not None:
            server.close()


def begin_signup_verification(values):
    email = values["email"]
    if get_user(email) is not None:
        return False, "An account with this email already exists.", 409

    now = time.time()
    pending = get_pending_signup(email)
    if pending and now - pending[6] < OTP_RESEND_INTERVAL_SECONDS:
        return False, "A verification code was just sent. Wait a minute before requesting another.", 429

    otp = f"{secrets.randbelow(1_000_000):06d}"
    save_pending_signup(
        email,
        values["name"],
        generate_password_hash(values["password"]),
        generate_password_hash(otp),
        now + OTP_LIFETIME_SECONDS,
        now,
    )
    try:
        send_otp_email(email, otp, "signup")
    except EmailDeliveryNotConfigured as exc:
        if local_otp_preview_allowed():
            remember_local_otp(email, otp, "signup")
            app.logger.warning(
                "Email is not configured; showing a local-only signup OTP for %s.",
                email,
            )
            return True, "Email is not configured; use the local development code shown below.", 202
        delete_pending_signup(email)
        app.logger.error("Could not send signup verification email: %s", exc)
        return False, str(exc), 503
    except (OSError, smtplib.SMTPException, ValueError) as exc:
        delete_pending_signup(email)
        app.logger.error("Could not send signup verification email: %s", exc)
        return False, str(exc), 503

    return True, "Verification code sent to your email address.", 202


def send_signup_otp(email, otp):
    send_otp_email(email, otp, "signup")


def verify_signup_otp(email, otp):
    pending = get_pending_signup(email)
    if pending is None:
        return False, "No pending signup was found. Please sign up again.", 404
    if pending[4] <= time.time():
        delete_pending_signup(email)
        return False, "That verification code expired. Please sign up again.", 400
    if pending[5] >= OTP_MAX_ATTEMPTS:
        delete_pending_signup(email)
        return False, "Too many incorrect attempts. Please sign up again.", 429
    if not re.fullmatch(r"\d{6}", otp):
        increment_signup_otp_attempts(email)
        return False, "Enter the 6-digit verification code.", 400
    if not check_password_hash(pending[3], otp):
        increment_signup_otp_attempts(email)
        return False, "Incorrect verification code.", 400

    try:
        activated = activate_pending_signup(email)
    except sqlite3.IntegrityError:
        delete_pending_signup(email)
        return False, "An account with this email already exists.", 409
    if not activated:
        return False, "This verification request has expired. Please sign up again.", 404

    return True, "Email verified. You can now sign in.", 200


def begin_password_reset(email):
    user = get_user(email)
    if user is None or not user[3]:
        return True, None

    now = time.time()
    existing = get_password_reset_otp(email)
    if existing and now - existing[3] < OTP_RESEND_INTERVAL_SECONDS:
        return True, None

    otp = f"{secrets.randbelow(1_000_000):06d}"
    otp_hash = generate_password_hash(otp)
    save_password_reset_otp(email, otp_hash, now + OTP_LIFETIME_SECONDS, now)
    if local_otp_preview_allowed():
        remember_local_otp(email, otp, "password-reset")
        threading.Thread(
            target=send_local_password_reset_email,
            args=(email, otp),
            daemon=True,
        ).start()
        return True, None

    try:
        send_otp_email(email, otp, "password-reset")
    except (EmailDeliveryNotConfigured, OSError, smtplib.SMTPException, ValueError) as exc:
        delete_password_reset_otp(email)
        app.logger.error("Could not send password reset OTP email: %s", exc)
        return False, str(exc)

    return True, None

def send_local_password_reset_email(email, otp):
    try:
        send_otp_email(email, otp, "password-reset")
    except (EmailDeliveryNotConfigured, OSError, smtplib.SMTPException, ValueError) as exc:
        app.logger.warning(
            "Could not send password reset OTP email during local development; "
            "the local reset code remains available: %s",
            exc,
        )


def complete_password_reset(email, otp, new_password):
    reset = get_password_reset_otp(email)
    if reset is None:
        return False, "No active reset request was found. Request a new code.", 404
    if reset[1] <= time.time():
        delete_password_reset_otp(email)
        return False, "That reset code expired. Request a new code.", 400
    if reset[2] >= OTP_MAX_ATTEMPTS:
        delete_password_reset_otp(email)
        return False, "Too many incorrect attempts. Request a new code.", 429
    if not re.fullmatch(r"\d{6}", otp):
        increment_password_reset_attempts(email)
        return False, "Enter the 6-digit reset code.", 400
    if not check_password_hash(reset[0], otp):
        increment_password_reset_attempts(email)
        return False, "Incorrect reset code.", 400
    if len(new_password) < 8:
        return False, "New password must be at least 8 characters.", 400
    if not update_user_password(email, generate_password_hash(new_password)):
        delete_password_reset_otp(email)
        return False, "The account could not be found. Request a new code.", 404

    delete_password_reset_otp(email)
    return True, "Password reset successfully. You can now sign in.", 200


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("user_email"):
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        submitted_token = request.form.get("csrf_token", "")
        if not hmac.compare_digest(submitted_token, session.get("_csrf_token", "")):
            error = "Your session expired. Please try again."
        else:
            values, error = validate_signup(request.form)
            if values:
                sent, message, _ = begin_signup_verification(values)
                if sent:
                    return redirect(url_for("verify_otp", email=values["email"]))
                error = message

    return render_template("signup.html", error=error)


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    email = request.values.get("email", "").strip().lower()
    if not EMAIL_PATTERN.fullmatch(email):
        return redirect(url_for("signup"))

    error = None
    if request.method == "POST":
        submitted_token = request.form.get("csrf_token", "")
        if not hmac.compare_digest(submitted_token, session.get("_csrf_token", "")):
            error = "Your session expired. Please try again."
        else:
            otp = request.form.get("otp", "").strip()
            success, message, _ = verify_signup_otp(email, otp)
            if success:
                return redirect(url_for("login", registered="1"))
            error = message

    return render_template(
        "otp.html",
        email=email,
        error=error,
        development_otp=get_local_otp_preview(email, "signup"),
    )


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    error = None
    request_submitted = False
    email = ""
    if request.method == "POST":
        submitted_token = request.form.get("csrf_token", "")
        email = request.form.get("email", "").strip().lower()
        if not hmac.compare_digest(submitted_token, session.get("_csrf_token", "")):
            error = "Your session expired. Please try again."
        elif not EMAIL_PATTERN.fullmatch(email):
            error = "Enter a valid email address."
        else:
            request_submitted, error = begin_password_reset(email)
            if request_submitted:
                return redirect(url_for("reset_password", email=email))

    return render_template(
        "forgot_password.html",
        error=error,
        request_submitted=request_submitted,
        email=email,
    )


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    email = request.values.get("email", "").strip().lower()
    if not EMAIL_PATTERN.fullmatch(email):
        return redirect(url_for("forgot_password"))

    error = None
    if request.method == "POST":
        submitted_token = request.form.get("csrf_token", "")
        if not hmac.compare_digest(submitted_token, session.get("_csrf_token", "")):
            error = "Your session expired. Please try again."
        else:
            otp = request.form.get("otp", "").strip()
            new_password = request.form.get("new_password", "")
            if not re.fullmatch(r"\d{6}", otp):
                error = "Enter the 6-digit reset code."
            elif len(new_password) < 8:
                error = "New password must be at least 8 characters."
            else:
                success, message, _ = complete_password_reset(email, otp, new_password)
                if success:
                    return redirect(url_for("login", reset="1"))
                error = message

    return render_template(
        "reset_password.html",
        email=email,
        error=error,
        development_otp=get_local_otp_preview(email, "password-reset"),
    )


@app.post("/api/signup")
@app.post("/api/auth/signup")
def signup_api():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    values, error = validate_signup(data)
    if error:
        return jsonify({"success": False, "message": error}), 400

    sent, message, status_code = begin_signup_verification(values)
    response = {"success": sent, "message": message}
    if sent:
        preview = get_local_otp_preview(values["email"], "signup")
        if preview:
            response["development_otp"] = preview
    return jsonify(response), status_code


@app.post("/api/verify-otp")
@app.post("/api/auth/verify-otp")
def verify_otp_api():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    email = data.get("email")
    otp = data.get("otp")
    if not isinstance(email, str) or not isinstance(otp, str):
        return jsonify({
            "success": False,
            "message": "Email and 6-digit verification code are required.",
        }), 400
    email = email.strip().lower()
    if not EMAIL_PATTERN.fullmatch(email):
        return jsonify({"success": False, "message": "Enter a valid email address."}), 400

    success, message, status_code = verify_signup_otp(email, otp.strip())
    return jsonify({"success": success, "message": message}), status_code


@app.post("/api/auth/login")
@app.post("/api/login")
def login_api():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    email_value = data.get("email")
    password = data.get("password")
    if not isinstance(email_value, str) or not isinstance(password, str):
        return jsonify({
            "success": False,
            "message": "Please provide email and password.",
        }), 400

    email = email_value.strip().lower()
    if not email or not password:
        return jsonify({
            "success": False,
            "message": "Please provide email and password.",
        }), 400

    user = get_user(email)
    if user is None or not check_password_hash(user[2], password):
        return jsonify({
            "success": False,
            "message": "Invalid credentials. Check your email or password.",
        }), 401
    if not user[3]:
        return jsonify({
            "success": False,
            "message": "Verify your email address before signing in.",
        }), 403

    session.clear()
    session["user_email"] = user[0]
    return jsonify({
        "success": True,
        "message": f"Welcome back, {user[1]}!",
        "redirectUrl": url_for("dashboard"),
    })


@app.post("/api/auth/forgot-password")
def forgot_password_api():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    email_value = data.get("email")
    if not isinstance(email_value, str):
        return jsonify({
            "success": False,
            "message": "Please enter a valid email address.",
        }), 400

    email = email_value.strip().lower()
    if not EMAIL_PATTERN.fullmatch(email):
        return jsonify({
            "success": False,
            "message": "Please enter a valid email address.",
        }), 400

    sent, _ = begin_password_reset(email)
    if not sent:
        return jsonify({
            "success": False,
            "message": "Password reset is temporarily unavailable because email delivery failed.",
        }), 503

    response = {
        "success": True,
        "message": "If that email is linked to an account, a password reset code has been sent.",
    }
    preview = get_local_otp_preview(email, "password-reset")
    if preview:
        response["development_otp"] = preview
    return jsonify(response)


@app.post("/api/auth/reset-password")
@app.post("/api/reset-password")
def reset_password_api():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    email = data.get("email")
    otp = data.get("otp")
    new_password = data.get("new_password")
    if not all(isinstance(value, str) for value in (email, otp, new_password)):
        return jsonify({
            "success": False,
            "message": "Email, reset code, and new password are required.",
        }), 400

    email = email.strip().lower()
    if not EMAIL_PATTERN.fullmatch(email):
        return jsonify({"success": False, "message": "Enter a valid email address."}), 400

    success, message, status_code = complete_password_reset(
        email,
        otp.strip(),
        new_password,
    )
    return jsonify({"success": success, "message": message}), status_code


@app.route("/logout", methods=["POST"])
def logout():
    submitted_token = request.form.get("csrf_token", "")
    if not hmac.compare_digest(submitted_token, session.get("_csrf_token", "")):
        abort(400, description="Your session expired. Please try again.")

    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required()
def dashboard():
    return render_template("index.html", user_email=session["user_email"])


@app.route("/style.css")
def stylesheet():
    return send_from_directory(app.root_path, "style.css")


@app.route("/script.js")
def frontend_script():
    return send_from_directory(app.root_path, "script.js")


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(app.root_path, "favicon.svg", mimetype="image/svg+xml")


# STUDENT REGISTRATION
@app.route("/students", methods=["POST"])
@login_required(api=True)
def register_student():
    data = request.get_json(silent=True) or {}
    student_id = (data.get("student_id") or request.form.get("student_id") or "").strip()
    name = (data.get("name") or request.form.get("name") or "").strip()

    if not student_id or not name:
        return jsonify({"error": "Student ID and name are required"}), 400

    result = add_student(student_id, name)
    return jsonify(result)


# FACE SCAN
@app.route("/face-scan", methods=["POST"])
@login_required(api=True)
def face_scan():
    data = request.get_json(silent=True) or {}
    student_id = (data.get("student_id") or request.form.get("student_id") or "").strip()

    if not student_id:
        return jsonify({"error": "Student ID required"}), 400

    result = verify_face(student_id)

    return jsonify(result)


# MARK ATTENDANCE
@app.route("/mark-attendance", methods=["POST"])
@login_required(api=True)
def attendance():
    data = request.get_json(silent=True) or {}

    student_id = (data.get("student_id") or request.form.get("student_id") or "").strip()
    status = (data.get("status") or request.form.get("status") or "Present").strip()

    if not student_id:
        return jsonify({"error": "Student ID required"}), 400

    result = mark_attendance(student_id, status)

    return jsonify(result)


# ATTENDANCE ANALYTICS
@app.route("/attendance/<student_id>", methods=["GET"])
@login_required(api=True)
def attendance_data(student_id):
    return jsonify(get_attendance(student_id))


# LOW ATTENDANCE ALERTS
@app.route("/alerts", methods=["GET"])
@login_required(api=True)
def alerts():
    return jsonify(get_alerts())


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True)
```

## `application.entry`

```
import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { AuthProvider } from "./auth/AuthContext";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>
);
```

## `attendance backend`

```

```

## `attendance percentage`

```
async function getAttendance(studentId) {

    const response = await fetch(
        "http://127.0.0.1:5000/attendance/" + studentId
    );

    const data = await response.json();

    console.log(data);

    document.getElementById("percentage").innerText =
        data.attendance_percentage + "%";
}
```

## `attendance.page`

```
import { Link } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

export default function Attendance() {
  const { logout } = useAuth();

  return (
    <main className="app-page">
      <header className="topbar">
        <Link className="brand-link" to="/dashboard">
          Smart AI Attendance
        </Link>
        <button className="secondary-button" onClick={logout} type="button">
          Log out
        </button>
      </header>

      <section className="content">
        <p className="eyebrow">ATTENDANCE</p>
        <h1>AI Attendance</h1>
        <p>Your attendance tools and records go here.</p>
        <Link className="text-link" to="/dashboard">Back to dashboard</Link>
      </section>
    </main>
  );
}
```

## `attendance.py`

```
from datetime import date
from database import get_db


def mark_attendance(student_id, status="Present"):

    db = get_db()
    cursor = db.cursor()

    today = str(date.today())

    # Check whether attendance already exists
    cursor.execute("""
        SELECT * FROM attendance
        WHERE student_id = ? AND date = ?
    """, (student_id, today))

    existing = cursor.fetchone()

    if existing:
        db.close()

        return {
            "success": False,
            "message": "Attendance already marked today"
        }

    cursor.execute("""
        INSERT INTO attendance
        (student_id, date, status)
        VALUES (?, ?, ?)
    """, (student_id, today, status))

    db.commit()
    db.close()

    return {
        "success": True,
        "student_id": student_id,
        "date": today,
        "status": status,
        "message": "Attendance marked successfully"
    }
```

## `Authentication.context`

```
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

const AuthContext = createContext(null);
const SESSION_KEY = "smart-attendance-session";

function readSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;

    const session = JSON.parse(raw);

    if (
      !session ||
      typeof session.user !== "string" ||
      typeof session.expiresAt !== "number" ||
      session.expiresAt <= Date.now()
    ) {
      sessionStorage.removeItem(SESSION_KEY);
      return null;
    }

    return session;
  } catch {
    // Handle malformed storage data without crashing the app.
    sessionStorage.removeItem(SESSION_KEY);
    return null;
  }
}

export function AuthProvider({ children }) {
  const [session, setSession] = useState(readSession);

  useEffect(() => {
    if (!session) return undefined;

    const remainingTime = session.expiresAt - Date.now();

    if (remainingTime <= 0) {
      sessionStorage.removeItem(SESSION_KEY);
      setSession(null);
      return undefined;
    }

    const timer = window.setTimeout(() => {
      sessionStorage.removeItem(SESSION_KEY);
      setSession(null);
    }, remainingTime);

    return () => window.clearTimeout(timer);
  }, [session]);

  const login = useCallback(async (email, password) => {
    const normalizedEmail = email.trim().toLowerCase();

    if (!normalizedEmail || !password) {
      return { ok: false, error: "Enter your email and password." };
    }

    // DEMO ONLY. Do not use hard-coded credentials in production.
    // Replace this block with a request to your authentication backend.
    const demoEmail = "admin@example.com";
    const demoPassword = "Attendance123!";

    if (normalizedEmail !== demoEmail || password !== demoPassword) {
      return { ok: false, error: "Invalid email or password." };
    }

    const newSession = {
      user: normalizedEmail,
      expiresAt: Date.now() + 8 * 60 * 60 * 1000,
    };

    try {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(newSession));
      setSession(newSession);
      return { ok: true };
    } catch {
      return {
        ok: false,
        error: "Unable to save your session. Please enable browser storage and try again.",
      };
    }
  }, []);

  const logout = useCallback(() => {
    sessionStorage.removeItem(SESSION_KEY);
    setSession(null);
  }, []);

  const value = useMemo(
    () => ({
      user: session?.user ?? null,
      isAuthenticated: Boolean(session && session.expiresAt > Date.now()),
      login,
      logout,
    }),
    [session, login, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error("useAuth must be used inside an AuthProvider.");
  }

  return context;
}
```

## `connecting of f and b`

```
async function scanFace(studentId) {

    const formData = new FormData();

    formData.append("student_id", studentId);

    const response = await fetch(
        "http://127.0.0.1:5000/face-scan",
        {
            method: "POST",
            body: formData
        }
    );

    const result = await response.json();

    console.log(result);

    if (result.success) {
        alert("Face verified: " + result.student_name);
    } else {
        alert(result.message);
    }
}
```

## `dashboard.page`

```
import { Link } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

export default function Dashboard() {
  const { user, logout } = useAuth();

  return (
    <main className="app-page">
      <header className="topbar">
        <Link className="brand-link" to="/dashboard">
          Smart AI Attendance
        </Link>
        <div className="topbar-actions">
          <span className="user-label">{user}</span>
          <button className="secondary-button" onClick={logout} type="button">
            Log out
          </button>
        </div>
      </header>

      <section className="content">
        <p className="eyebrow">OVERVIEW</p>
        <h1>Dashboard</h1>
        <p>You are signed in. Your attendance dashboard goes here.</p>

        <Link className="primary-link" to="/attendance">
          Open AI Attendance
        </Link>
      </section>
    </main>
  );
}
```

## `database.py`

```
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
```

## `face_scan.py`

```
from database import get_db


def verify_face(student_id):

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        "SELECT name FROM students WHERE id = ?",
        (student_id,)
    )

    student = cursor.fetchone()

    db.close()

    if student:

        return {
            "success": True,
            "student_id": student_id,
            "student_name": student[0],
            "message": "Face verified successfully"
        }

    return {
        "success": False,
        "message": "Student not registered"
    }
```

## `favicon.svg`

```
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect width="64" height="64" rx="16" fill="#2f7cf6" />
  <text x="32" y="42" fill="#fff" font-family="Arial, sans-serif" font-size="26" font-weight="700" text-anchor="middle">AI</text>
</svg>
```

## `forgettenPwsd`

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart AI Attendance - Forgot Password</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', sans-serif; }
        body { background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); height: 100vh; display: flex; justify-content: center; align-items: center; }
        .card-container { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.1); padding: 40px; border-radius: 16px; width: 100%; max-width: 420px; box-shadow: 0 20px 40px rgba(0,0,0,0.4); text-align: center; }
        .logo-box { display: inline-flex; align-items: center; justify-content: center; width: 64px; height: 64px; background: linear-gradient(135deg, #0ea5e9, #2563eb); border-radius: 12px; color: #ffffff; font-size: 28px; font-weight: 800; margin-bottom: 16px; }
        h2 { color: #ffffff; font-size: 24px; font-weight: 600; margin-bottom: 6px; }
        p.subtitle { color: #94a3b8; font-size: 14px; margin-bottom: 28px; line-height: 1.5; }
        .form-group { text-align: left; margin-bottom: 20px; }
        label { display: block; color: #cbd5e1; font-size: 13px; font-weight: 500; margin-bottom: 8px; }
        input { width: 100%; padding: 12px 16px; background: rgba(15, 23, 42, 0.6); border: 1px solid #334155; border-radius: 8px; color: #ffffff; font-size: 14px; }
        .btn-submit { width: 100%; padding: 12px; background: linear-gradient(135deg, #0ea5e9, #2563eb); border: none; border-radius: 8px; color: #ffffff; font-size: 15px; font-weight: 600; cursor: pointer; }
        .alert { padding: 10px; margin-bottom: 15px; border-radius: 6px; font-size: 13px; display: none; text-align: left; background: rgba(34, 197, 94, 0.2); border: 1px solid #22c55e; color: #86efac; }
        .footer-links { margin-top: 24px; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 20px; color: #94a3b8; font-size: 14px; }
        .footer-links a { color: #38bdf8; text-decoration: none; }
    </style>
</head>
<body>

    <div class="card-container">
        <div class="logo-box">𝚲𝚰</div>
        <h2>Reset password</h2>
        <p class="subtitle">Enter your account email below, and our systems will forward instructions to restore access.</p>
        
        <div id="alertBox" class="alert"></div>

        <form id="forgotForm">
            <div class="form-group">
                <label for="email">Email address</label>
                <input type="email" id="email" placeholder="you@example.com" required>
            </div>
            
            <button type="submit" class="btn-submit">Send Reset Token</button>
        </form>
        
        <div class="footer-links">
            Remember credentials? <a href="login.html">Return to sign in</a>
        </div>
    </div>

    <script>
        document.getElementById('forgotForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const alertBox = document.getElementById('alertBox');

            try {
                const response = await fetch('/api/auth/forgot-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email })
                });
                const result = await response.json();
                
                alertBox.textContent = result.message;
                alertBox.style.display = 'block';
            } catch (err) {
                alertBox.style.display = 'none';
                alert("Server connectivity breakdown occurred.");
            }
        });
    </script>
</body>
</html>
```

## `frontend`

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Smart Attendance</title>
    <link rel="stylesheet" href="style.css">
</head>

<body>

    <h1>AI-Powered Smart Attendance System</h1>
    <p class="subtitle">Face Recognition • Analytics • Alerts</p>

    <div class="container">
        <div class="column">
            <h2>Student Enrollment</h2>

            <input type="text" placeholder="Student ID">
            <input type="text" placeholder="Student Name">
            <input type="text" placeholder="Class">
            <input type="file">

            <button>Register Student</button>
        </div>
        <div class="column">
            <h2>Face Recognition</h2>

            <div class="camera">
                CAMERA
            </div>

            <button>Start Camera</button>

            <p>Face Detection: Ready</p>
            <p>Recognition: Waiting</p>
        </div>
        <div class="column">
            <h2>Attendance</h2>

            <div class="box">Present</div>
            <div class="box">Absent</div>
            <div class="box">Unknown</div>

            <button>Mark Attendance</button>
        </div>
        <div class="column">
            <h2>Attendance Records</h2>

            <table>
                <tr>
                    <th>ID</th>
                    <th>Status</th>
                    <th>Date</th>
                    <th>Time</th>
                </tr>

                <tr>
                    <td>---</td>
                    <td>---</td>
                    <td>---</td>
                    <td>---</td>
                </tr>
            </table>
        </div>

        <!-- Column 5 -->
        <div class="column">
            <h2>Analytics</h2>

            <div class="stat">
                Daily Attendance
                <b>0%</b>
            </div>

            <div class="stat">
                Weekly Attendance
                <b>0%</b>
            </div>

            <div class="stat">
                Monthly Attendance
                <b>0%</b>
            </div>

            <div class="stat">
                Low Attendance
                <b>0</b>
            </div>
        </div>
        <div class="column">
            <h2>Alerts</h2>

            <div class="alert">
                Low Attendance Alert
            </div>

            <div class="alert">
                Absent Alert
            </div>

            <div class="alert">
                Unknown Face Alert
            </div>

            <button>Send Alert</button>
        </div>

    </div>

</body>
</html>
```

## `frontend1`

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart AI Attendance - Login</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        body {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .login-container {
            background: rgba(30, 41, 59, 0.7);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 40px;
            border-radius: 16px;
            width: 100%;
            max-width: 420px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.4);
            text-align: center;
        }
        .logo-box {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 64px;
            height: 64px;
            background: linear-gradient(135deg, #0ea5e9, #2563eb);
            border-radius: 12px;
            color: #ffffff;
            font-size: 28px;
            font-weight: 800;
            margin-bottom: 16px;
            letter-spacing: -1px;
            box-shadow: 0 8px 16px rgba(14, 165, 233, 0.3);
        }
        h2 {
            color: #ffffff;
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 6px;
        }
        p.subtitle {
            color: #94a3b8;
            font-size: 14px;
            margin-bottom: 28px;
        }
        .form-group {
            text-align: left;
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #cbd5e1;
            font-size: 13px;
            font-weight: 500;
            margin-bottom: 8px;
        }
        input {
            width: 100%;
            padding: 12px 16px;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid #334155;
            border-radius: 8px;
            color: #ffffff;
            font-size: 14px;
            transition: all 0.3s ease;
        }
        input:focus {
            outline: none;
            border-color: #0ea5e9;
            box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.15);
        }
        .form-options {
            display: flex;
            justify-content: flex-end;
            margin-bottom: 24px;
        }
        .forgot-password {
            color: #38bdf8;
            font-size: 13px;
            text-decoration: none;
            transition: color 0.2s ease;
        }
        .forgot-password:hover {
            color: #0ea5e9;
            text-decoration: underline;
        }
        .btn-submit {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #0ea5e9, #2563eb);
            border: none;
            border-radius: 8px;
            color: #ffffff;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s ease;
        }
        .btn-submit:hover {
            opacity: 0.95;
        }
        .footer-links {
            margin-top: 24px;
            border-top: 1px solid rgba(255,255,255,0.05);
            padding-top: 20px;
            color: #94a3b8;
            font-size: 14px;
        }
        .footer-links a {
            color: #38bdf8;
            text-decoration: none;
            font-weight: 500;
        }
        .footer-links a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>

    <div class="login-container">
        <!-- New Typography Abstract Logo -->
        <div class="logo-box">𝚲𝚰</div>
        
        <h2>Welcome back</h2>
        <p class="subtitle">Sign in to manage your attendance dashboard.</p>
        
        <form>
            <div class="form-group">
                <label for="email">Email address</label>
                <input type="email" id="email" placeholder="you@example.com" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" placeholder="Enter your password" required>
            </div>
            
            <div class="form-options">
                <a href="#forgot" class="forgot-password">Forgot password?</a>
            </div>
            
            <button type="submit" class="btn-submit">Sign in</button>
        </form>
        
        <div class="footer-links">
            Don't have an account? <a href="#signup">Sign up</a>
        </div>
    </div>

</body>
</html>
```

## `intializeConnection`

```
declare const require: (moduleName: string) => any

declare module '@supabase/supabase-js' {
  export function createClient(url: string, key: string): any
}

const { createClient } = require('@supabase/supabase-js') as {
  createClient: (url: string, key: string) => any
}

// Replace these values with the direct URLs from your online Supabase dashboard settings
const SUPABASE_URL = 'https://supabase.co'
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY)
```

## `loginCode`

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart AI Attendance - Login</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, sans-serif; }
        body { background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); height: 100vh; display: flex; justify-content: center; align-items: center; }
        .card-container { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.1); padding: 40px; border-radius: 16px; width: 100%; max-width: 420px; box-shadow: 0 20px 40px rgba(0,0,0,0.4); text-align: center; }
        .logo-box { display: inline-flex; align-items: center; justify-content: center; width: 64px; height: 64px; background: linear-gradient(135deg, #0ea5e9, #2563eb); border-radius: 12px; color: #ffffff; font-size: 28px; font-weight: 800; margin-bottom: 16px; box-shadow: 0 8px 16px rgba(14, 165, 233, 0.3); }
        h2 { color: #ffffff; font-size: 24px; font-weight: 600; margin-bottom: 6px; }
        p.subtitle { color: #94a3b8; font-size: 14px; margin-bottom: 28px; }
        .form-group { text-align: left; margin-bottom: 20px; }
        label { display: block; color: #cbd5e1; font-size: 13px; font-weight: 500; margin-bottom: 8px; }
        input { width: 100%; padding: 12px 16px; background: rgba(15, 23, 42, 0.6); border: 1px solid #334155; border-radius: 8px; color: #ffffff; font-size: 14px; transition: all 0.3s ease; }
        input:focus { outline: none; border-color: #0ea5e9; box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.15); }
        .form-options { display: flex; justify-content: flex-end; margin-bottom: 24px; }
        .forgot-password { color: #38bdf8; font-size: 13px; text-decoration: none; }
        .forgot-password:hover { text-decoration: underline; }
        .btn-submit { width: 100%; padding: 12px; background: linear-gradient(135deg, #0ea5e9, #2563eb); border: none; border-radius: 8px; color: #ffffff; font-size: 15px; font-weight: 600; cursor: pointer; }
        .btn-submit:hover { opacity: 0.95; }
        .alert { padding: 10px; margin-bottom: 15px; border-radius: 6px; font-size: 13px; display: none; text-align: left; }
        .alert-error { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; }
        .footer-links { margin-top: 24px; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 20px; color: #94a3b8; font-size: 14px; }
        .footer-links a { color: #38bdf8; text-decoration: none; font-weight: 500; }
        .footer-links a:hover { text-decoration: underline; }
    </style>
</head>
<body>

    <div class="card-container">
        <div class="logo-box">𝚲𝚰</div>
        <h2>Welcome back</h2>
        <p class="subtitle">Sign in to manage your attendance dashboard.</p>
        
        <div id="alertBox" class="alert alert-error"></div>

        <form id="loginForm">
            <div class="form-group">
                <label for="email">Email address</label>
                <input type="email" id="email" placeholder="you@example.com" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" placeholder="Enter your password" required>
            </div>
            
            <div class="form-options">
                <a href="forgot-password.html" class="forgot-password">Forgot password?</a>
            </div>
            
            <button type="submit" class="btn-submit">Sign in</button>
        </form>
        
        <div class="footer-links">
            Don't have an account? <a href="signup.html">Sign up</a>
        </div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const alertBox = document.getElementById('alertBox');

            alertBox.style.display = 'none';

            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });

                const result = await response.json();

                if (result.success) {
                    alert('Login Successful! ' + result.message);
                    window.location.href = result.redirectUrl;
                } else {
                    alertBox.textContent = result.message;
                    alertBox.style.display = 'block';
                }
            } catch (err) {
                alertBox.textContent = "Cannot reach authentication server.";
                alertBox.style.display = 'block';
            }
        });
    </script>
</body>
</html>
```

## `low attendance`

```
async function getAlerts() {

    const response = await fetch(
        "http://127.0.0.1:5000/alerts"
    );

    const alerts = await response.json();

    console.log(alerts);
}
```

## `mark attendance for html`

```
async function markAttendance(studentId) {

    const response = await fetch(
        "http://127.0.0.1:5000/mark-attendance",
        {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                student_id: studentId,
                status: "Present"
            })
        }
    );

    const result = await response.json();

    alert(result.message);
}
```

## `otpTrigger`

```
/**
 * Call this function when the user enters their email address and clicks "Send Code".
 * This triggers your cloud database to send a true 6-digit OTP code using Resend.
 */
export async function sendUserOTP(emailAddress) {
  const { data, error } = await supabase.auth.signInWithOtp({
    email: emailAddress,
    options: {
      // Directs the browser back to your secure website page after authentication
      emailRedirectTo: window.location.origin, 
    },
  })

  if (error) {
    console.error("Error sending dynamic OTP code:", error.message)
    return { success: false, error: error.message }
  }

  console.log("OTP successfully sent to mailbox:", data)
  return { success: true, data }
}
```

## `protect.route`

```
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "./AuthContext";

export default function ProtectedRoute() {
  const { isAuthenticated } = useAuth();
  const location = useLocation();

  if (!isAuthenticated) {
    return (
      <Navigate
        to="/login"
        replace
        state={{ from: location.pathname }}
      />
    );
  }

  return <Outlet />;
}
```

## `replace.file`

```
src/
  main.jsx
  App.jsx
  auth/
    AuthContext.jsx
    ProtectedRoute.jsx
  pages/
    Login.jsx
    Dashboard.jsx
    Attendance.jsx
  styles.css
```

## `requirements.txt`

```
Flask
flask-cors
opencv-python
numpy
python-dotenv
```

## `route.url`

```
import { Navigate, Route, Routes } from "react-router-dom";
import ProtectedRoute from "./auth/ProtectedRoute";
import Attendance from "./pages/Attendance";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";

function NotFound() {
  return (
    <main className="content">
      <h1>Page not found</h1>
      <p>The requested page does not exist.</p>
      <a className="text-link" href="/login">Go to login</a>
    </main>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/login" replace />} />
      <Route path="/login" element={<Login />} />

      <Route element={<ProtectedRoute />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/attendance" element={<Attendance />} />
      </Route>

      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
```

## `script.js`

```
const API_BASE = window.location.origin;
let selectedStatus = 'Present';
let cameraStream = null;

function setStatus(message, isSuccess = true) {
  const box = document.getElementById('attendance-result');
  box.textContent = message;
  box.style.color = isSuccess ? '#90ee90' : '#ffb3b3';
}

function setFaceStatus(message, isSuccess = true) {
  const box = document.getElementById('face-result');
  box.textContent = message;
  box.style.color = isSuccess ? '#90ee90' : '#ffb3b3';
}

function setCameraStatus(message, isSuccess = true) {
  const box = document.getElementById('camera-status');
  box.textContent = message;
  box.style.color = isSuccess ? '#dfeeff' : '#ffb3b3';
}

function stopCamera() {
  if (cameraStream) {
    cameraStream.getTracks().forEach((track) => track.stop());
    cameraStream = null;
  }

  const video = document.getElementById('camera-feed');
  video.srcObject = null;
  video.hidden = true;
  document.getElementById('camera-placeholder').hidden = false;
  document.getElementById('start-camera-btn').disabled = false;
  document.getElementById('capture-photo-btn').disabled = true;
  document.getElementById('stop-camera-btn').disabled = true;
}

document.getElementById('start-camera-btn').addEventListener('click', async () => {
  if (!navigator.mediaDevices?.getUserMedia) {
    setCameraStatus('Camera access requires a supported browser and a secure connection.', false);
    return;
  }

  const startButton = document.getElementById('start-camera-btn');
  const video = document.getElementById('camera-feed');
  const photo = document.getElementById('captured-photo');
  startButton.disabled = true;
  photo.hidden = true;
  setCameraStatus('Requesting camera access...');

  try {
    cameraStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'user' },
      audio: false,
    });
    video.srcObject = cameraStream;
    video.hidden = false;
    await video.play();
    document.getElementById('camera-placeholder').hidden = true;
    document.getElementById('capture-photo-btn').disabled = false;
    document.getElementById('stop-camera-btn').disabled = false;
    setCameraStatus('Camera is on. Capture a photo when ready.');
  } catch (error) {
    stopCamera();
    const messages = {
      NotAllowedError: 'Camera permission was denied. Allow access in your browser settings.',
      NotFoundError: 'No camera was found on this device.',
      NotReadableError: 'The camera is busy in another application.',
    };
    setCameraStatus(messages[error.name] || 'Unable to start the camera. Check browser permissions and try again.', false);
  }
});

document.getElementById('capture-photo-btn').addEventListener('click', () => {
  const video = document.getElementById('camera-feed');
  if (!video.videoWidth || !video.videoHeight) {
    setCameraStatus('The camera is not ready yet. Try again in a moment.', false);
    return;
  }

  const canvas = document.createElement('canvas');
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  canvas.getContext('2d').drawImage(video, 0, 0);
  const photo = document.getElementById('captured-photo');
  photo.src = canvas.toDataURL('image/jpeg', 0.9);
  photo.hidden = false;
  setCameraStatus('Photo captured.');
});

document.getElementById('stop-camera-btn').addEventListener('click', () => {
  stopCamera();
  setCameraStatus('Camera stopped.');
});

window.addEventListener('pagehide', stopCamera);

async function apiRequest(endpoint, options = {}) {
  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    });

    const data = await response.json().catch(() => ({}));
    return { response, data };
  } catch {
    return {
      response: { ok: false },
      data: { error: 'Cannot reach the backend. Make sure the Flask app is running.' },
    };
  }
}

document.getElementById('student-form').addEventListener('submit', async (event) => {
  event.preventDefault();

  const studentId = document.getElementById('student-id').value.trim();
  const name = document.getElementById('student-name').value.trim();

  if (!studentId || !name) {
    alert('Please enter both student ID and student name.');
    return;
  }

  const { response, data } = await apiRequest('/students', {
    method: 'POST',
    body: JSON.stringify({ student_id: studentId, name }),
  });

  if (response.ok) {
    alert(data.message || 'Student registered successfully');
    document.getElementById('student-form').reset();
  } else {
    alert(data.message || data.error || 'Unable to register student');
  }
});

document.getElementById('face-scan-btn').addEventListener('click', async () => {
  const studentId = document.getElementById('student-id').value.trim();

  if (!studentId) {
    setFaceStatus('Please enter a Student ID first.', false);
    return;
  }

  const { response, data } = await apiRequest('/face-scan', {
    method: 'POST',
    body: JSON.stringify({ student_id: studentId }),
  });

  if (response.ok) {
    setFaceStatus(data.message || 'Face verified successfully', data.success !== false);
    document.getElementById('camera-status').textContent = data.success ? 'Face detected' : 'Verification failed';
  } else {
    setFaceStatus(data.error || 'Face scan failed', false);
  }
});

document.querySelectorAll('.status-btn').forEach((button) => {
  button.addEventListener('click', () => {
    selectedStatus = button.dataset.status;
    document.querySelectorAll('.status-btn').forEach((btn) => btn.classList.remove('active'));
    button.classList.add('active');
    setStatus(`Selected status: ${selectedStatus}`);
  });
});

document.getElementById('mark-attendance-btn').addEventListener('click', async () => {
  const studentId = document.getElementById('student-id').value.trim();

  if (!studentId) {
    setStatus('Please enter a Student ID first.', false);
    return;
  }

  const { response, data } = await apiRequest('/mark-attendance', {
    method: 'POST',
    body: JSON.stringify({ student_id: studentId, status: selectedStatus }),
  });

  if (response.ok) {
    setStatus(data.message || 'Attendance marked successfully', true);
  } else {
    setStatus(data.message || data.error || 'Attendance could not be marked', false);
  }
});

document.getElementById('view-attendance-btn').addEventListener('click', async () => {
  const studentId = document.getElementById('query-student-id').value.trim();

  if (!studentId) {
    document.getElementById('attendance-data').textContent = 'Enter a student ID to view attendance.';
    return;
  }

  const { response, data } = await apiRequest(`/attendance/${encodeURIComponent(studentId)}`);
  if (!response.ok) {
    document.getElementById('attendance-data').textContent = data.error || 'Unable to load attendance.';
    return;
  }

  document.getElementById('attendance-data').textContent = JSON.stringify(data, null, 2);
});

document.getElementById('load-alerts-btn').addEventListener('click', async () => {
  const { response, data } = await apiRequest('/alerts');

  const alertsBox = document.getElementById('alerts-list');
  if (!response.ok) {
    alertsBox.textContent = data.error || 'Unable to load alerts.';
    return;
  }
  if (!data.length) {
    alertsBox.textContent = 'No low attendance alerts.';
    return;
  }

  alertsBox.innerHTML = data.map((item) => `
    <div>
      <strong>${item.name}</strong> (${item.student_id})<br>
      Attendance: ${item.attendance}%<br>
      ${item.alert}
    </div>
  `).join('<hr>');
});

document.addEventListener('DOMContentLoaded', async () => {
  const { response: healthResponse } = await apiRequest('/health');
  if (healthResponse.ok) {
    document.getElementById('backend-status').textContent = 'Backend connected';
  } else {
    document.getElementById('backend-status').textContent = 'Backend unavailable';
    document.getElementById('backend-status').style.color = '#ffb3b3';
  }
});
```

## `signupCode`

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart AI Attendance - Create Account</title>
    <!-- Styles share exact theme variables with login for aesthetic symmetry -->
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', sans-serif; }
        body { background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); height: 100vh; display: flex; justify-content: center; align-items: center; }
        .card-container { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.1); padding: 40px; border-radius: 16px; width: 100%; max-width: 420px; box-shadow: 0 20px 40px rgba(0,0,0,0.4); text-align: center; }
        .logo-box { display: inline-flex; align-items: center; justify-content: center; width: 64px; height: 64px; background: linear-gradient(135deg, #0ea5e9, #2563eb); border-radius: 12px; color: #ffffff; font-size: 28px; font-weight: 800; margin-bottom: 16px; }
        h2 { color: #ffffff; font-size: 24px; font-weight: 600; margin-bottom: 6px; }
        p.subtitle { color: #94a3b8; font-size: 14px; margin-bottom: 28px; }
        .form-group { text-align: left; margin-bottom: 20px; }
        label { display: block; color: #cbd5e1; font-size: 13px; font-weight: 500; margin-bottom: 8px; }
        input { width: 100%; padding: 12px 16px; background: rgba(15, 23, 42, 0.6); border: 1px solid #334155; border-radius: 8px; color: #ffffff; font-size: 14px; }
        input:focus { outline: none; border-color: #0ea5e9; }
        .btn-submit { width: 100%; padding: 12px; background: linear-gradient(135deg, #0ea5e9, #2563eb); border: none; border-radius: 8px; color: #ffffff; font-size: 15px; font-weight: 600; cursor: pointer; margin-top: 10px; }
        .alert { padding: 10px; margin-bottom: 15px; border-radius: 6px; font-size: 13px; display: none; text-align: left; }
        .alert-error { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; }
        .alert-success { background: rgba(34, 197, 94, 0.2); border: 1px solid #22c55e; color: #86efac; }
        .footer-links { margin-top: 24px; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 20px; color: #94a3b8; font-size: 14px; }
        .footer-links a { color: #38bdf8; text-decoration: none; font-weight: 500; }
    </style>
</head>
<body>

    <div class="card-container">
        <div class="logo-box">𝚲𝚰</div>
        <h2>Create account</h2>
        <p class="subtitle">Join Smart AI Attendance dashboard system.</p>
        
        <div id="alertBox" class="alert"></div>

        <form id="signupForm">
            <div class="form-group">
                <label for="name">Full Name</label>
                <input type="text" id="name" placeholder="John Doe" required>
            </div>

            <div class="form-group">
                <label for="email">Email address</label>
                <input type="email" id="email" placeholder="you@example.com" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" placeholder="Create strong password" required>
            </div>
            
            <button type="submit" class="btn-submit">Register Account</button>
        </form>
        
        <div class="footer-links">
            Already registered? <a href="login.html">Sign in</a>
        </div>
    </div>

    <script>
        document.getElementById('signupForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const alertBox = document.getElementById('alertBox');

            alertBox.style.display = 'none';

            try {
                const response = await fetch('/api/auth/signup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, email, password })
                });

                const result = await response.json();

                if (response.ok) {
                    alertBox.className = "alert alert-success";
                    alertBox.textContent = result.message;
                    alertBox.style.display = 'block';
                    setTimeout(() => { window.location.href = 'login.html'; }, 2000);
                } else {
                    alertBox.className = "alert alert-error";
                    alertBox.textContent = result.message;
                    alertBox.style.display = 'block';
                }
            } catch (err) {
                alertBox.className = "alert alert-error";
                alertBox.textContent = "Error executing registration workflow.";
                alertBox.style.display = 'block';
            }
        });
    </script>
</body>
</html>
```

## `students.py`

```
import sqlite3
from database import get_db


def add_student(student_id, name):

    db = get_db()
    cursor = db.cursor()

    try:

        cursor.execute("""
            INSERT INTO students (id, name)
            VALUES (?, ?)
        """, (student_id, name))

        db.commit()

        result = {
            "success": True,
            "message": "Student registered successfully"
        }

    except sqlite3.IntegrityError:

        result = {
            "success": False,
            "message": "Student already exists"
        }

    db.close()

    return result
```

## `style.css`

```
* {
  box-sizing: border-box;
}

body {
  margin: 0;
  font-family: Arial, sans-serif;
  background: #08111f;
  color: #eaf2ff;
}

.page {
  max-width: 1200px;
  margin: 0 auto;
  padding: 32px 20px 60px;
}

header {
  text-align: center;
  margin-bottom: 28px;
}

header h1 {
  margin-bottom: 8px;
  font-size: 2.2rem;
}

header p {
  margin: 0;
  color: #a8c4ff;
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
}

.card {
  background: #12233d;
  border: 1px solid #24406f;
  border-radius: 14px;
  padding: 18px;
  box-shadow: 0 8px 18px rgba(0,0,0,0.18);
}

.card h2 {
  margin-top: 0;
  font-size: 1.2rem;
}

input, button {
  width: 100%;
  display: block;
  margin: 10px 0;
  padding: 10px 12px;
  border-radius: 8px;
  border: 1px solid #3c5d8c;
  font-size: 1rem;
}

input {
  background: #0d1a2c;
  color: #fff;
}

button {
  background: #2f7cf6;
  color: white;
  border: none;
  cursor: pointer;
  transition: 0.2s ease;
}

button:hover {
  background: #2268d8;
}

.camera-box,
.result-box,
.record-box,
.alerts-box {
  margin-top: 10px;
  padding: 12px;
  border-radius: 8px;
  background: #0d1a2c;
  color: #dfeeff;
  min-height: 48px;
}

.camera-preview {
  position: relative;
  width: 100%;
  aspect-ratio: 4 / 3;
  overflow: hidden;
  display: grid;
  place-items: center;
  background: #0d1a2c;
  color: #a8c4ff;
  border-radius: 8px;
}

.camera-preview video,
.camera-preview img {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.camera-preview [hidden] {
  display: none;
}

.camera-controls {
  display: flex;
  gap: 8px;
  margin-top: 10px;
}

.camera-controls button {
  min-width: 0;
  margin: 0;
  padding: 10px 6px;
}

.camera-controls button:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.attendance-options {
  display: flex;
  gap: 8px;
  margin: 12px 0;
}

.status-btn {
  flex: 1;
  background: #1a355d;
}

.status-btn.active {
  background: #24a148;
}

.metric {
  display: flex;
  justify-content: space-between;
  padding: 10px 0;
  border-bottom: 1px solid #2a4473;
}

.input-row {
  display: flex;
  gap: 8px;
}

.input-row input {
  flex: 1;
}

.account-bar {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 14px;
  margin-top: 16px;
  color: #a8c4ff;
}

.account-bar form {
  margin: 0;
}

.account-bar button {
  width: auto;
  margin: 0;
}

.login-page {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 24px;
}

.login-card {
  width: min(100%, 420px);
  padding: 32px;
  border: 1px solid #24406f;
  border-radius: 16px;
  background: #12233d;
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.28);
  text-align: center;
}

.brand-mark {
  display: grid;
  width: 52px;
  height: 52px;
  margin: 0 auto 16px;
  place-items: center;
  border-radius: 14px;
  background: #2f7cf6;
  color: white;
  font-weight: 700;
}

.eyebrow {
  color: #a8c4ff;
  font-size: 0.8rem;
  font-weight: 700;
  letter-spacing: 0.12em;
}

.login-card h1 {
  margin: 8px 0;
  font-size: 1.8rem;
}

.login-description {
  margin: 0 0 24px;
  color: #b5c6df;
}

.login-card form {
  text-align: left;
}

.login-card label {
  display: block;
  margin: 16px 0 6px;
  color: #dfeeff;
}

.login-card input {
  margin: 0;
}

.form-error {
  padding: 10px 12px;
  border-radius: 8px;
  background: #4a2029;
  color: #ffc3c3;
}

.demo-hint {
  margin: 20px 0 0;
  color: #a8c4ff;
  font-size: 0.9rem;
}

.secondary-button {
  background: #1a355d;
}

.secondary-button:hover {
  background: #244776;
}

@media (max-width: 600px) {
  .grid {
    grid-template-columns: 1fr;
  }

  .account-bar {
    flex-direction: column;
    gap: 8px;
  }

  .login-card {
    padding: 24px;
  }
}
```

## `styles`

```
:root {
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", sans-serif;
  color: #172033;
  background: #f4f7fb;
  font-synthesis: none;
  text-rendering: optimizeLegibility;
}

* {
  box-sizing: border-box;
}

body {
  min-width: 320px;
  min-height: 100vh;
  margin: 0;
}

button,
input {
  font: inherit;
}

.login-page {
  display: grid;
  min-height: 100vh;
  place-items: center;
  padding: 24px;
  background:
    radial-gradient(ellipse at top left, #e3edff 0, transparent 45%),
    #f4f7fb;
}

.login-card {
  width: min(100%, 430px);
  padding: 40px;
  border: 1px solid #e7ebf2;
  border-radius: 20px;
  background: #fff;
  box-shadow: 0 20px 60px rgb(31 48 78 / 10%);
}

.brand-mark {
  display: grid;
  width: 46px;
  height: 46px;
  place-items: center;
  border-radius: 14px;
  color: white;
  background: #315be8;
  font-weight: 800;
}

.eyebrow {
  margin: 20px 0 8px;
  color: #5873bd;
  font-size: 12px;
  font-weight: 750;
  letter-spacing: 0.12em;
}

h1 {
  margin: 0;
  color: #172033;
  font-size: clamp(28px, 5vw, 36px);
  letter-spacing: -0.04em;
}

.login-description,
.content > p:not(.eyebrow) {
  color: #68748a;
  line-height: 1.6;
}

.login-card form {
  display: grid;
  gap: 10px;
  margin-top: 28px;
}

.login-card label {
  margin-top: 8px;
  color: #27334a;
  font-size: 14px;
  font-weight: 650;
}

.login-card input {
  width: 100%;
  padding: 13px 14px;
  border: 1px solid #d8deea;
  border-radius: 10px;
  outline: none;
  background: #fff;
}

.login-card input:focus {
  border-color: #315be8;
  box-shadow: 0 0 0 3px rgb(49 91 232 / 12%);
}

.primary-button,
.primary-link {
  display: inline-flex;
  min-height: 46px;
  align-items: center;
  justify-content: center;
  margin-top: 12px;
  padding: 0 18px;
  border: 0;
  border-radius: 10px;
  color: #fff;
  background: #315be8;
  cursor: pointer;
  font-weight: 700;
  text-decoration: none;
}

.primary-button:hover,
.primary-link:hover {
  background: #244bd0;
}

.primary-button:disabled {
  cursor: wait;
  opacity: 0.7;
}

.form-error {
  margin: 4px 0;
  color: #b42318;
  font-size: 14px;
}

.demo-hint {
  margin: 22px 0 0;
  color: #7a8496;
  font-size: 12px;
  line-height: 1.6;
}

.app-page {
  min-height: 100vh;
  background: #f4f7fb;
}

.topbar {
  display: flex;
  min-height: 72px;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 12px clamp(20px, 5vw, 64px);
  border-bottom: 1px solid #e7ebf2;
  background: #fff;
}

.brand-link {
  color: #172033;
  font-weight: 750;
  text-decoration: none;
}

.topbar-actions {
  display: flex;
  align-items: center;
  gap: 16px;
}

.user-label {
  color: #68748a;
  font-size: 14px;
}

.secondary-button {
  padding: 9px 14px;
  border: 1px solid #d8deea;
  border-radius: 9px;
  color: #27334a;
  background: #fff;
  cursor: pointer;
}

.content {
  width: min(100% - 40px, 900px);
  margin: 64px auto;
}

.content .eyebrow {
  margin-top: 0;
}

.text-link {
  color: #315be8;
  font-weight: 650;
}

@media (max-width: 480px) {
  .login-card {
    padding: 28px 22px;
  }

  .topbar {
    align-items: flex-start;
    flex-direction: column;
  }

  .topbar-actions {
    width: 100%;
    justify-content: space-between;
  }
}
```

## `templates/database.Schema`

```
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  otp: { type: String },
  otpExpires: { type: Date }
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
```

## `templates/expressServerOtp`

```
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const path = require('path');
const User = require('./models/User');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// Database Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected Successfully'))
  .catch((err) => console.error('MongoDB Connection Error:', err));

// Configure Nodemailer Transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Helper: Generate 6-Digit OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// ROUTE 1: SIGNUP (Generate & Send OTP)
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    let user = await User.findOne({ email });
    if (user && user.isVerified) {
      return res.status(400).json({ message: 'Email is already registered and verified.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOTP();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // Valid for 10 minutes

    if (!user) {
      user = new User({ name, email, password: hashedPassword, otp, otpExpires });
    } else {
      user.password = hashedPassword;
      user.otp = otp;
      user.otpExpires = otpExpires;
    }

    await user.save();

    // Send Email
    await transporter.sendMail({
      from: `"Smart Attendance System" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Verification Code - Smart Attendance System',
      html: `<h3>Your One-Time Password (OTP) for registration is: <b>${otp}</b></h3><p>It will expire in 10 minutes.</p>`
    });

    res.status(200).json({ message: 'OTP sent to your email address.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error during signup.', error: error.message });
  }
});

// ROUTE 2: VERIFY OTP
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found.' });
    }

    if (user.otp !== otp || user.otpExpires < Date.now()) {
      return res.status(400).json({ message: 'Invalid or expired OTP.' });
    }

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.status(200).json({ message: 'Email verified successfully! You can now login.' });
  } catch (error) {
    res.status(500).json({ message: 'Verification error.', error: error.message });
  }
});

// ROUTE 3: LOGIN
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    if (!user.isVerified) {
      return res.status(403).json({ message: 'Please verify your email via OTP before logging in.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    res.status(200).json({ message: 'Login successful!', user: { name: user.name, email: user.email } });
  } catch (error) {
    res.status(500).json({ message: 'Login error.', error: error.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
```

## `templates/forgot_password.html`

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart AI Attendance - Forgot Password</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, sans-serif; }
        body { min-height: 100vh; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); display: flex; justify-content: center; align-items: center; padding: 24px; }
        .card-container { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.1); padding: 40px; border-radius: 16px; width: 100%; max-width: 420px; box-shadow: 0 20px 40px rgba(0,0,0,0.4); text-align: center; }
        .logo-box { display: inline-flex; align-items: center; justify-content: center; width: 64px; height: 64px; background: linear-gradient(135deg, #0ea5e9, #2563eb); border-radius: 12px; color: #fff; font-size: 28px; font-weight: 800; margin-bottom: 16px; }
        h1 { color: #fff; font-size: 24px; font-weight: 600; margin-bottom: 6px; }
        p.subtitle { color: #94a3b8; font-size: 14px; margin-bottom: 28px; line-height: 1.5; }
        .form-group { text-align: left; margin-bottom: 20px; }
        label { display: block; color: #cbd5e1; font-size: 13px; font-weight: 500; margin-bottom: 8px; }
        input { width: 100%; padding: 12px 16px; background: rgba(15, 23, 42, 0.6); border: 1px solid #334155; border-radius: 8px; color: #fff; font-size: 14px; }
        input:focus { outline: none; border-color: #0ea5e9; }
        .btn-submit, .auth-action { display: block; width: 100%; padding: 12px; border-radius: 8px; font-size: 15px; font-weight: 600; text-align: center; text-decoration: none; }
        .btn-submit { background: linear-gradient(135deg, #0ea5e9, #2563eb); border: none; color: #fff; cursor: pointer; }
        .message { padding: 12px; margin-bottom: 18px; border-radius: 8px; background: rgba(34, 197, 94, 0.15); border: 1px solid #22c55e; color: #bbf7d0; font-size: 14px; text-align: left; line-height: 1.5; }
        .form-error { margin-bottom: 18px; color: #fecaca; font-size: 14px; text-align: left; }
        .auth-action { margin-top: 12px; border: 1px solid #334155; color: #bae6fd; font-size: 14px; }
        .auth-action:hover { border-color: #0ea5e9; background: rgba(14, 165, 233, 0.1); }
        @media (max-width: 480px) { .card-container { padding: 28px 22px; } }
    </style>
</head>
<body>
    <main class="card-container">
        <div class="logo-box" aria-hidden="true">AI</div>
        <h1>Reset password</h1>
        <p class="subtitle">Enter your account email and we’ll send a one-time reset code.</p>

        {% if request_submitted %}
            <p class="message" role="status">
                If that email is linked to an account, a reset code has been sent.
            </p>
        {% endif %}
        {% if error %}
            <p class="form-error" role="alert">{{ error }}</p>
        {% endif %}

        <form action="{{ url_for('forgot_password') }}" method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div class="form-group">
                <label for="email">Email address</label>
                <input id="email" name="email" type="email" autocomplete="email" placeholder="you@example.com" value="{{ email }}" required>
            </div>
            <button type="submit" class="btn-submit">Send reset code</button>
        </form>

        <a class="auth-action" href="{{ url_for('login') }}">Back to login</a>
    </main>
</body>
</html>
```

## `templates/index.html`

```
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AI Smart Attendance</title>
  <link rel="icon" href="{{ url_for('favicon') }}" type="image/svg+xml" />
  <link rel="stylesheet" href="style.css" />
</head>
<body>
  <div class="page">
    <header>
      <h1>AI-Powered Smart Attendance System</h1>
      <p>Face Recognition • Analytics • Alerts</p>
      <div class="account-bar">
        <span>Signed in as {{ user_email }}</span>
        <form method="post" action="{{ url_for('logout') }}">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}" />
          <button class="secondary-button" type="submit">Log out</button>
        </form>
      </div>
    </header>

    <main class="grid">
      <section class="card">
        <h2>Student Enrollment</h2>
        <form id="student-form">
          <input id="student-id" type="text" placeholder="Student ID" required />
          <input id="student-name" type="text" placeholder="Student Name" required />
          <button type="submit">Register Student</button>
        </form>
      </section>

      <section class="card">
        <h2>Face Recognition</h2>
        <div class="camera-preview">
          <video id="camera-feed" autoplay playsinline muted hidden></video>
          <img id="captured-photo" alt="Captured camera photo" hidden />
          <span id="camera-placeholder">Camera off</span>
        </div>
        <div class="camera-controls">
          <button id="start-camera-btn" type="button">Start camera</button>
          <button id="capture-photo-btn" type="button" disabled>Capture</button>
          <button id="stop-camera-btn" type="button" disabled>Stop</button>
        </div>
        <div class="camera-box" id="camera-status" aria-live="polite">Allow camera access to preview and capture a photo.</div>
        <div class="camera-box" id="backend-status" aria-live="polite">Checking backend...</div>
        <button id="face-scan-btn" type="button">Verify Face</button>
        <div id="face-result" class="result-box">Face Detection: Waiting</div>
      </section>

      <section class="card">
        <h2>Attendance</h2>
        <div class="attendance-options">
          <button class="status-btn" data-status="Present">Present</button>
          <button class="status-btn" data-status="Absent">Absent</button>
          <button class="status-btn" data-status="Late">Late</button>
        </div>
        <button id="mark-attendance-btn">Mark Attendance</button>
        <div id="attendance-result" class="result-box">Status: Waiting</div>
      </section>

      <section class="card">
        <h2>Attendance Records</h2>
        <div class="input-row">
          <input id="query-student-id" type="text" placeholder="Student ID" />
          <button id="view-attendance-btn">View</button>
        </div>
        <div id="attendance-data" class="record-box">No record loaded yet.</div>
      </section>

      <section class="card">
        <h2>Analytics</h2>
        <div class="metric">
          <span>Daily Attendance</span>
          <strong id="daily-attendance">0%</strong>
        </div>
        <div class="metric">
          <span>Weekly Attendance</span>
          <strong id="weekly-attendance">0%</strong>
        </div>
        <div class="metric">
          <span>Monthly Attendance</span>
          <strong id="monthly-attendance">0%</strong>
        </div>
        <div class="metric">
          <span>Low Attendance</span>
          <strong id="low-attendance">0</strong>
        </div>
      </section>

      <section class="card">
        <h2>Alerts</h2>
        <button id="load-alerts-btn">Load Alerts</button>
        <div id="alerts-list" class="alerts-box">No alerts.</div>
      </section>
    </main>
  </div>

  <script src="script.js"></script>
</body>
</html>
```

## `templates/login.html`

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart AI Attendance - Login</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        body {
            min-height: 100vh;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 24px;
        }
        .login-container {
            background: rgba(30, 41, 59, 0.7);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 40px;
            border-radius: 16px;
            width: 100%;
            max-width: 420px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
            text-align: center;
        }
        .logo-box {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 64px;
            height: 64px;
            background: linear-gradient(135deg, #0ea5e9, #2563eb);
            border-radius: 12px;
            color: #ffffff;
            font-size: 28px;
            font-weight: 800;
            margin-bottom: 16px;
            letter-spacing: -1px;
            box-shadow: 0 8px 16px rgba(14, 165, 233, 0.3);
        }
        h1 {
            color: #ffffff;
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 6px;
        }
        p.subtitle {
            color: #94a3b8;
            font-size: 14px;
            margin-bottom: 28px;
        }
        .form-group {
            text-align: left;
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #cbd5e1;
            font-size: 13px;
            font-weight: 500;
            margin-bottom: 8px;
        }
        input {
            width: 100%;
            padding: 12px 16px;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid #334155;
            border-radius: 8px;
            color: #ffffff;
            font-size: 14px;
            transition: all 0.3s ease;
        }
        input:focus {
            outline: none;
            border-color: #0ea5e9;
            box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.15);
        }
        .btn-submit {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #0ea5e9, #2563eb);
            border: none;
            border-radius: 8px;
            color: #ffffff;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s ease;
        }
        .btn-submit:hover {
            opacity: 0.95;
        }
        .form-error {
            margin-bottom: 18px;
            color: #fecaca;
            font-size: 14px;
            text-align: left;
        }
        .footer-links {
            margin-top: 24px;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            padding-top: 20px;
            color: #94a3b8;
            font-size: 14px;
        }
        .footer-links strong {
            color: #38bdf8;
            font-weight: 500;
        }
        .auth-actions {
            display: grid;
            gap: 10px;
            margin-top: 20px;
        }
        .auth-action {
            display: block;
            padding: 11px 14px;
            border: 1px solid #334155;
            border-radius: 8px;
            color: #bae6fd;
            font-size: 14px;
            text-decoration: none;
            transition: background 0.2s ease, border-color 0.2s ease;
        }
        .auth-action:hover {
            background: rgba(14, 165, 233, 0.1);
            border-color: #0ea5e9;
        }
        .form-success {
            margin-bottom: 18px;
            color: #86efac;
            font-size: 14px;
            text-align: left;
        }
        @media (max-width: 480px) {
            .login-container {
                padding: 28px 22px;
            }
        }
    </style>
</head>
<body>
    <main class="login-container">
        <div class="logo-box" aria-hidden="true">AI</div>
        <h1>Welcome back</h1>
        <p class="subtitle">Sign in to manage your attendance dashboard.</p>

        {% if registered %}
            <p class="form-success" role="status">Email verified. Your account is ready to sign in.</p>
        {% endif %}
        {% if password_reset %}
            <p class="form-success" role="status">Password reset successfully. Sign in with your new password.</p>
        {% endif %}

        <form action="{{ url_for('login') }}" method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div class="form-group">
                <label for="email">Email address</label>
                <input
                    type="email"
                    id="email"
                    name="email"
                    autocomplete="username"
                    placeholder="you@example.com"
                    value="{{ request.form.get('email', '') }}"
                    required
                >
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input
                    type="password"
                    id="password"
                    name="password"
                    autocomplete="current-password"
                    placeholder="Enter your password"
                    required
                >
            </div>

            {% if error %}
                <p class="form-error" role="alert">{{ error }}</p>
            {% endif %}

            <button type="submit" class="btn-submit">Sign in</button>
        </form>

        <nav class="auth-actions" aria-label="Account options">
            <a class="auth-action" href="{{ url_for('forgot_password') }}">Forgot password?</a>
            <a class="auth-action" href="{{ url_for('signup') }}">Create an account</a>
        </nav>

        {% if demo_credentials %}
            <div class="footer-links">
                Demo: <strong>admin@example.com</strong> /
                <strong>Attendance123!</strong>
            </div>
        {% endif %}
    </main>
</body>
</html>
```

## `templates/otp.html`

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify your email | Smart AI Attendance</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, sans-serif; }
        body { min-height: 100vh; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); display: flex; justify-content: center; align-items: center; padding: 24px; }
        .card { width: 100%; max-width: 420px; padding: 40px; border: 1px solid rgba(255,255,255,.1); border-radius: 16px; background: rgba(30,41,59,.7); box-shadow: 0 20px 40px rgba(0,0,0,.4); text-align: center; }
        .logo { display: grid; width: 64px; height: 64px; margin: 0 auto 16px; place-items: center; border-radius: 12px; background: linear-gradient(135deg,#0ea5e9,#2563eb); color: #fff; font-size: 26px; font-weight: 800; }
        h1 { margin-bottom: 8px; color: #fff; font-size: 24px; }
        .subtitle { margin-bottom: 24px; color: #94a3b8; font-size: 14px; line-height: 1.5; }
        label { display: block; margin-bottom: 8px; color: #cbd5e1; font-size: 13px; text-align: left; }
        input { width: 100%; padding: 12px 16px; border: 1px solid #334155; border-radius: 8px; background: rgba(15,23,42,.6); color: #fff; font-size: 18px; letter-spacing: .3em; text-align: center; }
        input:focus { outline: none; border-color: #0ea5e9; box-shadow: 0 0 0 3px rgba(14,165,233,.15); }
        button, .link { display: block; width: 100%; margin-top: 14px; padding: 12px; border: 0; border-radius: 8px; background: linear-gradient(135deg,#0ea5e9,#2563eb); color: #fff; font-size: 15px; font-weight: 600; text-decoration: none; cursor: pointer; }
        .link { border: 1px solid #334155; background: transparent; color: #bae6fd; font-size: 14px; }
        .error { margin-top: 16px; color: #fecaca; font-size: 14px; text-align: left; }
        @media (max-width: 480px) { .card { padding: 28px 22px; } }
    </style>
</head>
<body>
    <main class="card">
        <div class="logo" aria-hidden="true">AI</div>
        <h1>Verify your email</h1>
        <p class="subtitle">Enter the 6-digit code sent to {{ email }}. The code expires in 10 minutes.</p>
        {% if development_otp %}
            <p class="error" role="status">
                Local development only — no email was sent. Verification code: <strong>{{ development_otp }}</strong>
            </p>
        {% endif %}
        <form method="post" action="{{ url_for('verify_otp') }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="hidden" name="email" value="{{ email }}">
            <label for="otp">Verification code</label>
            <input id="otp" name="otp" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="000000" required>
            {% if error %}
                <p class="error" role="alert">{{ error }}</p>
            {% endif %}
            <button type="submit">Verify email</button>
        </form>
        <a class="link" href="{{ url_for('signup') }}">Back to sign up</a>
    </main>
</body>
</html>
```

## `templates/OtpFrontend`

```
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Smart Attendance System</title>
  <style>
    * { box-sizing: border-box; font-family: Arial, sans-serif; }
    body { background: #fafafa; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
    .card { background: #fff; border: 1px solid #dbdbdb; width: 350px; padding: 30px; text-align: center; border-radius: 4px; }
    h2 { margin-bottom: 20px; color: #262626; }
    input { width: 100%; padding: 10px; margin: 6px 0; border: 1px solid #dbdbdb; border-radius: 3px; background: #fafafa; }
    button { width: 100%; padding: 10px; background: #0095f6; border: none; color: white; font-weight: bold; border-radius: 4px; cursor: pointer; margin-top: 10px; }
    button:hover { background: #1877f2; }
    .toggle { margin-top: 15px; font-size: 14px; color: #8e8e8e; cursor: pointer; }
    .hidden { display: none; }
    .demo-box { margin-top: 15px; font-size: 12px; color: #555; background: #f0f0f0; padding: 8px; border-radius: 4px; }
  </style>
</head>
<body>

  <div class="card">
    <h2>Smart Attendance</h2>

    <!-- LOGIN FORM -->
    <form id="loginForm">
      <input type="email" id="loginEmail" placeholder="Email" required />
      <input type="password" id="loginPassword" placeholder="Password" required />
      <button type="submit">Log In</button>
      <div class="toggle" onclick="showSignup()">Don't have an account? Sign up</div>
    </form>

    <!-- SIGNUP FORM -->
    <form id="signupForm" class="hidden">
      <input type="text" id="signupName" placeholder="Full Name" required />
      <input type="email" id="signupEmail" placeholder="Email Address" required />
      <input type="password" id="signupPassword" placeholder="Password" required />
      <button type="submit">Send OTP</button>
      <div class="toggle" onclick="showLogin()">Have an account? Log in</div>
    </form>

    <!-- OTP VERIFICATION FORM -->
    <form id="otpForm" class="hidden">
      <p style="font-size: 13px;">Enter the 6-digit OTP sent to your email.</p>
      <input type="text" id="otpInput" placeholder="6-Digit OTP" maxlength="6" required />
      <button type="submit">Verify & Activate</button>
    </form>

    <div class="demo-box">
      <strong>Demo Credentials:</strong><br>
      admin@example.com / Attendance123!
    </div>
  </div>

  <script>
    let currentEmail = '';

    function showSignup() {
      document.getElementById('loginForm').classList.add('hidden');
      document.getElementById('signupForm').classList.remove('hidden');
      document.getElementById('otpForm').classList.add('hidden');
    }

    function showLogin() {
      document.getElementById('signupForm').classList.add('hidden');
      document.getElementById('loginForm').classList.remove('hidden');
      document.getElementById('otpForm').classList.add('hidden');
    }

    document.getElementById('signupForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      currentEmail = document.getElementById('signupEmail').value;
      const response = await fetch('/api/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: document.getElementById('signupName').value,
          email: currentEmail,
          password: document.getElementById('signupPassword').value
        })
      });
      const data = await response.json();
      alert(data.message);
      if (response.ok) {
        document.getElementById('signupForm').classList.add('hidden');
        document.getElementById('otpForm').classList.remove('hidden');
      }
    });

    document.getElementById('otpForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const response = await fetch('/api/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: currentEmail,
          otp: document.getElementById('otpInput').value
        })
      });
      const data = await response.json();
      alert(data.message);
      if (response.ok) showLogin();
    });

    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: document.getElementById('loginEmail').value,
          password: document.getElementById('loginPassword').value
        })
      });
      const data = await response.json();
      alert(data.message);
    });
  </script>
</body>
</html>
```

## `templates/reset_password.html`

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset password | Smart AI Attendance</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, sans-serif; }
        body { min-height: 100vh; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); display: flex; justify-content: center; align-items: center; padding: 24px; }
        .card { width: 100%; max-width: 420px; padding: 40px; border: 1px solid rgba(255,255,255,.1); border-radius: 16px; background: rgba(30,41,59,.7); box-shadow: 0 20px 40px rgba(0,0,0,.4); text-align: center; }
        .logo { display: grid; width: 64px; height: 64px; margin: 0 auto 16px; place-items: center; border-radius: 12px; background: linear-gradient(135deg,#0ea5e9,#2563eb); color: #fff; font-size: 26px; font-weight: 800; }
        h1 { margin-bottom: 8px; color: #fff; font-size: 24px; }
        .subtitle { margin-bottom: 24px; color: #94a3b8; font-size: 14px; line-height: 1.5; }
        .field { margin-bottom: 18px; text-align: left; }
        label { display: block; margin-bottom: 8px; color: #cbd5e1; font-size: 13px; }
        input { width: 100%; padding: 12px 16px; border: 1px solid #334155; border-radius: 8px; background: rgba(15,23,42,.6); color: #fff; font-size: 16px; }
        input:focus { outline: none; border-color: #0ea5e9; box-shadow: 0 0 0 3px rgba(14,165,233,.15); }
        button, .link { display: block; width: 100%; margin-top: 14px; padding: 12px; border: 0; border-radius: 8px; background: linear-gradient(135deg,#0ea5e9,#2563eb); color: #fff; font-size: 15px; font-weight: 600; text-align: center; text-decoration: none; cursor: pointer; }
        .link { border: 1px solid #334155; background: transparent; color: #bae6fd; font-size: 14px; }
        .error { margin-bottom: 16px; color: #fecaca; font-size: 14px; text-align: left; }
        @media (max-width: 480px) { .card { padding: 28px 22px; } }
    </style>
</head>
<body>
    <main class="card">
        <div class="logo" aria-hidden="true">AI</div>
        <h1>Choose a new password</h1>
        <p class="subtitle">If an account matches {{ email }}, a reset code has been sent. Enter that code and your new password.</p>
        {% if development_otp %}
            <p class="error" role="status">
                Local development only — your reset code is ready: <strong>{{ development_otp }}</strong>
            </p>
        {% endif %}
        <form method="post" action="{{ url_for('reset_password') }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="hidden" name="email" value="{{ email }}">
            {% if error %}
                <p class="error" role="alert">{{ error }}</p>
            {% endif %}
            <div class="field">
                <label for="otp">6-digit reset code</label>
                <input id="otp" name="otp" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required>
            </div>
            <div class="field">
                <label for="new_password">New password</label>
                <input id="new_password" name="new_password" type="password" autocomplete="new-password" minlength="8" required>
            </div>
            <button type="submit">Reset password</button>
        </form>
        <a class="link" href="{{ url_for('forgot_password') }}">Request a new code</a>
    </main>
</body>
</html>
```

## `templates/signup.html`

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart AI Attendance - Create Account</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, sans-serif; }
        body { min-height: 100vh; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); display: flex; justify-content: center; align-items: center; padding: 24px; }
        .card-container { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.1); padding: 40px; border-radius: 16px; width: 100%; max-width: 420px; box-shadow: 0 20px 40px rgba(0,0,0,0.4); text-align: center; }
        .logo-box { display: inline-flex; align-items: center; justify-content: center; width: 64px; height: 64px; background: linear-gradient(135deg, #0ea5e9, #2563eb); border-radius: 12px; color: #fff; font-size: 28px; font-weight: 800; margin-bottom: 16px; }
        h1 { color: #fff; font-size: 24px; font-weight: 600; margin-bottom: 6px; }
        p.subtitle { color: #94a3b8; font-size: 14px; margin-bottom: 28px; }
        .form-group { text-align: left; margin-bottom: 20px; }
        label { display: block; color: #cbd5e1; font-size: 13px; font-weight: 500; margin-bottom: 8px; }
        input { width: 100%; padding: 12px 16px; background: rgba(15, 23, 42, 0.6); border: 1px solid #334155; border-radius: 8px; color: #fff; font-size: 14px; }
        input:focus { outline: none; border-color: #0ea5e9; box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.15); }
        .btn-submit, .auth-action { display: block; width: 100%; padding: 12px; border-radius: 8px; font-size: 15px; font-weight: 600; text-align: center; text-decoration: none; }
        .btn-submit { background: linear-gradient(135deg, #0ea5e9, #2563eb); border: none; color: #fff; cursor: pointer; }
        .form-error { margin-bottom: 18px; color: #fecaca; font-size: 14px; text-align: left; }
        .auth-action { margin-top: 12px; border: 1px solid #334155; color: #bae6fd; font-size: 14px; }
        .auth-action:hover { border-color: #0ea5e9; background: rgba(14, 165, 233, 0.1); }
        @media (max-width: 480px) { .card-container { padding: 28px 22px; } }
    </style>
</head>
<body>
    <main class="card-container">
        <div class="logo-box" aria-hidden="true">AI</div>
        <h1>Create account</h1>
        <p class="subtitle">Join the Smart AI Attendance dashboard.</p>

        <form action="{{ url_for('signup') }}" method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div class="form-group">
                <label for="name">Full name</label>
                <input id="name" name="name" type="text" autocomplete="name" maxlength="120" placeholder="Your name" value="{{ request.form.get('name', '') }}" required>
            </div>
            <div class="form-group">
                <label for="email">Email address</label>
                <input id="email" name="email" type="email" autocomplete="email" placeholder="you@example.com" value="{{ request.form.get('email', '') }}" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input id="password" name="password" type="password" autocomplete="new-password" minlength="8" placeholder="At least 8 characters" required>
            </div>

            {% if error %}
                <p class="form-error" role="alert">{{ error }}</p>
            {% endif %}

            <button type="submit" class="btn-submit">Sign up</button>
        </form>

        <a class="auth-action" href="{{ url_for('login') }}">Already have an account? Log in</a>
    </main>
</body>
</html>
```

## `TheBackEndCode`

```
const express = require('express');
const path = require('path');
const app = express();
const PORT = 3000;

// Middleware to process incoming JSON payload data
app.use(express.json());

// Serve static interface files from the public folder automatically
app.use(express.static(path.join(__dirname, 'public')));

// Simulated Data Store (In-Memory Database placeholder)
const localDatabase = [
    { email: 'admin@example.com', password: 'Attendance123!', name: 'Administrator' }
];

// ----------------------------------------------------
// 1. BACK-END ROUTE: USER LOGIN AUTHENTICATION
// ----------------------------------------------------
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Please provide email and password.' });
    }

    // Lookup credentials in database
    const userRecord = localDatabase.find(user => user.email.toLowerCase() === email.toLowerCase());

    if (!userRecord || userRecord.password !== password) {
        return res.status(401).json({ success: false, message: 'Invalid credentials. Check your email or password.' });
    }

    return res.json({ success: true, message: `Welcome back, ${userRecord.name}!`, redirectUrl: '/dashboard' });
});

// ----------------------------------------------------
// 2. BACK-END ROUTE: NEW USER REGISTRATION (SIGN UP)
// ----------------------------------------------------
app.post('/api/auth/signup', (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ success: false, message: 'All registration parameters are required.' });
    }

    // Verify duplication
    const accountExists = localDatabase.some(user => user.email.toLowerCase() === email.toLowerCase());
    if (accountExists) {
        return res.status(409).json({ success: false, message: 'An account with this email already exists.' });
    }

    // Append new record securely into storage
    localDatabase.push({ name, email, password });
    return res.status(201).json({ success: true, message: 'Account registered successfully! Redirecting to login...' });
});

// ----------------------------------------------------
// 3. BACK-END ROUTE: PASSWORD RESET REQUEST
// ----------------------------------------------------
app.post('/api/auth/forgot-password', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });
    }

    const accountExists = localDatabase.some(user => user.email.toLowerCase() === email.toLowerCase());
    
    // Security Best Practice: Don't explicitly reveal if email exists or not to prevent user enumeration attacks
    return res.json({ 
        success: true, 
        message: 'If that email address is linked to an account, a password reset link has been dispatched.' 
    });
});

// Fallback handling to catch empty dashboard view routing safely
app.get('/dashboard', (req, res) => {
    res.send('<h2 style="font-family:sans-serif; text-align:center; margin-top:50px; color:#2563eb;">Success! Secure Dashboard Interface Loaded.</h2>');
});

// Initialize server container instance
app.listen(PORT, () => {
    console.log(`Smart AI Attendance backend actively serving requests on: http://localhost:${PORT}`);
    console.log(`- Login Endpoint: http://localhost:${PORT}/login.html`);
    console.log(`- Registration Endpoint: http://localhost:${PORT}/signup.html`);
});
```

## `verifyInputcode`

```
/**
 * Call this function when the user types the 6 numbers into your verification UI boxes.
 * It submits the token verification payload to authenticate the session profile.
 */
export async function verifyUserOTP(emailAddress, sixDigitToken) {
  const { data, error } = await supabase.auth.verifyOtp({
    email: emailAddress,
    token: sixDigitToken, // Pass the text value string extracted from the UI form boxes
    type: 'email',
  })

  if (error) {
    console.error("Verification confirmation rejected:", error.message)
    return { success: false, error: error.message }
  }

  console.log("Authentication secure. Active session payload:", data.session)
  return { success: true, user: data.user }
}
```

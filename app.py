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
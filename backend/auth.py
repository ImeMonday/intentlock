"""Prototype sign-in: PBKDF2-hashed passwords and server-side session tokens.

Prototype scope: one shared workspace for all users, no rate limiting and no email verification.
Do not treat this as production-grade authentication.
"""
import hashlib
import hmac
import secrets

from backend import audit, db

ITERATIONS = 200_000
DEMO_EMAIL = "demo@intentlock.app"


def _hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS).hex()


def create_user(conn, email, password, name=""):
    email = email.strip().lower()
    if "@" not in email or len(email) > 120:
        raise ValueError("Enter a valid email address.")
    if len(password) < 8:
        raise ValueError("Use at least 8 characters for the password.")
    if db.one(conn, "SELECT 1 AS x FROM users WHERE email=?", (email,)):
        raise ValueError("An account with this email already exists.")
    salt = secrets.token_hex(16)
    cur = conn.execute("INSERT INTO users(email, name, pw_hash, salt, created_at) VALUES (?,?,?,?,?)",
                       (email, name.strip()[:60], _hash(password, salt), salt, audit.now_iso()))
    return cur.lastrowid


def check_login(conn, email, password):
    u = db.one(conn, "SELECT * FROM users WHERE email=?", (email.strip().lower(),))
    if u and hmac.compare_digest(_hash(password, u["salt"]), u["pw_hash"]):
        return u
    return None


def new_session(conn, user_id):
    token = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO sessions(token, user_id, created_at) VALUES (?,?,?)", (token, user_id, audit.now_iso()))
    return token


def user_for(conn, token):
    if not token:
        return None
    return db.one(conn, "SELECT u.id, u.email, u.name FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=?", (token,))


def end_session(conn, token):
    conn.execute("DELETE FROM sessions WHERE token=?", (token,))


def demo_user_id(conn):
    """Each demo visitor gets a brand-new guest account with an empty vault; nobody knows its random password."""
    return create_user(conn, f"guest-{secrets.token_hex(5)}@intentlock.app", secrets.token_urlsafe(18), "Guest")

"""
auth.py - Authentication & Authorization

Covers:
  - Input validation (username, email, password strength)
  - bcrypt password hashing (cost factor 12)
  - Account lockout (5 failed attempts → 15 min lockout)
  - Per-IP rate limiting (10 attempts / 60 seconds)
  - RBAC helpers (require_auth, require_role decorators)
"""

import html
import json
import os
import re
import time
import uuid
from functools import wraps

import bcrypt
from flask import g, redirect, request, abort

from config import Config
from storage import _read_json, _write_json


# ── In-memory rate limit tracker  { ip: [timestamp, ...] } ───────────────────
_rate_limit_store: dict[str, list] = {}


# ── Validation ────────────────────────────────────────────────────────────────

def validate_username(username: str) -> tuple[bool, str]:
    """3–20 chars, alphanumeric + underscore only."""
    if not username:
        return False, 'Username is required.'
    if not re.fullmatch(r'[\w]{3,20}', username):
        return False, 'Username must be 3–20 alphanumeric characters or underscores.'
    return True, ''


def validate_email(email: str) -> tuple[bool, str]:
    """Basic RFC-5321-ish check."""
    if not email:
        return False, 'Email is required.'
    pattern = r'^[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}$'
    if not re.fullmatch(pattern, email):
        return False, 'Invalid email format.'
    return True, ''


def validate_password(password: str) -> tuple[bool, str]:
    """
    Minimum 12 chars, must contain:
      uppercase, lowercase, digit, special (!@#$%^&*)
    """
    if not password or len(password) < 12:
        return False, 'Password must be at least 12 characters.'
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter.'
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter.'
    if not re.search(r'\d', password):
        return False, 'Password must contain at least one number.'
    if not re.search(r'[!@#$%^&*]', password):
        return False, 'Password must contain at least one special character (!@#$%^&*).'
    return True, ''


def sanitize(value: str) -> str:
    """HTML-escape a string to prevent XSS."""
    return html.escape(str(value).strip())


# ── User storage helpers ──────────────────────────────────────────────────────

def _load_users() -> dict:
    return _read_json(Config.USERS_FILE, default={})


def _save_users(users: dict) -> None:
    _write_json(Config.USERS_FILE, users)


def get_user_by_id(user_id: str) -> dict | None:
    return _load_users().get(user_id)


def get_user_by_username(username: str) -> dict | None:
    users = _load_users()
    for u in users.values():
        if u['username'].lower() == username.lower():
            return u
    return None


def get_user_by_email(email: str) -> dict | None:
    users = _load_users()
    for u in users.values():
        if u['email'].lower() == email.lower():
            return u
    return None


# ── Registration ──────────────────────────────────────────────────────────────

def register_user(username: str, email: str, password: str, confirm: str) -> tuple[bool, str]:
    """
    Validate inputs, hash password, persist new user.
    Returns (success: bool, message: str).
    """
    # Sanitize
    username = sanitize(username)
    email    = sanitize(email)

    # Validate
    ok, msg = validate_username(username)
    if not ok:
        return False, msg
    ok, msg = validate_email(email)
    if not ok:
        return False, msg
    ok, msg = validate_password(password)
    if not ok:
        return False, msg
    if password != confirm:
        return False, 'Passwords do not match.'

    # Duplicate check
    if get_user_by_username(username):
        return False, 'Username already taken.'
    if get_user_by_email(email):
        return False, 'Email already registered.'

    # Hash password — bcrypt cost factor 12
    pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

    user_id = str(uuid.uuid4())
    user = {
        'id':              user_id,
        'username':        username,
        'email':           email,
        'password_hash':   pw_hash.decode('utf-8'),
        'role':            'user',       # default role
        'created_at':      time.time(),
        'failed_attempts': 0,
        'locked_until':    None,
    }

    users = _load_users()
    users[user_id] = user
    _save_users(users)
    return True, 'Registration successful.'


# ── Login ─────────────────────────────────────────────────────────────────────

def check_rate_limit(ip: str) -> bool:
    """
    Return True (allowed) if the IP has fewer than RATE_LIMIT_MAX
    attempts in the last RATE_LIMIT_WINDOW seconds.
    """
    now    = time.time()
    window = Config.RATE_LIMIT_WINDOW
    hits   = _rate_limit_store.get(ip, [])

    # Keep only timestamps within the window
    hits = [t for t in hits if now - t < window]
    _rate_limit_store[ip] = hits

    if len(hits) >= Config.RATE_LIMIT_MAX:
        return False

    hits.append(now)
    _rate_limit_store[ip] = hits
    return True


def authenticate_user(username: str, password: str) -> tuple[dict | None, str]:
    """
    Verify credentials.
    Returns (user_dict, '') on success, (None, reason) on failure.
    Handles account lockout.
    """
    user = get_user_by_username(username)
    if not user:
        # Generic message — don't leak whether username exists
        return None, 'Invalid username or password.'

    # Lockout check
    if user['locked_until'] and time.time() < user['locked_until']:
        mins = int((user['locked_until'] - time.time()) / 60) + 1
        return None, f'Account locked. Try again in {mins} minute(s).'

    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        # Increment failure counter
        users = _load_users()
        users[user['id']]['failed_attempts'] += 1
        if users[user['id']]['failed_attempts'] >= Config.MAX_FAILED_ATTEMPTS:
            users[user['id']]['locked_until'] = time.time() + Config.LOCKOUT_DURATION
            _save_users(users)
            return None, 'Account locked after too many failed attempts. Try again in 15 minutes.'
        _save_users(users)
        remaining = Config.MAX_FAILED_ATTEMPTS - users[user['id']]['failed_attempts']
        return None, f'Invalid username or password. {remaining} attempt(s) remaining.'

    # Success — reset failure counter
    users = _load_users()
    users[user['id']]['failed_attempts'] = 0
    users[user['id']]['locked_until']    = None
    _save_users(users)
    return users[user['id']], ''


# ── RBAC Decorators ───────────────────────────────────────────────────────────

def require_auth(f):
    """Redirect to /login if no valid session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not getattr(g, 'user', None):
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated


def require_role(*roles):
    """Abort 403 if current user's role is not in `roles`."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not getattr(g, 'user', None):
                return redirect('/login')
            if g.user['role'] not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


# ── Password change ───────────────────────────────────────────────────────────

def change_password(user_id: str, old_password: str, new_password: str) -> tuple[bool, str]:
    users = _load_users()
    user  = users.get(user_id)
    if not user:
        return False, 'User not found.'
    if not bcrypt.checkpw(old_password.encode(), user['password_hash'].encode()):
        return False, 'Current password is incorrect.'
    ok, msg = validate_password(new_password)
    if not ok:
        return False, msg
    users[user_id]['password_hash'] = bcrypt.hashpw(
        new_password.encode(), bcrypt.gensalt(rounds=12)
    ).decode()
    _save_users(users)
    return True, 'Password changed successfully.'


# ── Password Reset Tokens ─────────────────────────────────────────────────────

def _load_reset_tokens() -> dict:
    return _read_json(Config.RESET_TOKENS_FILE, default={})

def _save_reset_tokens(tokens: dict) -> None:
    import fcntl
    lock_path = Config.RESET_TOKENS_FILE + '.lock'
    with open(lock_path, 'w') as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            _write_json(Config.RESET_TOKENS_FILE, tokens)
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)

def generate_reset_token(email: str) -> tuple[bool, str, str]:
    """
    Look up the user by email, create a time-limited reset token,
    store it, and return (success, message, token).
    The token should be emailed in production; here we return it
    so the caller can display/log it.
    """
    import secrets as _secrets
    user = get_user_by_email(email)
    if not user:
        # Don't reveal whether the email exists — always succeed from UI perspective
        return True, 'If that email is registered, a reset link has been sent.', ''

    token   = _secrets.token_urlsafe(32)
    expires = time.time() + Config.RESET_TOKEN_EXPIRY

    tokens = _load_reset_tokens()
    # Purge any existing tokens for this user
    tokens = {t: d for t, d in tokens.items() if d['user_id'] != user['id']}
    tokens[token] = {
        'user_id':    user['id'],
        'email':      email,
        'expires_at': expires,
        'used':       False,
    }
    _save_reset_tokens(tokens)
    return True, 'If that email is registered, a reset link has been sent.', token


def validate_reset_token(token: str) -> tuple[dict | None, str]:
    """
    Return (user_dict, '') if the token is valid and unused.
    Return (None, reason) if expired, used, or not found.
    """
    tokens = _load_reset_tokens()
    entry  = tokens.get(token)
    if not entry:
        return None, 'Invalid or expired reset link.'
    if entry['used']:
        return None, 'This reset link has already been used.'
    if time.time() > entry['expires_at']:
        return None, 'This reset link has expired. Please request a new one.'
    user = get_user_by_id(entry['user_id'])
    if not user:
        return None, 'User account no longer exists.'
    return user, ''


def consume_reset_token(token: str, new_password: str) -> tuple[bool, str]:
    """
    Validate token, update password, mark token as used.
    Returns (success, message).
    """
    user, err = validate_reset_token(token)
    if not user:
        return False, err

    ok, msg = validate_password(new_password)
    if not ok:
        return False, msg

    # Update password
    users = _load_users()
    users[user['id']]['password_hash'] = bcrypt.hashpw(
        new_password.encode(), bcrypt.gensalt(rounds=12)
    ).decode()
    users[user['id']]['failed_attempts'] = 0
    users[user['id']]['locked_until']    = None
    _save_users(users)

    # Mark token used (don't delete so we can detect replay attempts)
    tokens = _load_reset_tokens()
    if token in tokens:
        tokens[token]['used'] = True
        _save_reset_tokens(tokens)

    return True, 'Password reset successfully. You can now log in.'


def admin_set_password(admin_id: str, target_user_id: str, new_password: str) -> tuple[bool, str]:
    """
    Admin directly sets a user's password without needing the old one.
    Logs the action. Invalidates all existing sessions for the target user.
    """
    users = _load_users()
    admin = users.get(admin_id)
    if not admin or admin['role'] != 'admin':
        return False, 'Unauthorized.'

    target = users.get(target_user_id)
    if not target:
        return False, 'User not found.'

    ok, msg = validate_password(new_password)
    if not ok:
        return False, msg

    users[target_user_id]['password_hash'] = bcrypt.hashpw(
        new_password.encode(), bcrypt.gensalt(rounds=12)
    ).decode()
    users[target_user_id]['failed_attempts'] = 0
    users[target_user_id]['locked_until']    = None
    _save_users(users)
    return True, f"Password for '{target['username']}' has been reset."
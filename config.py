"""
config.py - Application Configuration
All secrets should come from environment variables in production.
"""

import os

class Config:
    # ── Flask ──────────────────────────────────────────────────────────────
    # In production: export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
    SECRET_KEY = os.environ.get('SECRET_KEY', 'change-me-in-production')
    ENV = os.environ.get('FLASK_ENV', 'development')
    DEBUG = ENV == 'development'

    # ── Directories ────────────────────────────────────────────────────────
    BASE_DIR     = os.path.abspath(os.path.dirname(__file__))
    DATA_DIR     = os.path.join(BASE_DIR, 'data')
    LOGS_DIR     = os.path.join(BASE_DIR, 'logs')
    UPLOAD_DIR   = os.path.join(DATA_DIR, 'documents')

    # ── File storage paths ─────────────────────────────────────────────────
    USERS_FILE     = os.path.join(DATA_DIR, 'users.json')
    SESSIONS_FILE  = os.path.join(DATA_DIR, 'sessions.json')
    DOCUMENTS_FILE = os.path.join(DATA_DIR, 'documents.json')
    KEY_FILE         = os.path.join(DATA_DIR, 'secret.key')   # Fernet key — NEVER commit
    RESET_TOKENS_FILE = os.path.join(DATA_DIR, 'reset_tokens.json')

    # ── Password reset ─────────────────────────────────────────────────────
    RESET_TOKEN_EXPIRY = 3600        # 1 hour (seconds)

    # ── Upload limits ──────────────────────────────────────────────────────
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024          # 16 MB hard cap
    ALLOWED_EXTENSIONS = {'pdf', 'txt', 'docx', 'png', 'jpg', 'jpeg'}

    # ── Session ────────────────────────────────────────────────────────────
    SESSION_TIMEOUT = 1800           # 30 minutes (seconds)

    # ── Account lockout ────────────────────────────────────────────────────
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION    = 900        # 15 minutes (seconds)

    # ── Rate limiting (login endpoint) ─────────────────────────────────────
    RATE_LIMIT_WINDOW = 60           # 1-minute window
    RATE_LIMIT_MAX    = 10           # max attempts per IP per window

    # ── TLS (development self-signed cert) ─────────────────────────────────
    TLS_CERT = os.path.join(BASE_DIR, 'cert.pem')
    TLS_KEY  = os.path.join(BASE_DIR, 'key.pem')
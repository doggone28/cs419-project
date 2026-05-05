# CS 419 — Secure Document Sharing System
Spring 2026 | Team Project

A secure web application for uploading, encrypting, and sharing confidential documents between users, built with Python/Flask.

---

## Features

- **User authentication** — registration, login, logout, password change
- **Role-based access control** — Admin, User, and Guest roles with enforced permissions
- **Document management** — upload, download, share, and delete encrypted documents
- **Document sharing** — grant Viewer or Editor access to specific users
- **Admin panel** — manage user roles, unlock locked accounts, reset user passwords
- **Security event logging** — all auth, access, and admin actions logged to `logs/security.log`

---

## Security Implementations

| Control | Implementation |
|---|---|
| Password hashing | bcrypt, cost factor 12 |
| Account lockout | 5 failed attempts → 15-minute lockout |
| Rate limiting | Max 10 login attempts per IP per minute |
| Session tokens | `secrets.token_urlsafe(32)`, 30-minute timeout |
| Session cookies | `HttpOnly`, `Secure` (production), `SameSite=Strict` |
| Data-at-rest encryption | Fernet (AES-128) — all uploaded files encrypted on disk |
| Transport encryption | TLS with self-signed certificate (HTTPS) |
| HTTPS enforcement | HTTP → HTTPS redirect in production mode |
| XSS prevention | Jinja2 auto-escaping + `html.escape` on all inputs |
| Path traversal prevention | Magic-byte + extension validation on uploads; `os.path.abspath` guard on downloads |
| MIME type validation | Magic-byte check on every uploaded file |
| Security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Input validation | Whitelist regex on username/email/password; length limits on all fields |

---

## Project Structure

```
secure-app/
├── app.py                  # Flask routes and app setup
├── auth.py                 # Registration, login, RBAC decorators
├── documents.py            # Upload, download, share, encryption logic
├── storage.py              # EncryptedStorage (Fernet) + SessionManager
├── logger.py               # Security event logger
├── config.py               # App configuration
├── test_security.py        # Security test suite (88 tests)
├── requirements.txt
├── cert.pem / key.pem      # TLS certificate (self-signed, not committed)
├── data/
│   ├── users.json          # User accounts
│   ├── sessions.json       # Active sessions
│   ├── documents.json      # Document metadata
│   └── documents/          # Encrypted document files (.enc)
├── logs/
│   └── security.log        # Security event log (JSON lines)
├── static/
│   └── js/
│       └── password-toggle.js
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── upload.html
│   ├── share.html
│   ├── profile.html
│   ├── admin.html
│   ├── admin_reset_password.html
│   ├── forgot_password.html
│   └── error.html
└── docs/
    ├── security_design.pdf
    └── pentest_report.pdf
```

---

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate a TLS certificate (one-time)

```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -out cert.pem -keyout key.pem -days 365 \
  -subj "/C=US/ST=Illinois/L=Chicago/O=CS419/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

### 3. Run the app

```bash
python3 app.py
```

Accessible at **`https://localhost:6505`**

> Your browser will show a certificate warning for the self-signed cert.
> Click **Advanced → Proceed to localhost** to continue.

---

## Running Modes

| Command | Mode | Notes |
|---|---|---|
| `python3 app.py` | HTTPS (default) | Requires `cert.pem` + `key.pem` |
| `python3 app.py --no-tls` | HTTP only | Development fallback |
| `FLASK_ENV=production python3 app.py` | HTTPS + production flags | Enables forced HTTPS redirect and secure cookies |

---

## First-Time Setup

1. Navigate to `https://localhost:6505/register` and create an account.
2. To make an admin account, open `data/users.json` and change the user's `"role"` field to `"admin"`.
3. Log in — admins will see an **Admin** link in the navbar.

---

## Running Tests

```bash
python3 test_security.py
```

Runs 88 automated tests covering: input validation, authentication, rate limiting, access control, path traversal prevention, session management, and encryption.

---

## Notes

- **Password reset** is a placeholder — no email service is integrated. The "Forgot Password" page accepts input but does not send emails.
- **`data/secret.key`** is the Fernet encryption key. Never commit this file — it decrypts all stored documents.
- **`key.pem`** is the TLS private key. Never commit this file.
- Both files are excluded in `.gitignore`.

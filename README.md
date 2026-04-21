# 🔒 SecureDocs — CS 419 Secure Web Application

A secure document sharing system built with Flask for CS 419 (Spring 2026).

---

## Features

| Feature | Implementation |
|---|---|
| Authentication | bcrypt (cost 12), account lockout, rate limiting |
| Access Control | RBAC: admin / user / guest |
| Input Validation | Whitelist regex, length limits, HTML escaping |
| Encryption | Fernet (AES-128-CBC) for files + JSON data at rest |
| Session Management | 256-bit random tokens, HttpOnly + SameSite cookies |
| Security Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc. |
| Logging | Structured JSON security event log |

---

## Quick Start

### 1. Clone & enter the project
```bash
git clone <your-repo-url>
cd secure-app
```

### 2. Create a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Set environment variables
```bash
# Generate a strong secret key
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export FLASK_ENV=development
```

### 5. Run the app
```bash
python app.py
```
Visit: http://localhost:5000

### 6. (Optional) Run with self-signed TLS
```bash
# Generate cert
openssl req -x509 -newkey rsa:4096 -nodes \
  -out cert.pem -keyout key.pem -days 365 \
  -subj "/CN=localhost"

python app.py --tls
```
Visit: https://localhost:5000

---

## Default Roles

| Role | Permissions |
|---|---|
| **admin** | Full access — manage users, view all docs |
| **user** | Upload, share, download own + shared docs |
| **guest** | View and download shared docs only |

To make yourself an admin: edit `data/users.json` and set `"role": "admin"`.

---

## Project Structure

```
secure-app/
├── app.py              # Flask application & routes
├── auth.py             # Registration, login, RBAC decorators
├── documents.py        # Document upload/download/share/delete
├── storage.py          # Fernet encrypted storage + session manager
├── logger.py           # Structured security event logger
├── config.py           # Configuration (env-driven)
├── requirements.txt
├── data/
│   ├── users.json      # User accounts (encrypted in prod)
│   ├── sessions.json   # Active sessions
│   ├── documents.json  # Document metadata
│   ├── documents/      # Encrypted document files (.enc)
│   └── secret.key      # Fernet key — NEVER commit!
├── logs/
│   └── security.log    # JSON security events
├── static/
│   ├── css/style.css
│   └── js/main.js
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── upload.html
│   ├── share.html
│   ├── profile.html
│   ├── admin.html
│   └── error.html
├── tests/
│   └── test_security.py
└── docs/               # Security design doc + pentest report
```

---

## Security Notes

- **`data/secret.key`** — Fernet encryption key. Back it up. Never commit it.
  Add to `.gitignore`:
  ```
  data/secret.key
  data/documents/
  logs/
  *.pem
  __pycache__/
  venv/
  .env
  ```
- Passwords are hashed with **bcrypt cost factor 12** — never stored in plaintext.
- Session tokens are **256-bit cryptographically random** (`secrets.token_urlsafe(32)`).
- All cookies are **HttpOnly + SameSite=Strict** (+ Secure in production).
- Security events are logged to `logs/security.log` in structured JSON.

---

## Running Tests
```bash
python -m pytest tests/ -v
```

---

## Security Testing Tools

- [OWASP ZAP](https://www.zaproxy.org/) — automated scanner
- [Burp Suite Community](https://portswigger.net/burp) — manual proxy testing
- [SecurityHeaders.com](https://securityheaders.com) — verify HTTP headers

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Flask Docs](https://flask.palletsprojects.com/)
- [cryptography.io](https://cryptography.io/)

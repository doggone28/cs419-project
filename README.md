# CS 419 — Secure Document Sharing System

## Setup

```bash
pip install -r requirements.txt
```

## Running the app

### HTTPS (default — certificate files must exist)
```bash
python3 app.py
```
Accessible at `https://localhost:6505`

> Your browser will warn about the self-signed certificate. Click **Advanced → Proceed** to continue.

**If `cert.pem` / `key.pem` are missing**, generate them first (one-time):
```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -out cert.pem -keyout key.pem -days 365 \
  -subj "/C=US/ST=Illinois/L=Chicago/O=CS419/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

### HTTP only (development fallback)
```bash
python3 app.py --no-tls
```

### Production mode (HTTPS redirect + secure cookies)
```bash
export FLASK_ENV=production
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python app.py --tls
```

## Default accounts

On first run, no accounts exist. Register at `/register`.  
To create an admin, register normally then manually edit `data/users.json` and set `"role": "admin"`.

## Security features implemented

- bcrypt password hashing (cost factor 12)
- Account lockout after 5 failed attempts (15 min)
- Rate limiting: 10 login attempts per IP per minute
- RBAC: admin / user / guest roles
- Fernet AES-128 encryption for stored documents
- Session tokens via `secrets.token_urlsafe(32)`, 30-min timeout
- All security headers (CSP, HSTS, X-Frame-Options, etc.)
- Full security event logging to `logs/security.log`
- XSS prevention via Jinja2 auto-escaping + `html.escape`
- Path traversal prevention on all file operations
- HTTPS via TLS with self-signed cert; HTTP→HTTPS redirect in production

"""
storage.py - Encrypted Storage & Session Manager

EncryptedStorage  : Fernet-based encrypted JSON file I/O.
SessionManager    : Secure token-based session management backed by JSON.
"""

import json
import os
import secrets
import time

from cryptography.fernet import Fernet


# ── Encrypted Storage ──────────────────────────────────────────────────────────

class EncryptedStorage:
    """
    Persist arbitrary Python dicts as AES-128-CBC (Fernet) encrypted files.
    The symmetric key is stored in KEY_FILE (never commit this file).
    """

    def __init__(self, key_file: str = 'data/secret.key'):
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.key)
            # Restrict permissions: owner read-only
            os.chmod(key_file, 0o600)
        self.cipher = Fernet(self.key)

    def save(self, filepath: str, data) -> None:
        """Serialize `data` to JSON, then encrypt and write to `filepath`."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        plaintext  = json.dumps(data).encode()
        ciphertext = self.cipher.encrypt(plaintext)
        with open(filepath, 'wb') as f:
            f.write(ciphertext)

    def load(self, filepath: str, default=None):
        """Read, decrypt and deserialize `filepath`; return `default` if missing."""
        if not os.path.exists(filepath):
            return default
        with open(filepath, 'rb') as f:
            ciphertext = f.read()
        if not ciphertext:
            return default
        plaintext = self.cipher.decrypt(ciphertext)
        return json.loads(plaintext.decode())

    def encrypt_file(self, src_path: str, dest_path: str) -> None:
        """Encrypt a raw binary file (document uploads)."""
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(src_path, 'rb') as f:
            raw = f.read()
        with open(dest_path, 'wb') as f:
            f.write(self.cipher.encrypt(raw))

    def decrypt_file(self, enc_path: str) -> bytes:
        """Decrypt and return raw bytes of an encrypted document."""
        with open(enc_path, 'rb') as f:
            return self.cipher.decrypt(f.read())


# ── Simple unencrypted JSON helpers (for non-sensitive lists) ─────────────────

def _read_json(filepath: str, default=None):
    if not os.path.exists(filepath):
        return default if default is not None else {}
    with open(filepath, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return default if default is not None else {}


def _write_json(filepath: str, data) -> None:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)


# ── Session Manager ────────────────────────────────────────────────────────────

class SessionManager:
    """
    Token-based sessions stored in sessions.json.
    Tokens: 256-bit URL-safe random strings (secrets.token_urlsafe(32)).
    Sessions expire after `timeout` seconds of inactivity.
    """

    def __init__(
        self,
        sessions_file: str = 'data/sessions.json',
        timeout: int = 1800,
    ):
        self.sessions_file = sessions_file
        self.timeout       = timeout

    # ── Internal helpers ───────────────────────────────────────────────────

    def _load(self) -> dict:
        return _read_json(self.sessions_file, default={})

    def _save(self, sessions: dict) -> None:
        _write_json(self.sessions_file, sessions)

    # ── Public API ─────────────────────────────────────────────────────────

    def create(self, user_id: str, ip: str, user_agent: str) -> str:
        """Create a new session and return the token."""
        token   = secrets.token_urlsafe(32)
        now     = time.time()
        sessions = self._load()
        sessions[token] = {
            'user_id':       user_id,
            'created_at':    now,
            'last_activity': now,
            'ip_address':    ip,
            'user_agent':    user_agent,
        }
        self._save(sessions)
        return token

    def validate(self, token: str) -> dict | None:
        """
        Return session dict if valid, else None.
        Updates last_activity on success. Destroys expired sessions.
        """
        if not token:
            return None
        sessions = self._load()
        session  = sessions.get(token)
        if not session:
            return None

        # Timeout check
        if time.time() - session['last_activity'] > self.timeout:
            self.destroy(token)
            return None

        # Refresh last_activity
        session['last_activity'] = time.time()
        sessions[token] = session
        self._save(sessions)
        return session

    def destroy(self, token: str) -> None:
        """Delete a specific session (logout)."""
        sessions = self._load()
        sessions.pop(token, None)
        self._save(sessions)

    def destroy_all_for_user(self, user_id: str) -> None:
        """Invalidate every session belonging to `user_id` (e.g. password change)."""
        sessions = self._load()
        to_delete = [t for t, s in sessions.items() if s['user_id'] == user_id]
        for t in to_delete:
            del sessions[t]
        self._save(sessions)

    def purge_expired(self) -> int:
        """Remove all timed-out sessions. Returns count removed."""
        sessions = self._load()
        now      = time.time()
        expired  = [t for t, s in sessions.items()
                    if now - s['last_activity'] > self.timeout]
        for t in expired:
            del sessions[t]
        self._save(sessions)
        return len(expired)

"""
storage.py - Encrypted Storage & Session Manager

EncryptedStorage  : Fernet-based encrypted JSON file I/O.
SessionManager    : Secure token-based session management backed by JSON.
"""

import fcntl
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

    Uses an exclusive file lock on every write so concurrent requests
    from multiple active sessions don't overwrite each other.
    validate() only writes when a session needs to be destroyed (expired);
    last_activity is checked in memory but NOT written back on every request
    to avoid constant full-file rewrites.
    """

    def __init__(self, sessions_file: str = 'data/sessions.json', timeout: int = 1800):
        self.sessions_file = sessions_file
        self.timeout       = timeout
        os.makedirs(os.path.dirname(sessions_file), exist_ok=True)

    # ── Lock-safe read/write ───────────────────────────────────────────────

    def _load(self) -> dict:
        if not os.path.exists(self.sessions_file):
            return {}
        with open(self.sessions_file, 'r') as f:
            try:
                return json.load(f)
            except (json.JSONDecodeError, ValueError):
                return {}

    def _locked_update(self, fn):
        """
        Open the sessions file with an exclusive lock, call fn(sessions) → sessions,
        write the result back, then release the lock.
        This prevents concurrent requests from clobbering each other.
        """
        lock_path = self.sessions_file + '.lock'
        with open(lock_path, 'w') as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                sessions = self._load()
                sessions = fn(sessions)
                with open(self.sessions_file, 'w') as f:
                    json.dump(sessions, f, indent=2)
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)

    # ── Public API ─────────────────────────────────────────────────────────

    def create(self, user_id: str, ip: str, user_agent: str) -> str:
        """Create a new session and return the token."""
        token = secrets.token_urlsafe(32)
        now   = time.time()
        entry = {
            'user_id':       user_id,
            'created_at':    now,
            'last_activity': now,
            'ip_address':    ip,
            'user_agent':    user_agent,
        }
        def add(sessions):
            sessions[token] = entry
            return sessions
        self._locked_update(add)
        return token

    def validate(self, token: str) -> dict | None:
        """
        Return session dict if valid, else None.
        Does NOT write last_activity on every request — only removes expired sessions.
        This prevents concurrent sessions from overwriting each other.
        """
        if not token:
            return None
        sessions = self._load()
        session  = sessions.get(token)
        if not session:
            return None

        # Expired — destroy and reject
        if time.time() - session['last_activity'] > self.timeout:
            self.destroy(token)
            return None

        return session

    def touch(self, token: str) -> None:
        """
        Refresh last_activity for a token.
        Called periodically (e.g. on write operations) rather than every request
        to avoid hammering the file on every page load.
        """
        def update(sessions):
            if token in sessions:
                sessions[token]['last_activity'] = time.time()
            return sessions
        self._locked_update(update)

    def destroy(self, token: str) -> None:
        """Delete a specific session (logout)."""
        def remove(sessions):
            sessions.pop(token, None)
            return sessions
        self._locked_update(remove)

    def destroy_all_for_user(self, user_id: str) -> None:
        """Invalidate every session belonging to `user_id` (e.g. password change)."""
        def remove_all(sessions):
            return {t: s for t, s in sessions.items() if s['user_id'] != user_id}
        self._locked_update(remove_all)

    def purge_expired(self) -> int:
        """Remove all timed-out sessions. Returns count removed."""
        now     = time.time()
        removed = 0
        def purge(sessions):
            nonlocal removed
            fresh   = {t: s for t, s in sessions.items()
                       if now - s['last_activity'] <= self.timeout}
            removed = len(sessions) - len(fresh)
            return fresh
        self._locked_update(purge)
        return removed
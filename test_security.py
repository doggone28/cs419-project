"""
tests/test_security.py
CS 419 — Security Test Suite

Run with:  python -m pytest tests/ -v
"""

import json
import os
import sys
import time

import pytest

# ── Bootstrap path so imports resolve ─────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from auth import (validate_email, validate_password, validate_username,
                  sanitize, check_rate_limit, register_user, authenticate_user,
                  _save_users)
from config import Config


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_users(tmp_path, monkeypatch):
    """Each test gets a fresh, empty users file in a temp dir."""
    monkeypatch.setattr(Config, 'USERS_FILE',
                        str(tmp_path / 'users.json'))
    _save_users({})
    yield


# ══════════════════════════════════════════════════════════════════════════════
# A. Input Validation
# ══════════════════════════════════════════════════════════════════════════════

class TestUsernameValidation:
    def test_valid(self):
        ok, _ = validate_username('alice_01')
        assert ok

    def test_too_short(self):
        ok, msg = validate_username('ab')
        assert not ok
        assert 'alphanumeric' in msg.lower() or '3' in msg

    def test_too_long(self):
        ok, _ = validate_username('a' * 21)
        assert not ok

    def test_special_chars_rejected(self):
        ok, _ = validate_username('user<script>')
        assert not ok

    def test_path_traversal_rejected(self):
        ok, _ = validate_username('../etc/passwd')
        assert not ok


class TestEmailValidation:
    def test_valid(self):
        ok, _ = validate_email('user@example.com')
        assert ok

    def test_missing_at(self):
        ok, _ = validate_email('userexample.com')
        assert not ok

    def test_empty(self):
        ok, _ = validate_email('')
        assert not ok


class TestPasswordValidation:
    def test_strong_password(self):
        ok, _ = validate_password('Str0ng!Pass#99')
        assert ok

    def test_too_short(self):
        ok, msg = validate_password('Short1!')
        assert not ok
        assert '12' in msg

    def test_missing_uppercase(self):
        ok, _ = validate_password('weak1password!')
        assert not ok

    def test_missing_lowercase(self):
        ok, _ = validate_password('WEAK1PASSWORD!')
        assert not ok

    def test_missing_digit(self):
        ok, _ = validate_password('WeakPassword!!')
        assert not ok

    def test_missing_special(self):
        ok, _ = validate_password('WeakPassword123')
        assert not ok


class TestSanitizeXSS:
    """Verify HTML-escaping strips XSS payloads."""

    def test_script_tag_escaped(self):
        result = sanitize('<script>alert(1)</script>')
        assert '<script>' not in result
        assert '&lt;script&gt;' in result

    def test_onerror_escaped(self):
        result = sanitize('<img src=x onerror=alert(1)>')
        assert 'onerror' not in result or '&lt;' in result

    def test_safe_string_unchanged(self):
        result = sanitize('hello world')
        assert result == 'hello world'


# ══════════════════════════════════════════════════════════════════════════════
# B. Authentication
# ══════════════════════════════════════════════════════════════════════════════

class TestRegistration:
    def test_successful_registration(self):
        ok, msg = register_user('testuser', 'test@example.com',
                                'Str0ng!Pass#99', 'Str0ng!Pass#99')
        assert ok

    def test_duplicate_username(self):
        register_user('testuser', 'a@example.com', 'Str0ng!Pass#99', 'Str0ng!Pass#99')
        ok, msg = register_user('testuser', 'b@example.com', 'Str0ng!Pass#99', 'Str0ng!Pass#99')
        assert not ok
        assert 'taken' in msg.lower()

    def test_duplicate_email(self):
        register_user('user1', 'same@example.com', 'Str0ng!Pass#99', 'Str0ng!Pass#99')
        ok, msg = register_user('user2', 'same@example.com', 'Str0ng!Pass#99', 'Str0ng!Pass#99')
        assert not ok
        assert 'email' in msg.lower()

    def test_password_mismatch(self):
        ok, msg = register_user('user3', 'u3@example.com',
                                'Str0ng!Pass#99', 'Different1!')
        assert not ok
        assert 'match' in msg.lower()

    def test_password_not_stored_plaintext(self):
        """Ensure bcrypt hash is stored, not the raw password."""
        from auth import _load_users
        register_user('hashtest', 'ht@example.com', 'Str0ng!Pass#99', 'Str0ng!Pass#99')
        users = _load_users()
        user  = next(u for u in users.values() if u['username'] == 'hashtest')
        assert user['password_hash'] != 'Str0ng!Pass#99'
        assert user['password_hash'].startswith('$2b$')   # bcrypt prefix


class TestAuthentication:
    def setup_method(self):
        register_user('loginuser', 'lu@example.com',
                      'Str0ng!Pass#99', 'Str0ng!Pass#99')

    def test_valid_credentials(self):
        user, err = authenticate_user('loginuser', 'Str0ng!Pass#99')
        assert user is not None
        assert err == ''

    def test_wrong_password(self):
        user, err = authenticate_user('loginuser', 'WrongPass1!')
        assert user is None
        assert err != ''

    def test_nonexistent_user(self):
        user, err = authenticate_user('nobody', 'Str0ng!Pass#99')
        assert user is None
        # Must NOT reveal whether username exists
        assert 'invalid' in err.lower() or 'incorrect' in err.lower()

    def test_account_lockout_after_five_failures(self):
        """Account should lock after 5 bad attempts."""
        for _ in range(5):
            authenticate_user('loginuser', 'WrongPass1!')
        user, err = authenticate_user('loginuser', 'Str0ng!Pass#99')
        assert user is None
        assert 'lock' in err.lower()

    def test_lockout_message_does_not_reveal_password(self):
        """Error messages must not include the submitted password."""
        for _ in range(5):
            authenticate_user('loginuser', 'WrongPass1!')
        _, err = authenticate_user('loginuser', 'WrongPass1!')
        assert 'WrongPass1!' not in err


# ══════════════════════════════════════════════════════════════════════════════
# C. Rate Limiting
# ══════════════════════════════════════════════════════════════════════════════

class TestRateLimit:
    def test_allows_within_limit(self):
        """First 10 attempts from an IP should pass."""
        from auth import _rate_limit_store
        _rate_limit_store.clear()
        for _ in range(10):
            assert check_rate_limit('1.2.3.4') is True

    def test_blocks_eleventh_attempt(self):
        from auth import _rate_limit_store
        _rate_limit_store.clear()
        for _ in range(10):
            check_rate_limit('5.6.7.8')
        assert check_rate_limit('5.6.7.8') is False

    def test_different_ips_independent(self):
        from auth import _rate_limit_store
        _rate_limit_store.clear()
        for _ in range(10):
            check_rate_limit('10.0.0.1')
        # Different IP should still be allowed
        assert check_rate_limit('10.0.0.2') is True


# ══════════════════════════════════════════════════════════════════════════════
# D. Access Control
# ══════════════════════════════════════════════════════════════════════════════

class TestAccessControl:
    def test_can_read_as_owner(self):
        from documents import can_read
        doc = {'owner_id': 'u1', 'shares': {}}
        assert can_read(doc, 'u1', 'user') is True

    def test_cannot_read_without_share(self):
        from documents import can_read
        doc = {'owner_id': 'u1', 'shares': {}}
        assert can_read(doc, 'u2', 'user') is False

    def test_viewer_can_read(self):
        from documents import can_read
        doc = {'owner_id': 'u1', 'shares': {'u2': 'viewer'}}
        assert can_read(doc, 'u2', 'user') is True

    def test_viewer_cannot_write(self):
        from documents import can_write
        doc = {'owner_id': 'u1', 'shares': {'u2': 'viewer'}}
        assert can_write(doc, 'u2', 'user') is False

    def test_editor_can_write(self):
        from documents import can_write
        doc = {'owner_id': 'u1', 'shares': {'u2': 'editor'}}
        assert can_write(doc, 'u2', 'user') is True

    def test_admin_can_read_any(self):
        from documents import can_read
        doc = {'owner_id': 'u1', 'shares': {}}
        assert can_read(doc, 'u999', 'admin') is True

    def test_non_owner_cannot_delete(self):
        from documents import can_delete
        doc = {'owner_id': 'u1', 'shares': {}}
        assert can_delete(doc, 'u2', 'user') is False


# ══════════════════════════════════════════════════════════════════════════════
# E. Path Traversal Prevention
# ══════════════════════════════════════════════════════════════════════════════

class TestPathTraversal:
    def test_traversal_rejected(self):
        from documents import safe_filename_check
        with pytest.raises((ValueError, Exception)):
            safe_filename_check('../../../etc/passwd')

    def test_double_dot_rejected(self):
        from documents import safe_filename_check
        with pytest.raises((ValueError, Exception)):
            safe_filename_check('..\\windows\\system32\\config')

    def test_normal_filename_accepted(self):
        from documents import safe_filename_check
        result = safe_filename_check('report_2026.pdf')
        assert result == 'report_2026.pdf'

    def test_null_byte_rejected(self):
        from documents import safe_filename_check
        with pytest.raises(Exception):
            safe_filename_check('file\x00.txt')

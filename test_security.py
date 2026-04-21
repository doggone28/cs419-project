"""
test_security.py — CS 419 Security Test Suite
Run from your project root:  python3 test_security.py

No extra tools required — uses Python's built-in unittest only.
"""

import json
import os
import sys
import tempfile
import time
import unittest

# ── Make sure imports resolve from the project root ───────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auth import (
    validate_username, validate_email, validate_password,
    sanitize, check_rate_limit, register_user, authenticate_user,
    _load_users, _save_users, change_password,
)
from config import Config
from documents import can_read, can_write, can_delete, safe_filename_check
from storage import SessionManager


# ══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════════════

class BaseTest(unittest.TestCase):
    """
    Redirects users.json to a temp file so every test starts clean
    without touching real data.
    """
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        )
        self._tmp.write('{}')
        self._tmp.close()
        self._orig_path = Config.USERS_FILE
        Config.USERS_FILE = self._tmp.name
        _save_users({})

        # Also clear in-memory rate limit store between tests
        from auth import _rate_limit_store
        _rate_limit_store.clear()

    def tearDown(self):
        Config.USERS_FILE = self._orig_path
        os.unlink(self._tmp.name)

    def _register(self, username='testuser', email='test@example.com',
                  password='Str0ng!Pass#99'):
        return register_user(username, email, password, password)


# ══════════════════════════════════════════════════════════════════════════════
#  A. Input Validation
# ══════════════════════════════════════════════════════════════════════════════

class TestUsernameValidation(BaseTest):

    def test_valid_username(self):
        ok, _ = validate_username('alice_01')
        self.assertTrue(ok)

    def test_too_short(self):
        ok, msg = validate_username('ab')
        self.assertFalse(ok)
        self.assertIn('3', msg)

    def test_too_long(self):
        ok, _ = validate_username('a' * 21)
        self.assertFalse(ok)

    def test_special_chars_rejected(self):
        ok, _ = validate_username('user<script>')
        self.assertFalse(ok)

    def test_path_traversal_rejected(self):
        ok, _ = validate_username('../etc/passwd')
        self.assertFalse(ok)

    def test_spaces_rejected(self):
        ok, _ = validate_username('user name')
        self.assertFalse(ok)


class TestEmailValidation(BaseTest):

    def test_valid_email(self):
        ok, _ = validate_email('user@example.com')
        self.assertTrue(ok)

    def test_missing_at_symbol(self):
        ok, _ = validate_email('userexample.com')
        self.assertFalse(ok)

    def test_missing_domain(self):
        ok, _ = validate_email('user@')
        self.assertFalse(ok)

    def test_empty_string(self):
        ok, _ = validate_email('')
        self.assertFalse(ok)

    def test_double_at(self):
        ok, _ = validate_email('user@@example.com')
        self.assertFalse(ok)


class TestPasswordValidation(BaseTest):

    def test_strong_password_passes(self):
        ok, _ = validate_password('Str0ng!Pass#99')
        self.assertTrue(ok)

    def test_too_short(self):
        ok, msg = validate_password('Short1!')
        self.assertFalse(ok)
        self.assertIn('12', msg)

    def test_missing_uppercase(self):
        ok, _ = validate_password('weak1password!')
        self.assertFalse(ok)

    def test_missing_lowercase(self):
        ok, _ = validate_password('WEAK1PASSWORD!')
        self.assertFalse(ok)

    def test_missing_digit(self):
        ok, _ = validate_password('WeakPassword!!')
        self.assertFalse(ok)

    def test_missing_special_char(self):
        ok, _ = validate_password('WeakPassword123')
        self.assertFalse(ok)

    def test_exactly_12_chars_passes(self):
        ok, _ = validate_password('Abcdefg1234!')
        self.assertTrue(ok)


class TestXSSPrevention(BaseTest):

    def test_script_tag_escaped(self):
        result = sanitize('<script>alert(1)</script>')
        self.assertNotIn('<script>', result)
        self.assertIn('&lt;script&gt;', result)

    def test_img_onerror_escaped(self):
        result = sanitize('<img src=x onerror=alert(1)>')
        self.assertNotIn('<img', result)

    def test_javascript_uri_escaped(self):
        result = sanitize('<a href="javascript:alert(1)">')
        self.assertNotIn('<a ', result)

    def test_safe_string_unchanged(self):
        self.assertEqual(sanitize('hello world'), 'hello world')

    def test_ampersand_escaped(self):
        result = sanitize('cats & dogs')
        self.assertIn('&amp;', result)


# ══════════════════════════════════════════════════════════════════════════════
#  B. Authentication
# ══════════════════════════════════════════════════════════════════════════════

class TestRegistration(BaseTest):

    def test_successful_registration(self):
        ok, msg = self._register()
        self.assertTrue(ok, msg)

    def test_duplicate_username_rejected(self):
        self._register(username='dupeuser', email='a@example.com')
        ok, msg = register_user('dupeuser', 'b@example.com',
                                'Str0ng!Pass#99', 'Str0ng!Pass#99')
        self.assertFalse(ok)
        self.assertIn('taken', msg.lower())

    def test_duplicate_email_rejected(self):
        self._register(username='user1', email='same@example.com')
        ok, msg = register_user('user2', 'same@example.com',
                                'Str0ng!Pass#99', 'Str0ng!Pass#99')
        self.assertFalse(ok)
        self.assertIn('email', msg.lower())

    def test_password_mismatch_rejected(self):
        ok, msg = register_user('user3', 'u3@example.com',
                                'Str0ng!Pass#99', 'DifferentPass1!')
        self.assertFalse(ok)
        self.assertIn('match', msg.lower())

    def test_password_not_stored_in_plaintext(self):
        self._register()
        users = _load_users()
        user  = next(u for u in users.values() if u['username'] == 'testuser')
        self.assertNotEqual(user['password_hash'], 'Str0ng!Pass#99')
        self.assertTrue(user['password_hash'].startswith('$2b$'))

    def test_bcrypt_cost_factor_is_12(self):
        """Verify the hash encodes cost factor 12."""
        self._register()
        users = _load_users()
        user  = next(u for u in users.values() if u['username'] == 'testuser')
        self.assertIn('$2b$12$', user['password_hash'])

    def test_default_role_is_user(self):
        self._register()
        users = _load_users()
        user  = next(u for u in users.values() if u['username'] == 'testuser')
        self.assertEqual(user['role'], 'user')

    def test_weak_password_rejected_at_registration(self):
        ok, _ = register_user('weakuser', 'w@example.com', 'password', 'password')
        self.assertFalse(ok)


class TestLogin(BaseTest):

    def setUp(self):
        super().setUp()
        self._register()

    def test_correct_credentials_succeed(self):
        user, err = authenticate_user('testuser', 'Str0ng!Pass#99')
        self.assertIsNotNone(user)
        self.assertEqual(err, '')

    def test_wrong_password_fails(self):
        user, err = authenticate_user('testuser', 'WrongPass1!')
        self.assertIsNone(user)
        self.assertNotEqual(err, '')

    def test_nonexistent_user_fails(self):
        user, err = authenticate_user('nobody', 'Str0ng!Pass#99')
        self.assertIsNone(user)

    def test_error_does_not_reveal_username_existence(self):
        _, err_no_user  = authenticate_user('nobody',   'Str0ng!Pass#99')
        _, err_bad_pass = authenticate_user('testuser', 'WrongPass1!')
        # Both messages must be indistinguishable
        self.assertEqual(
            err_no_user.split('.')[0].lower(),
            err_bad_pass.split('.')[0].lower(),
            "Error messages should not reveal whether the username exists"
        )

    def test_account_locks_after_5_failures(self):
        for _ in range(5):
            authenticate_user('testuser', 'WrongPass1!')
        user, err = authenticate_user('testuser', 'Str0ng!Pass#99')
        self.assertIsNone(user)
        self.assertIn('lock', err.lower())

    def test_correct_password_rejected_while_locked(self):
        for _ in range(5):
            authenticate_user('testuser', 'WrongPass1!')
        user, _ = authenticate_user('testuser', 'Str0ng!Pass#99')
        self.assertIsNone(user)

    def test_lockout_message_does_not_contain_password(self):
        for _ in range(5):
            authenticate_user('testuser', 'WrongPass1!')
        _, err = authenticate_user('testuser', 'WrongPass1!')
        self.assertNotIn('WrongPass1!', err)

    def test_failed_attempts_counter_increments(self):
        authenticate_user('testuser', 'WrongPass1!')
        users = _load_users()
        user  = next(u for u in users.values() if u['username'] == 'testuser')
        self.assertGreater(user['failed_attempts'], 0)

    def test_successful_login_resets_failed_attempts(self):
        authenticate_user('testuser', 'WrongPass1!')
        authenticate_user('testuser', 'Str0ng!Pass#99')
        users = _load_users()
        user  = next(u for u in users.values() if u['username'] == 'testuser')
        self.assertEqual(user['failed_attempts'], 0)


class TestPasswordChange(BaseTest):

    def setUp(self):
        super().setUp()
        self._register()
        users   = _load_users()
        self.uid = next(uid for uid, u in users.items()
                        if u['username'] == 'testuser')

    def test_valid_password_change(self):
        ok, _ = change_password(self.uid, 'Str0ng!Pass#99', 'NewPass!Word1@')
        self.assertTrue(ok)

    def test_wrong_old_password_rejected(self):
        ok, msg = change_password(self.uid, 'WrongOld1!', 'NewPass!Word1@')
        self.assertFalse(ok)

    def test_weak_new_password_rejected(self):
        ok, _ = change_password(self.uid, 'Str0ng!Pass#99', 'weak')
        self.assertFalse(ok)

    def test_new_hash_differs_from_old(self):
        import bcrypt
        users_before = _load_users()
        old_hash = users_before[self.uid]['password_hash']
        change_password(self.uid, 'Str0ng!Pass#99', 'NewPass!Word1@')
        users_after = _load_users()
        new_hash = users_after[self.uid]['password_hash']
        self.assertNotEqual(old_hash, new_hash)


# ══════════════════════════════════════════════════════════════════════════════
#  C. Rate Limiting
# ══════════════════════════════════════════════════════════════════════════════

class TestRateLimiting(BaseTest):

    def setUp(self):
        super().setUp()
        from auth import _rate_limit_store
        _rate_limit_store.clear()

    def test_first_10_attempts_allowed(self):
        for i in range(10):
            self.assertTrue(check_rate_limit('1.2.3.4'),
                            f'Attempt {i+1} should be allowed')

    def test_eleventh_attempt_blocked(self):
        for _ in range(10):
            check_rate_limit('9.9.9.9')
        self.assertFalse(check_rate_limit('9.9.9.9'))

    def test_separate_ips_tracked_independently(self):
        for _ in range(10):
            check_rate_limit('10.0.0.1')
        # Different IP should still have its full quota
        self.assertTrue(check_rate_limit('10.0.0.2'))

    def test_window_resets_after_time(self):
        """Simulate old timestamps expiring out of the window."""
        from auth import _rate_limit_store
        old_time = time.time() - Config.RATE_LIMIT_WINDOW - 1
        _rate_limit_store['5.5.5.5'] = [old_time] * 10
        # All timestamps are expired, so a new attempt should be allowed
        self.assertTrue(check_rate_limit('5.5.5.5'))


# ══════════════════════════════════════════════════════════════════════════════
#  D. Access Control (RBAC)
# ══════════════════════════════════════════════════════════════════════════════

class TestAccessControl(BaseTest):

    def _doc(self, owner='u1', shares=None):
        return {'owner_id': owner, 'shares': shares or {}}

    # ── can_read ──────────────────────────────────────────────────────────

    def test_owner_can_read_own_doc(self):
        self.assertTrue(can_read(self._doc('u1'), 'u1', 'user'))

    def test_stranger_cannot_read_unshared_doc(self):
        self.assertFalse(can_read(self._doc('u1'), 'u2', 'user'))

    def test_viewer_can_read_shared_doc(self):
        doc = self._doc('u1', shares={'u2': 'viewer'})
        self.assertTrue(can_read(doc, 'u2', 'user'))

    def test_editor_can_read_shared_doc(self):
        doc = self._doc('u1', shares={'u2': 'editor'})
        self.assertTrue(can_read(doc, 'u2', 'user'))

    def test_admin_can_read_any_doc(self):
        self.assertTrue(can_read(self._doc('u1'), 'admin_user', 'admin'))

    def test_guest_cannot_read_unshared_doc(self):
        self.assertFalse(can_read(self._doc('u1'), 'guest1', 'guest'))

    # ── can_write ─────────────────────────────────────────────────────────

    def test_owner_can_write_own_doc(self):
        self.assertTrue(can_write(self._doc('u1'), 'u1', 'user'))

    def test_viewer_cannot_write(self):
        doc = self._doc('u1', shares={'u2': 'viewer'})
        self.assertFalse(can_write(doc, 'u2', 'user'))

    def test_editor_can_write(self):
        doc = self._doc('u1', shares={'u2': 'editor'})
        self.assertTrue(can_write(doc, 'u2', 'user'))

    def test_stranger_cannot_write(self):
        self.assertFalse(can_write(self._doc('u1'), 'u2', 'user'))

    def test_admin_can_write_any_doc(self):
        self.assertTrue(can_write(self._doc('u1'), 'admin_user', 'admin'))

    # ── can_delete ────────────────────────────────────────────────────────

    def test_owner_can_delete_own_doc(self):
        self.assertTrue(can_delete(self._doc('u1'), 'u1', 'user'))

    def test_editor_cannot_delete(self):
        doc = self._doc('u1', shares={'u2': 'editor'})
        self.assertFalse(can_delete(doc, 'u2', 'user'))

    def test_viewer_cannot_delete(self):
        doc = self._doc('u1', shares={'u2': 'viewer'})
        self.assertFalse(can_delete(doc, 'u2', 'user'))

    def test_admin_can_delete_any_doc(self):
        self.assertTrue(can_delete(self._doc('u1'), 'admin_user', 'admin'))

    def test_stranger_cannot_delete(self):
        self.assertFalse(can_delete(self._doc('u1'), 'u2', 'user'))


# ══════════════════════════════════════════════════════════════════════════════
#  E. Path Traversal Prevention
# ══════════════════════════════════════════════════════════════════════════════

class TestPathTraversal(BaseTest):

    def test_dotdot_slash_rejected(self):
        with self.assertRaises(ValueError):
            safe_filename_check('../../../etc/passwd')

    def test_windows_traversal_rejected(self):
        with self.assertRaises(ValueError):
            safe_filename_check('..\\windows\\system32')

    def test_null_byte_rejected(self):
        with self.assertRaises(ValueError):
            safe_filename_check('file\x00.txt')

    def test_absolute_path_rejected(self):
        with self.assertRaises(ValueError):
            safe_filename_check('/etc/passwd')

    def test_normal_filename_accepted(self):
        result = safe_filename_check('report_2026.pdf')
        self.assertEqual(result, 'report_2026.pdf')

    def test_filename_with_dash_accepted(self):
        result = safe_filename_check('my-document.txt')
        self.assertEqual(result, 'my-document.txt')

    def test_hidden_traversal_rejected(self):
        with self.assertRaises(ValueError):
            safe_filename_check('....//etc/passwd')

    def test_encoded_slash_rejected(self):
        with self.assertRaises(ValueError):
            safe_filename_check('%2F%2E%2E%2Fetc%2Fpasswd')


# ══════════════════════════════════════════════════════════════════════════════
#  F. Session Management
# ══════════════════════════════════════════════════════════════════════════════

class TestSessionManagement(BaseTest):

    def setUp(self):
        super().setUp()
        self._tmp_sess = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        )
        self._tmp_sess.write('{}')
        self._tmp_sess.close()
        self.mgr = SessionManager(self._tmp_sess.name, timeout=5)

    def tearDown(self):
        super().tearDown()
        os.unlink(self._tmp_sess.name)

    def test_create_returns_token(self):
        token = self.mgr.create('user1', '127.0.0.1', 'TestBrowser')
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 20)

    def test_token_is_url_safe_random(self):
        tokens = {self.mgr.create('u1', '127.0.0.1', 'UA') for _ in range(10)}
        # All 10 tokens must be unique
        self.assertEqual(len(tokens), 10)

    def test_valid_token_resolves_to_session(self):
        token   = self.mgr.create('user1', '127.0.0.1', 'UA')
        session = self.mgr.validate(token)
        self.assertIsNotNone(session)
        self.assertEqual(session['user_id'], 'user1')

    def test_invalid_token_returns_none(self):
        self.assertIsNone(self.mgr.validate('fake-token-xyz'))

    def test_expired_session_rejected(self):
        token = self.mgr.create('user1', '127.0.0.1', 'UA')
        # Force expiry by setting last_activity in the past
        with open(self._tmp_sess.name, 'r') as f:
            import json
            sessions = json.load(f)
        sessions[token]['last_activity'] = time.time() - 999
        with open(self._tmp_sess.name, 'w') as f:
            json.dump(sessions, f)
        self.assertIsNone(self.mgr.validate(token))

    def test_destroy_removes_session(self):
        token = self.mgr.create('user1', '127.0.0.1', 'UA')
        self.mgr.destroy(token)
        self.assertIsNone(self.mgr.validate(token))

    def test_multiple_sessions_coexist(self):
        """Two concurrent sessions must not log each other out."""
        tok_a = self.mgr.create('userA', '127.0.0.1', 'UA')
        tok_b = self.mgr.create('userB', '127.0.0.2', 'UB')
        self.assertIsNotNone(self.mgr.validate(tok_a))
        self.assertIsNotNone(self.mgr.validate(tok_b))

    def test_destroy_all_for_user_removes_only_their_sessions(self):
        tok_a1 = self.mgr.create('userA', '127.0.0.1', 'UA')
        tok_a2 = self.mgr.create('userA', '127.0.0.1', 'UA')
        tok_b  = self.mgr.create('userB', '127.0.0.2', 'UB')
        self.mgr.destroy_all_for_user('userA')
        self.assertIsNone(self.mgr.validate(tok_a1))
        self.assertIsNone(self.mgr.validate(tok_a2))
        self.assertIsNotNone(self.mgr.validate(tok_b))

    def test_purge_expired_removes_only_old_sessions(self):
        tok_fresh = self.mgr.create('userA', '127.0.0.1', 'UA')
        tok_old   = self.mgr.create('userB', '127.0.0.2', 'UB')
        with open(self._tmp_sess.name, 'r') as f:
            import json
            sessions = json.load(f)
        sessions[tok_old]['last_activity'] = time.time() - 999
        with open(self._tmp_sess.name, 'w') as f:
            json.dump(sessions, f)
        removed = self.mgr.purge_expired()
        self.assertEqual(removed, 1)
        self.assertIsNotNone(self.mgr.validate(tok_fresh))


# ══════════════════════════════════════════════════════════════════════════════
#  G. Encryption
# ══════════════════════════════════════════════════════════════════════════════

class TestEncryption(BaseTest):

    def setUp(self):
        super().setUp()
        self._tmpdir = tempfile.mkdtemp()
        from storage import EncryptedStorage
        self.enc = EncryptedStorage(
            os.path.join(self._tmpdir, 'test.key')
        )

    def tearDown(self):
        super().tearDown()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_encrypted_file_differs_from_plaintext(self):
        data = {'secret': 'do not read'}
        path = os.path.join(self._tmpdir, 'data.enc')
        self.enc.save(path, data)
        with open(path, 'rb') as f:
            raw = f.read()
        self.assertNotIn(b'do not read', raw)
        self.assertNotIn(b'secret', raw)

    def test_round_trip_preserves_data(self):
        data = {'key': 'value', 'number': 42, 'nested': {'a': 1}}
        path = os.path.join(self._tmpdir, 'round.enc')
        self.enc.save(path, data)
        loaded = self.enc.load(path)
        self.assertEqual(loaded, data)

    def test_key_file_created_on_disk(self):
        key_path = os.path.join(self._tmpdir, 'test.key')
        self.assertTrue(os.path.exists(key_path))

    def test_key_file_permissions_are_owner_only(self):
        key_path = os.path.join(self._tmpdir, 'test.key')
        mode = oct(os.stat(key_path).st_mode)[-3:]
        self.assertEqual(mode, '600', 'Key file should be readable only by owner')

    def test_encrypted_file_binary_not_json(self):
        data = {'test': True}
        path = os.path.join(self._tmpdir, 'binary.enc')
        self.enc.save(path, data)
        with open(path, 'rb') as f:
            raw = f.read()
        # Should not be valid JSON
        try:
            json.loads(raw)
            self.fail('Encrypted file should not be valid JSON')
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    def test_load_missing_file_returns_default(self):
        result = self.enc.load('/nonexistent/path.enc', default='fallback')
        self.assertEqual(result, 'fallback')

    def test_different_key_cannot_decrypt(self):
        from cryptography.fernet import InvalidToken
        data = {'secret': 'hidden'}
        path = os.path.join(self._tmpdir, 'locked.enc')
        self.enc.save(path, data)

        # Create a second storage with a different key
        from storage import EncryptedStorage
        enc2 = EncryptedStorage(os.path.join(self._tmpdir, 'other.key'))
        with self.assertRaises(Exception):
            enc2.load(path)


# ══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("=" * 60)
    print("  CS 419 — Security Test Suite")
    print("=" * 60)
    loader  = unittest.TestLoader()
    suite   = unittest.TestLoader().loadTestsFromModule(
        sys.modules[__name__]
    )
    runner  = unittest.TextTestRunner(verbosity=2)
    result  = runner.run(suite)
    print("\n" + "=" * 60)
    total  = result.testsRun
    passed = total - len(result.failures) - len(result.errors)
    print(f"  Results: {passed}/{total} passed", end="")
    if result.failures or result.errors:
        print(f"  |  {len(result.failures)} failed  {len(result.errors)} errors")
    else:
        print("  ✓  All tests passed!")
    print("=" * 60)
    sys.exit(0 if result.wasSuccessful() else 1)
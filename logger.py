"""
logger.py - Security Event Logger
Logs all security-relevant events to logs/security.log in structured JSON.
"""

import logging
import json
import os
from datetime import datetime, timezone


class SecurityLogger:
    def __init__(self, log_file: str = 'logs/security.log'):
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.DEBUG)

        # Avoid adding duplicate handlers on reload
        if not self.logger.handlers:
            handler = logging.FileHandler(log_file)
            handler.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(handler)

    def log_event(
        self,
        event_type: str,
        user_id,
        details: dict,
        severity: str = 'INFO',
        ip_address: str = None,
        user_agent: str = None,
    ):
        """Write a structured JSON log entry."""
        entry = {
            'timestamp':  datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'severity':   severity,
            'user_id':    user_id,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'details':    details,
        }
        line = json.dumps(entry)

        level_map = {
            'CRITICAL': self.logger.critical,
            'ERROR':    self.logger.error,
            'WARNING':  self.logger.warning,
            'INFO':     self.logger.info,
            'DEBUG':    self.logger.debug,
        }
        level_map.get(severity, self.logger.info)(line)

    # ── Convenience methods ────────────────────────────────────────────────

    def login_success(self, user_id, username, ip, ua):
        self.log_event('LOGIN_SUCCESS', user_id,
                       {'username': username}, ip_address=ip, user_agent=ua)

    def login_failed(self, username, reason, ip, ua):
        self.log_event('LOGIN_FAILED', None,
                       {'username': username, 'reason': reason},
                       severity='WARNING', ip_address=ip, user_agent=ua)

    def account_locked(self, user_id, username, ip):
        self.log_event('ACCOUNT_LOCKED', user_id,
                       {'username': username, 'reason': f'{5} failed attempts'},
                       severity='ERROR', ip_address=ip)

    def logout(self, user_id, ip):
        self.log_event('LOGOUT', user_id, {}, ip_address=ip)

    def registration(self, username, ip):
        self.log_event('REGISTRATION', None,
                       {'username': username}, ip_address=ip)

    def access_denied(self, user_id, resource, reason, ip):
        self.log_event('ACCESS_DENIED', user_id,
                       {'resource': resource, 'reason': reason},
                       severity='WARNING', ip_address=ip)

    def data_access(self, user_id, resource, action, ip):
        self.log_event('DATA_ACCESS', user_id,
                       {'resource': resource, 'action': action},
                       ip_address=ip)

    def session_created(self, user_id, ip):
        self.log_event('SESSION_CREATED', user_id, {}, ip_address=ip)

    def session_expired(self, user_id, ip):
        self.log_event('SESSION_EXPIRED', user_id, {},
                       severity='INFO', ip_address=ip)

    def input_validation_failure(self, field, ip):
        self.log_event('INPUT_VALIDATION_FAILED', None,
                       {'field': field},
                       severity='WARNING', ip_address=ip)

    def rate_limit_exceeded(self, ip):
        self.log_event('RATE_LIMIT_EXCEEDED', None,
                       {'ip': ip}, severity='WARNING', ip_address=ip)

    def suspicious_activity(self, detail, ip):
        self.log_event('SUSPICIOUS_ACTIVITY', None,
                       {'detail': detail}, severity='CRITICAL', ip_address=ip)

    def password_changed(self, user_id, ip):
        self.log_event('PASSWORD_CHANGED', user_id, {}, ip_address=ip)

    def document_shared(self, owner_id, doc_id, target_user, ip):
        self.log_event('DOCUMENT_SHARED', owner_id,
                       {'doc_id': doc_id, 'shared_with': target_user},
                       ip_address=ip)

    def document_deleted(self, user_id, doc_id, ip):
        self.log_event('DOCUMENT_DELETED', user_id,
                       {'doc_id': doc_id}, ip_address=ip)


# Module-level singleton — import this everywhere
security_log = SecurityLogger()

"""
documents.py - Document Management

Handles:
  - Encrypted document upload / download
  - Per-document roles: owner / editor / viewer
  - Sharing with specific users
  - Version history (audit trail)
"""

import os
import re
import time
import uuid

from werkzeug.utils import secure_filename

from config import Config
from storage import EncryptedStorage, _read_json, _write_json

_enc = EncryptedStorage(Config.KEY_FILE)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_docs() -> list:
    return _read_json(Config.DOCUMENTS_FILE, default=[])


def _save_docs(docs: list) -> None:
    _write_json(Config.DOCUMENTS_FILE, docs)


def allowed_extension(filename: str) -> bool:
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    return ext in Config.ALLOWED_EXTENSIONS


def safe_filename_check(filename: str) -> str:
    """
    Sanitize filename — REJECT first, then sanitize:
      1. Reject null bytes (C-string termination attack).
      2. Reject path traversal sequences BEFORE secure_filename can hide them.
      3. werkzeug secure_filename normalises the result.
      4. Whitelist: only alphanumeric, dash, underscore, dot.
      5. Reject empty result (e.g. purely non-ASCII input).
    """
    # 1. Null byte check
    if '\x00' in filename:
        raise ValueError('Invalid filename: null byte detected.')

    # 2. Path traversal — check raw input before any normalization
    raw = filename.replace('\\', '/')
    if '..' in raw.split('/') or raw.startswith('/'):
        raise ValueError('Invalid filename: path traversal detected.')

    # 3. Normalize via werkzeug
    filename = secure_filename(filename)

    # 4. Whitelist characters
    if not filename or not re.match(r'^[\w\-\.]+$', filename):
        raise ValueError('Invalid filename: disallowed characters.')

    return filename


def get_doc_by_id(doc_id: str) -> dict | None:
    docs = _load_docs()
    return next((d for d in docs if d['id'] == doc_id), None)


# ── Access control ────────────────────────────────────────────────────────────

def can_read(doc: dict, user_id: str, user_role: str) -> bool:
    if user_role == 'admin':
        return True
    if doc['owner_id'] == user_id:
        return True
    share = doc.get('shares', {}).get(user_id)
    return share in ('viewer', 'editor')


def can_write(doc: dict, user_id: str, user_role: str) -> bool:
    if user_role == 'admin':
        return True
    if doc['owner_id'] == user_id:
        return True
    return doc.get('shares', {}).get(user_id) == 'editor'


def can_delete(doc: dict, user_id: str, user_role: str) -> bool:
    if user_role == 'admin':
        return True
    return doc['owner_id'] == user_id


# ── Upload ────────────────────────────────────────────────────────────────────

def upload_document(file_storage, uploader_id: str, description: str = '') -> tuple[bool, str, dict | None]:
    """
    Accept a Werkzeug FileStorage object, validate, encrypt, persist.
    Returns (success, message, doc_dict).
    """
    if not file_storage or file_storage.filename == '':
        return False, 'No file selected.', None

    try:
        filename = safe_filename_check(file_storage.filename)
    except ValueError as e:
        return False, str(e), None

    if not allowed_extension(filename):
        return False, f'File type not allowed. Permitted: {", ".join(Config.ALLOWED_EXTENSIONS)}', None

    doc_id   = str(uuid.uuid4())
    version  = 1
    enc_name = f'{doc_id}_v{version}.enc'
    enc_path = os.path.join(Config.UPLOAD_DIR, enc_name)

    os.makedirs(Config.UPLOAD_DIR, exist_ok=True)

    # Save raw upload to a temp location, then encrypt
    tmp_path = enc_path + '.tmp'
    try:
        file_storage.save(tmp_path)
        _enc.encrypt_file(tmp_path, enc_path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    doc = {
        'id':          doc_id,
        'owner_id':    uploader_id,
        'original_name': filename,
        'description': description[:500],     # length limit
        'uploaded_at': time.time(),
        'shares':      {},                    # { user_id: 'viewer'|'editor' }
        'versions': [
            {
                'version':     version,
                'enc_file':    enc_name,
                'uploaded_at': time.time(),
                'uploaded_by': uploader_id,
            }
        ],
    }

    docs = _load_docs()
    docs.append(doc)
    _save_docs(docs)
    return True, 'Document uploaded successfully.', doc


# ── Download ──────────────────────────────────────────────────────────────────

def download_document(doc_id: str, user_id: str, user_role: str) -> tuple[bytes | None, str]:
    """Return (decrypted_bytes, original_filename) or (None, error_message)."""
    doc = get_doc_by_id(doc_id)
    if not doc:
        return None, 'Document not found.'
    if not can_read(doc, user_id, user_role):
        return None, 'Access denied.'

    # Latest version
    latest  = doc['versions'][-1]
    enc_path = os.path.join(Config.UPLOAD_DIR, latest['enc_file'])
    if not os.path.exists(enc_path):
        return None, 'File not found on disk.'

    # Path traversal guard
    abs_path = os.path.abspath(enc_path)
    if not abs_path.startswith(os.path.abspath(Config.UPLOAD_DIR)):
        return None, 'Access denied.'

    data = _enc.decrypt_file(enc_path)
    return data, doc['original_name']


# ── Sharing ───────────────────────────────────────────────────────────────────

def share_document(doc_id: str, owner_id: str, owner_role: str,
                   target_user_id: str, permission: str) -> tuple[bool, str]:
    """Grant `target_user_id` read (viewer) or write (editor) access."""
    if permission not in ('viewer', 'editor'):
        return False, 'Permission must be "viewer" or "editor".'

    docs = _load_docs()
    for i, doc in enumerate(docs):
        if doc['id'] == doc_id:
            if not can_write(doc, owner_id, owner_role):
                return False, 'You do not have permission to share this document.'
            docs[i]['shares'][target_user_id] = permission
            _save_docs(docs)
            return True, f'Access granted ({permission}).'
    return False, 'Document not found.'


def revoke_share(doc_id: str, owner_id: str, owner_role: str,
                 target_user_id: str) -> tuple[bool, str]:
    docs = _load_docs()
    for i, doc in enumerate(docs):
        if doc['id'] == doc_id:
            if not can_write(doc, owner_id, owner_role):
                return False, 'Permission denied.'
            docs[i]['shares'].pop(target_user_id, None)
            _save_docs(docs)
            return True, 'Access revoked.'
    return False, 'Document not found.'


# ── Delete ────────────────────────────────────────────────────────────────────

def delete_document(doc_id: str, user_id: str, user_role: str) -> tuple[bool, str]:
    docs = _load_docs()
    for i, doc in enumerate(docs):
        if doc['id'] == doc_id:
            if not can_delete(doc, user_id, user_role):
                return False, 'Only the document owner or admin can delete.'
            # Delete all encrypted files
            for v in doc['versions']:
                fp = os.path.join(Config.UPLOAD_DIR, v['enc_file'])
                if os.path.exists(fp):
                    os.remove(fp)
            docs.pop(i)
            _save_docs(docs)
            return True, 'Document deleted.'
    return False, 'Document not found.'


# ── Listing ───────────────────────────────────────────────────────────────────

def list_documents_for_user(user_id: str, user_role: str) -> list:
    """Return all docs visible to this user (owned + shared + all if admin)."""
    docs = _load_docs()
    if user_role == 'admin':
        return docs
    return [d for d in docs if can_read(d, user_id, user_role)]

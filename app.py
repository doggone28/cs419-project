"""
app.py - Secure Document Sharing System
CS 419 Course Project — Spring 2026

Run (development):
    python app.py

Run (with TLS):
    python app.py --tls
"""

import os
import sys

from flask import (Flask, abort, flash, g, make_response, redirect,
                   render_template, request, send_file, url_for)
from werkzeug.exceptions import HTTPException

from auth import (authenticate_user, change_password, check_rate_limit,
                  get_user_by_id, register_user, require_auth, require_role,
                  sanitize, _load_users, _save_users)
from config import Config
from documents import (delete_document, download_document, list_documents_for_user,
                       share_document, upload_document, get_doc_by_id, revoke_share)
from logger import security_log
from storage import SessionManager

# ── App setup ──────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config.from_object(Config)
app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH

session_mgr = SessionManager(Config.SESSIONS_FILE, Config.SESSION_TIMEOUT)

os.makedirs(Config.DATA_DIR,   exist_ok=True)
os.makedirs(Config.LOGS_DIR,   exist_ok=True)
os.makedirs(Config.UPLOAD_DIR, exist_ok=True)


# ── Request lifecycle ──────────────────────────────────────────────────────────

@app.before_request
def load_session():
    """Resolve session token → user object and attach to Flask `g`."""
    token = request.cookies.get('session_token')
    session = session_mgr.validate(token) if token else None
    if session:
        g.user   = get_user_by_id(session['user_id'])
        g.token  = token
    else:
        g.user  = None
        g.token = None


@app.before_request
def force_https():
    """Redirect HTTP → HTTPS in production."""
    if not Config.DEBUG and not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)


# ── Security headers ───────────────────────────────────────────────────────────

@app.after_request
def set_security_headers(response):
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers['X-Frame-Options']           = 'DENY'
    response.headers['X-Content-Type-Options']     = 'nosniff'
    response.headers['X-XSS-Protection']          = '1; mode=block'
    response.headers['Referrer-Policy']           = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy']        = 'geolocation=(), microphone=(), camera=()'
    if not Config.DEBUG:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


# ── Error handlers ─────────────────────────────────────────────────────────────
# Generic messages — never expose stack traces or internal details

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403,
                           message='You do not have permission to access this resource.'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404,
                           message='Page not found.'), 404


@app.errorhandler(413)
def too_large(e):
    return render_template('error.html', code=413,
                           message='File too large. Maximum size is 16 MB.'), 413


@app.errorhandler(500)
def server_error(e):
    # Log detailed error server-side; show nothing to user
    app.logger.error('500 error: %s', e)
    return render_template('error.html', code=500,
                           message='An unexpected error occurred.'), 500


# ── Public routes ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if g.user:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


# ── Auth routes ────────────────────────────────────────────────────────────────

@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.user:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '')
        email    = request.form.get('email', '')
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        # Input length guard (prevent huge payloads)
        if any(len(v) > 256 for v in [username, email, password, confirm]):
            security_log.input_validation_failure('oversized_input', request.remote_addr)
            flash('Input too long.', 'danger')
            return render_template('register.html')

        ok, msg = register_user(username, email, password, confirm)
        if ok:
            security_log.registration(username, request.remote_addr)
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            security_log.input_validation_failure('registration', request.remote_addr)
            flash(msg, 'danger')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        ip       = request.remote_addr
        ua       = request.headers.get('User-Agent', '')
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Rate limit check
        if not check_rate_limit(ip):
            security_log.rate_limit_exceeded(ip)
            flash('Too many login attempts. Please wait a minute.', 'danger')
            return render_template('login.html')

        user, reason = authenticate_user(username, password)
        if user:
            token = session_mgr.create(user['id'], ip, ua)
            security_log.login_success(user['id'], username, ip, ua)
            security_log.session_created(user['id'], ip)

            response = make_response(redirect(url_for('dashboard')))
            response.set_cookie(
                'session_token',
                token,
                httponly=True,          # JS cannot read
                secure=not Config.DEBUG, # HTTPS only in prod
                samesite='Strict',      # CSRF mitigation
                max_age=Config.SESSION_TIMEOUT,
            )
            return response
        else:
            security_log.login_failed(username, reason, ip, ua)
            flash(reason, 'danger')

    return render_template('login.html')


@app.route('/logout')
@require_auth
def logout():
    security_log.logout(g.user['id'], request.remote_addr)
    session_mgr.destroy(g.token)
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('session_token')
    flash('You have been logged out.', 'info')
    return response


# ── Dashboard ──────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@require_auth
def dashboard():
    docs = list_documents_for_user(g.user['id'], g.user['role'])
    return render_template('dashboard.html', user=g.user, docs=docs)


# ── Document routes ────────────────────────────────────────────────────────────

@app.route('/upload', methods=['GET', 'POST'])
@require_auth
def upload():
    # Guests cannot upload
    if g.user['role'] == 'guest':
        security_log.access_denied(g.user['id'], '/upload', 'guest role', request.remote_addr)
        abort(403)

    if request.method == 'POST':
        file        = request.files.get('document')
        description = sanitize(request.form.get('description', ''))

        ok, msg, doc = upload_document(file, g.user['id'], description)
        if ok:
            security_log.data_access(g.user['id'], doc['original_name'], 'upload', request.remote_addr)
            flash(msg, 'success')
            return redirect(url_for('dashboard'))
        else:
            security_log.input_validation_failure('file_upload', request.remote_addr)
            flash(msg, 'danger')

    return render_template('upload.html', user=g.user)


@app.route('/document/<doc_id>/download')
@require_auth
def download(doc_id):
    import io
    data, name_or_err = download_document(doc_id, g.user['id'], g.user['role'])
    if data is None:
        if name_or_err == 'Access denied.':
            security_log.access_denied(g.user['id'], f'doc/{doc_id}', 'permission', request.remote_addr)
            abort(403)
        abort(404)

    security_log.data_access(g.user['id'], doc_id, 'download', request.remote_addr)
    return send_file(
        io.BytesIO(data),
        download_name=name_or_err,
        as_attachment=True,
    )


@app.route('/document/<doc_id>/share', methods=['GET', 'POST'])
@require_auth
def share(doc_id):
    doc = get_doc_by_id(doc_id)
    if not doc:
        abort(404)

    # Only owner or admin can manage shares
    if doc['owner_id'] != g.user['id'] and g.user['role'] != 'admin':
        security_log.access_denied(g.user['id'], f'doc/{doc_id}/share', 'not owner', request.remote_addr)
        abort(403)

    all_users = _load_users()

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'share':
            target_id  = sanitize(request.form.get('target_user_id', ''))
            permission = sanitize(request.form.get('permission', ''))
            ok, msg = share_document(doc_id, g.user['id'], g.user['role'], target_id, permission)
            if ok:
                security_log.document_shared(g.user['id'], doc_id, target_id, request.remote_addr)
            flash(msg, 'success' if ok else 'danger')

        elif action == 'revoke':
            target_id = sanitize(request.form.get('target_user_id', ''))
            ok, msg = revoke_share(doc_id, g.user['id'], g.user['role'], target_id)
            flash(msg, 'success' if ok else 'danger')

        return redirect(url_for('share', doc_id=doc_id))

    # Refresh doc after possible update
    doc = get_doc_by_id(doc_id)
    shareable_users = {uid: u for uid, u in all_users.items()
                       if uid != g.user['id'] and uid != doc['owner_id']}
    return render_template('share.html', user=g.user, doc=doc,
                           all_users=shareable_users)


@app.route('/document/<doc_id>/delete', methods=['POST'])
@require_auth
def delete_doc(doc_id):
    ok, msg = delete_document(doc_id, g.user['id'], g.user['role'])
    if ok:
        security_log.document_deleted(g.user['id'], doc_id, request.remote_addr)
        flash(msg, 'success')
    else:
        flash(msg, 'danger')
    return redirect(url_for('dashboard'))


# ── Profile / password change ──────────────────────────────────────────────────

@app.route('/profile', methods=['GET', 'POST'])
@require_auth
def profile():
    if request.method == 'POST':
        old_pw  = request.form.get('old_password', '')
        new_pw  = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')

        if new_pw != confirm:
            flash('New passwords do not match.', 'danger')
        else:
            ok, msg = change_password(g.user['id'], old_pw, new_pw)
            if ok:
                security_log.password_changed(g.user['id'], request.remote_addr)
                # Invalidate all sessions for security
                session_mgr.destroy_all_for_user(g.user['id'])
                flash('Password changed. Please log in again.', 'success')
                return redirect(url_for('login'))
            flash(msg, 'danger')

    return render_template('profile.html', user=g.user)


# ── Admin routes ───────────────────────────────────────────────────────────────

@app.route('/admin')
@require_auth
@require_role('admin')
def admin_dashboard():
    users = _load_users()
    docs  = list_documents_for_user(g.user['id'], 'admin')
    security_log.data_access(g.user['id'], '/admin', 'view', request.remote_addr)
    return render_template('admin.html', user=g.user, users=users, docs=docs)


@app.route('/admin/users/<target_id>/role', methods=['POST'])
@require_auth
@require_role('admin')
def admin_change_role(target_id):
    new_role = request.form.get('role', '')
    if new_role not in ('admin', 'user', 'guest'):
        flash('Invalid role.', 'danger')
        return redirect(url_for('admin_dashboard'))

    users = _load_users()
    if target_id not in users:
        abort(404)
    users[target_id]['role'] = new_role
    _save_users(users)
    security_log.log_event('ROLE_CHANGED', g.user['id'],
                           {'target': target_id, 'new_role': new_role},
                           ip_address=request.remote_addr)
    flash(f'Role updated to {new_role}.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/users/<target_id>/unlock', methods=['POST'])
@require_auth
@require_role('admin')
def admin_unlock(target_id):
    users = _load_users()
    if target_id not in users:
        abort(404)
    users[target_id]['failed_attempts'] = 0
    users[target_id]['locked_until']    = None
    _save_users(users)
    flash('Account unlocked.', 'success')
    return redirect(url_for('admin_dashboard'))


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    use_tls = '--tls' in sys.argv
    ssl_ctx = (Config.TLS_CERT, Config.TLS_KEY) if use_tls else None
    app.run(
        host='0.0.0.0',
        port=5000,
        ssl_context=ssl_ctx,
        debug=Config.DEBUG,
    )

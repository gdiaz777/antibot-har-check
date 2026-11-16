"""
Anti-Bot lab — a small web application to test the CloudGuard WAF Anti-Bot
Injected/Validated URIs with antibot_check.py.

Login flows:
  Classic form   GET /login     -> POST /login        -> 302 /home
  SPA (fetch)    GET /spa/      -> POST /api/login    (JSON)
  Registration   GET /register  -> POST /register     -> 302 /login

Credentials come from the environment: LAB_USER, LAB_PASSWORD, LAB_SECRET.
"""

import hmac
import os
import secrets

from flask import (Flask, abort, jsonify, redirect, render_template_string,
                   request, session, url_for)

app = Flask(__name__)
app.secret_key = os.environ.get('LAB_SECRET') or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')

USERS = {os.environ.get('LAB_USER', 'demo'): os.environ['LAB_PASSWORD']}

LAYOUT = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} · Anti-Bot Lab</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:420px;margin:60px auto;
      padding:0 16px;color:#1d2330;background:#f5f6f8}
 .card{background:#fff;border-radius:8px;padding:24px;
       box-shadow:0 1px 3px rgba(0,0,0,.12)}
 label{display:block;margin-top:12px;font-size:14px}
 input{width:100%;box-sizing:border-box;padding:8px;margin-top:4px;
       border:1px solid #c5cad3;border-radius:4px}
 button{margin-top:18px;width:100%;padding:10px;border:0;border-radius:4px;
        background:#e5007e;color:#fff;font-weight:600;cursor:pointer}
 .err{color:#b00020}.ok{color:#0a7a32}
 nav{margin-top:16px;font-size:14px}
</style></head><body><div class="card">
<h1>{{ title }}</h1>
{% if error %}<p class="err">{{ error }}</p>{% endif %}
{% if message %}<p class="ok">{{ message }}</p>{% endif %}
{{ body|safe }}
</div>
<nav><a href="/login">Login (form)</a> · <a href="/spa/">Login (SPA)</a> ·
<a href="/register">Register</a></nav>
</body></html>'''


# Response variants of GET /login, to find what stops the WAF from injecting
# the Anti-Bot sensor. Space-separated flags in this file, read per request:
#   chunked    no Content-Length (streamed body)
#   nocharset  Content-Type: text/html without charset
#   minimal    bare <html><head></head><body> page
#   nocookie   no Set-Cookie header
VARIANT_FILE = '/etc/antibot-lab/variant'


def variant():
    try:
        with open(VARIANT_FILE) as f:
            return set(f.read().split())
    except OSError:
        return set()


@app.after_request
def apply_variant(resp):
    flags = variant()
    if not flags or request.method != 'GET' or request.path != '/login':
        return resp
    if 'minimal' in flags:
        resp.set_data('<html><head><title>Sign in</title></head><body>'
                      '<form method="post" action="/login">'
                      '<input name="username"><input type="password" '
                      'name="password"><button>Sign in</button></form>'
                      '</body></html>')
    if 'nocharset' in flags:
        resp.headers['Content-Type'] = 'text/html'
    if 'nocookie' in flags:
        # The session cookie is written after this hook: skip it
        session.modified = False
    if 'chunked' in flags:
        data = resp.get_data()
        resp.response = iter([data])
        resp.headers.pop('Content-Length', None)
    return resp


def page(title, body, **kw):
    return render_template_string(LAYOUT, title=title, body=body, **kw)


def csrf_token():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_urlsafe(24)
    return session['csrf']


def check_csrf():
    sent, expected = request.form.get('csrf_token', ''), session.get('csrf')
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, 'invalid CSRF token')


def valid(user, password):
    expected = USERS.get(user)
    return expected is not None and hmac.compare_digest(password, expected)


@app.get('/')
def index():
    return redirect(url_for('home' if 'user' in session else 'login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        check_csrf()
        user = request.form.get('username', '')
        if valid(user, request.form.get('password', '')):
            session.clear()
            session['user'] = user
            return redirect(url_for('home'))
        error = 'Invalid username or password'
    form = f'''<form method="post" action="/login">
<input type="hidden" name="csrf_token" value="{csrf_token()}">
<label>Username<input name="username" autocomplete="username" required></label>
<label>Password<input type="password" name="password"
 autocomplete="current-password" required></label>
<button type="submit">Sign in</button></form>'''
    return page('Sign in', form, error=error), 401 if error else 200


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        check_csrf()
        user = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not user or len(password) < 8 or user in USERS:
            error = 'Choose another username and a password of 8+ characters'
        elif password != request.form.get('confirm_password'):
            error = 'Passwords do not match'
        else:
            USERS[user] = password
            return redirect(url_for('login'))
        return page('Register', _register_form(), error=error), 400
    return page('Register', _register_form())


def _register_form():
    return f'''<form method="post" action="/register">
<input type="hidden" name="csrf_token" value="{csrf_token()}">
<label>Username<input name="username" required></label>
<label>Email<input type="email" name="email" required></label>
<label>Password<input type="password" name="password" required></label>
<label>Confirm password<input type="password" name="confirm_password"
 required></label>
<button type="submit">Create account</button></form>'''


@app.get('/home')
def home():
    if 'user' not in session:
        return redirect(url_for('login'))
    return page('Welcome', f'<p>Signed in as <b>{session["user"]}</b>.</p>'
                           '<p><a href="/logout">Sign out</a></p>')


@app.get('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


SPA = '''<div id="app"><form id="f">
<label>Username<input id="u" autocomplete="username" required></label>
<label>Password<input id="p" type="password" autocomplete="current-password"
 required></label>
<button type="submit">Sign in</button></form><p id="out"></p></div>
<script>
document.getElementById('f').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  history.pushState({}, '', '/spa/login');
  const r = await fetch('/api/login', {method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: document.getElementById('u').value,
                          password: document.getElementById('p').value})});
  const data = await r.json();
  const out = document.getElementById('out');
  out.className = r.ok ? 'ok' : 'err';
  out.textContent = r.ok ? 'Signed in as ' + data.user : data.error;
});
</script>'''


@app.get('/spa/')
@app.get('/spa/login')
def spa():
    return page('Sign in (SPA)', SPA)


@app.post('/api/login')
def api_login():
    data = request.get_json(silent=True) or {}
    user = str(data.get('username', ''))
    if valid(user, str(data.get('password', ''))):
        session.clear()
        session['user'] = user
        return jsonify(ok=True, user=user)
    return jsonify(ok=False, error='Invalid username or password'), 401


@app.get('/healthz')
def healthz():
    return 'ok'

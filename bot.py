#!/usr/bin/env python3
# bot.py - Keneviz minimal, secure server (Cloudflare + uptime token)
import os
import time
import sqlite3
import secrets
import re
from functools import wraps
from flask import Flask, render_template, render_template_string, request, session, redirect, url_for, jsonify, make_response, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach
import hashlib

# ---------------- Config ----------------
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = False   # production: True (HTTPS)
    CF_REQUIRED = os.environ.get('CF_REQUIRED', 'True').lower() in ('1','true','yes')
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT') or '15 per minute'
    DB_PATH = os.environ.get('DB_PATH') or 'keneviz.db'
    # UPTIME_TOKEN: environment override OR built-in token you gave
    UPTIME_TOKEN = os.environ.get('UPTIME_TOKEN') or "gPWNMXgR0BCIz8ozdGk5-AZUSVH7CJJ2E3fe7DbHgkQ"
    JOB_ALLOWLIST_IPS = [ip.strip() for ip in (os.environ.get('JOB_ALLOWLIST_IPS') or '').split(',') if ip.strip()]

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']

# ---------------- Rate limiter ----------------
limiter = Limiter(key_func=get_remote_address, default_limits=[app.config['RATELIMIT_DEFAULT']])
limiter.init_app(app)

# ---------------- DB / Audit ----------------
def get_db_conn():
    conn = sqlite3.connect(app.config['DB_PATH'], check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, ip TEXT, path TEXT, method TEXT, ts INTEGER, note TEXT)''')
    conn.commit()
    conn.close()

init_db()

def audit(ip, path, method, note=''):
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute('INSERT INTO audit (ip, path, method, ts, note) VALUES (?, ?, ?, ?, ?)', (ip, path, method, int(time.time()), note))
        conn.commit()
        conn.close()
    except Exception:
        pass

# ---------------- Helpers ----------------
USERNAME_RE = re.compile(r'^[A-Za-z0-9._-]{3,30}$')

def sanitize_input(v, max_len=1000):
    if v is None:
        return ''
    if not isinstance(v, str):
        v = str(v)
    v = v.strip()
    if len(v) > max_len:
        v = v[:max_len]
    return bleach.clean(v, strip=True)

def simple_hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

# ---------------- Basic DDoS blacklist ----------------
req_times = {}    # ip -> [timestamps]
blacklist = {}    # ip -> expiry
MAX_WINDOW = 60
MAX_PER_WINDOW = 300
BLACKLIST_SECONDS = 300

def record_req(ip):
    now = time.time()
    arr = req_times.get(ip, [])
    arr = [t for t in arr if now - t < MAX_WINDOW]
    arr.append(now)
    req_times[ip] = arr
    if len(arr) > MAX_PER_WINDOW:
        blacklist[ip] = now + BLACKLIST_SECONDS

def is_blacklisted(ip):
    exp = blacklist.get(ip)
    if exp and time.time() < exp:
        return True
    if exp and time.time() >= exp:
        del blacklist[ip]
    return False

# ---------------- Secure headers ----------------
@app.after_request
def set_secure_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    return resp

# ---------------- Request checks ----------------
@app.before_request
def before_any():
    ip = request.headers.get('CF-Connecting-IP') or request.remote_addr

    # temp blacklist
    if is_blacklisted(ip):
        return make_response('Too many requests (temporary block).', 429)
    record_req(ip)

    # healthz logic: allow if token matches OR IP in allowlist
    if request.path == '/healthz':
        token = request.headers.get('X-UPTIME-TOKEN') or request.args.get('token')
        if app.config['UPTIME_TOKEN'] and token and secrets.compare_digest(token, app.config['UPTIME_TOKEN']):
            audit(ip, request.path, request.method, 'health_ok_token')
            return None
        if ip in app.config['JOB_ALLOWLIST_IPS']:
            audit(ip, request.path, request.method, 'health_ok_ip')
            return None
        # if CF required but no token/allow -> block health check
        if app.config['CF_REQUIRED'] and 'CF-Connecting-IP' not in request.headers:
            return make_response('Health check blocked: missing CF header or token.', 403)
        return None

    # For all other paths require Cloudflare header when configured (allow localhost)
    if app.config['CF_REQUIRED']:
        if 'CF-Connecting-IP' not in request.headers and request.remote_addr not in ('127.0.0.1','::1'):
            return make_response('Access denied: Cloudflare required.', 403)

    # audit normal requests
    audit(ip, request.path, request.method, 'request')

# ---------------- Routes ----------------
@app.route('/')
@limiter.limit('60 per minute')
def index():
    try:
        return render_template('index.html')
    except Exception:
        return '<h2>Keneviz - index not found</h2>', 200

# Example API endpoint (sanitized, parameterized usage if using DB)
@app.route('/api/<name>', methods=['GET','POST'])
@limiter.limit('30 per minute')
def api_proxy(name):
    # sanitize name and params
    name = sanitize_input(name, 100)
    params = request.args.to_dict() if request.method == 'GET' else request.form.to_dict()
    params = {k: sanitize_input(v) for k,v in params.items()}
    # example: just return sanitized info (replace with real logic)
    return jsonify({'api': name, 'params': params})

@app.route('/healthz', methods=['GET'])
@limiter.exempt
def healthz():
    return jsonify({'status':'ok','ts':int(time.time())})

@app.route('/s/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

# ---------------- Run ----------------
if __name__ == '__main__':
    if os.environ.get('FLASK_ENV') == 'production':
        app.config['SESSION_COOKIE_SECURE'] = True
    print('Starting keneviz bot... CF_REQUIRED=', app.config['CF_REQUIRED'])
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',5000)), debug=False)

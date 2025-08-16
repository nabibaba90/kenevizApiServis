#!/usr/bin/env python3
# bot.py - Keneviz minimal, secure server (Cloudflare + uptime token)
import os
import time
import sqlite3
import secrets
import re
from functools import wraps
from flask import Flask, render_template, render_template_string, request, session, redirect, url_for, jsonify, make_response, send_from_directory, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach
import hashlib
import hmac
import base64
import threading

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

    # Keneviz captcha config
    KENEVIZ_CHALLENGE_TTL = int(os.environ.get('KENEVIZ_CHALLENGE_TTL') or 120)  # seconds for challenge validity
    KENEVIZ_VC_TTL = int(os.environ.get('KENEVIZ_VC_TTL') or 3600)               # verification token validity
    KENEVIZ_SECRET = os.environ.get('KENEVIZ_SECRET') or (secrets.token_urlsafe(32))  # used for HMAC signatures

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

def _hmac_sign(msg: str) -> str:
    key = app.config['KENEVIZ_SECRET'].encode()
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()

def _now_ts() -> int:
    return int(time.time())

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

# ---------------- Keneviz in-memory stores ----------------
_keneviz_challenges = {}   # challenge_id -> {sig, ip, ts, used}
_keneviz_verifications = {} # vc_token -> {challenge_id, ip, ts, used}

_keneviz_lock = threading.Lock()

def _cleanup_keneviz_stores():
    """Remove expired items periodically."""
    with _keneviz_lock:
        now = _now_ts()
        ch_ttl = app.config['KENEVIZ_CHALLENGE_TTL']
        vc_ttl = app.config['KENEVIZ_VC_TTL']
        for cid in list(_keneviz_challenges.keys()):
            if now - _keneviz_challenges[cid]['ts'] > ch_ttl:
                del _keneviz_challenges[cid]
        for tok in list(_keneviz_verifications.keys()):
            if now - _keneviz_verifications[tok]['ts'] > vc_ttl:
                del _keneviz_verifications[tok]

def _start_cleanup_thread():
    def run():
        while True:
            time.sleep(60)
            try:
                _cleanup_keneviz_stores()
            except Exception:
                pass
    t = threading.Thread(target=run, daemon=True)
    t.start()

_start_cleanup_thread()

# ---------------- Secure headers ----------------
@app.after_request
def set_secure_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:;"
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

# ---------------- Keneviz widget & verification API ----------------

def _get_client_ip():
    return request.headers.get('CF-Connecting-IP') or request.remote_addr

@app.route('/keneviz_widget.js')
def keneviz_widget_js():
    """
    Serve a tiny JS widget that builds a "Keneviz: I'm not a robot" single-click button.
    It:
      - renders a button in #keneviz-widget
      - on click: fetch /keneviz_challenge, then /keneviz_verify
      - on success: dispatches window event 'keneviz-verified' with {token: ...}
      - sets hidden input #keneviz_token if present in DOM
    """
    js = r"""
(function(){
  function createButton(container){
    var div = document.getElementById(container);
    if(!div) return;
    div.innerHTML = '';
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.id = 'keneviz_btn';
    btn.innerText = '✔ Ben robot değilim (Keneviz)';
    btn.style.padding = '10px 16px';
    btn.style.borderRadius = '8px';
    btn.style.border = '1px solid #ccc';
    btn.style.cursor = 'pointer';
    btn.style.background = '#fff';
    btn.style.fontWeight = '600';
    div.appendChild(btn);

    var info = document.createElement('span');
    info.id = 'keneviz_info';
    info.style.marginLeft = '10px';
    div.appendChild(info);

    btn.addEventListener('click', function(){
      btn.disabled = true;
      var infoEl = document.getElementById('keneviz_info');
      infoEl.innerText = ' doğrulanıyor...';
      // step1: get challenge
      fetch('/keneviz_challenge', {method:'POST', credentials:'same-origin'}).then(function(r){ return r.json(); }).then(function(ch){
        if(!ch || !ch.challenge_id || !ch.sig){
          infoEl.innerText = ' hata (challenge).';
          btn.disabled = false;
          return;
        }
        // step2: verify
        fetch('/keneviz_verify', {
          method:'POST',
          credentials:'same-origin',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({challenge_id: ch.challenge_id, sig: ch.sig})
        }).then(function(r){ return r.json(); }).then(function(res){
          if(res && res.success && res.verification_token){
            infoEl.innerText = ' doğrulandı ✓';
            // set hidden input if exists
            var hidden = document.getElementById('keneviz_token');
            if(hidden) hidden.value = res.verification_token;
            // dispatch event
            window.dispatchEvent(new CustomEvent('keneviz-verified', {detail: {token: res.verification_token}}));
            // optionally style button as verified
            btn.style.background = '#e6ffed';
            btn.style.borderColor = '#4caf50';
            btn.innerText = 'Doğrulandı ✓';
          } else {
            infoEl.innerText = ' doğrulama başarısız.';
            btn.disabled = false;
          }
        }).catch(function(){
          infoEl.innerText = ' doğrulama hatası.';
          btn.disabled = false;
        });
      }).catch(function(){
        var infoEl = document.getElementById('keneviz_info');
        infoEl.innerText = ' challenge hatası.';
        btn.disabled = false;
      });
    });
  }
  // wait DOM ready
  if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', function(){ createButton('keneviz-widget'); });
  } else {
    createButton('keneviz-widget');
  }
})();
"""
    resp = make_response(js)
    resp.headers['Content-Type'] = 'application/javascript; charset=utf-8'
    return resp

@app.route('/keneviz_challenge', methods=['POST'])
@limiter.limit('10 per minute')
def keneviz_challenge():
    """Create a short-lived challenge tied to the request IP."""
    ip = _get_client_ip()
    challenge_id = secrets.token_urlsafe(18)
    ts = _now_ts()
    payload = f"{challenge_id}|{ts}|{ip}"
    sig = _hmac_sign(payload)
    with _keneviz_lock:
        _keneviz_challenges[challenge_id] = {'sig': sig, 'ip': ip, 'ts': ts, 'used': False}
    audit(ip, request.path, request.method, 'keneviz_challenge')
    return jsonify({'challenge_id': challenge_id, 'sig': sig, 'ttl': app.config['KENEVIZ_CHALLENGE_TTL']})

@app.route('/keneviz_verify', methods=['POST'])
@limiter.limit('20 per minute')
def keneviz_verify():
    """
    Verify a challenge and emit a verification token (vc_token).
    Client should POST JSON: {challenge_id, sig}
    """
    data = request.get_json(force=True, silent=True) or {}
    challenge_id = sanitize_input(data.get('challenge_id'))
    sig = sanitize_input(data.get('sig'))
    ip = _get_client_ip()
    if not challenge_id or not sig:
        return jsonify({'success': False, 'error': 'missing'}), 400
    with _keneviz_lock:
        info = _keneviz_challenges.get(challenge_id)
        if not info:
            return jsonify({'success': False, 'error': 'invalid_or_expired'}), 400
        # check IP matches (prevent CSRF from other host)
        if info['ip'] != ip:
            return jsonify({'success': False, 'error': 'ip_mismatch'}), 400
        # check signature matches and not already used and not expired
        if not hmac.compare_digest(info['sig'], sig):
            return jsonify({'success': False, 'error': 'bad_sig'}), 400
        if info.get('used'):
            return jsonify({'success': False, 'error': 'already_used'}), 400
        if _now_ts() - info['ts'] > app.config['KENEVIZ_CHALLENGE_TTL']:
            del _keneviz_challenges[challenge_id]
            return jsonify({'success': False, 'error': 'expired'}), 400
        # all good -> mark used and issue verification token
        info['used'] = True
        vc_ts = _now_ts()
        vc_payload = f"vc|{challenge_id}|{vc_ts}|{ip}"
        vc_sig = _hmac_sign(vc_payload)
        vc_token = base64.urlsafe_b64encode(f"{vc_payload}|{vc_sig}".encode()).decode()
        _keneviz_verifications[vc_token] = {'challenge_id': challenge_id, 'ip': ip, 'ts': vc_ts, 'used': False}
    audit(ip, request.path, request.method, 'keneviz_verified')
    return jsonify({'success': True, 'verification_token': vc_token, 'ttl': app.config['KENEVIZ_VC_TTL']})

def _validate_vc_token(token, ip_check=True):
    """Return True/False. If valid, mark token as used (single-use)."""
    if not token:
        return False
    try:
        with _keneviz_lock:
            info = _keneviz_verifications.get(token)
            if not info:
                return False
            # token lifetime
            if _now_ts() - info['ts'] > app.config['KENEVIZ_VC_TTL']:
                del _keneviz_verifications[token]
                return False
            if info.get('used'):
                return False
            if ip_check and info['ip'] != _get_client_ip():
                return False
            # mark used
            info['used'] = True
            return True
    except Exception:
        return False

def require_keneviz(f):
    """Decorator to protect endpoints. Accepts header X-KENEVIZ-VERIFIED or form field 'keneviz_token'."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-KENEVIZ-VERIFIED') or request.form.get('keneviz_token') or (request.get_json(silent=True) or {}).get('keneviz_token') if request.is_json else None
        if not token or not _validate_vc_token(token):
            audit(_get_client_ip(), request.path, request.method, 'keneviz_blocked')
            return make_response(jsonify({'error':'keneviz_required'}), 403)
        # passed
        audit(_get_client_ip(), request.path, request.method, 'keneviz_ok')
        return f(*args, **kwargs)
    return decorated

# ---------------- Routes ----------------
@app.route('/')
@limiter.limit('60 per minute')
def index():
    try:
        # Try to render templates/index.html if exists; else minimal page with widget example
        if os.path.exists(os.path.join(app.template_folder or 'templates', 'index.html')):
            return render_template('index.html')
        else:
            # Minimal example page that demonstrates widget integration
            html = """
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Keneviz - demo</title></head>
  <body>
    <h2>Keneviz demo page</h2>
    <div id="keneviz-widget"></div>
    <form id="demo-form" method="POST" action="/demo_submit">
      <input type="hidden" name="keneviz_token" id="keneviz_token" value="">
      <input type="text" name="name" placeholder="isim">
      <button type="submit">Gönder</button>
    </form>
    <script src="/keneviz_widget.js"></script>
    <script>
      window.addEventListener('keneviz-verified', function(e){ console.log('verified token', e.detail.token); });
    </script>
  </body>
</html>"""
            return render_template_string(html)
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

# Demo protected route
@app.route('/demo_submit', methods=['POST'])
@require_keneviz
def demo_submit():
    name = sanitize_input(request.form.get('name'))
    return jsonify({'ok': True, 'name': name})

# ---------------- Run ----------------
if __name__ == '__main__':
    if os.environ.get('FLASK_ENV') == 'production':
        app.config['SESSION_COOKIE_SECURE'] = True
    print('Starting keneviz bot... CF_REQUIRED=', app.config['CF_REQUIRED'])
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',5000)), debug=False)

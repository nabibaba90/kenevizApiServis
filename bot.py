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
from urllib.parse import quote, unquote

# ---------------- Config ----------------
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = False   # production: True (HTTPS)
    CF_REQUIRED = os.environ.get('CF_REQUIRED', 'True').lower() in ('1','true','yes')
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT') or '15 per minute'
    DB_PATH = os.environ.get('DB_PATH') or 'keneviz.db'
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
def _get_client_ip():
    return request.headers.get('CF-Connecting-IP') or request.remote_addr

@app.before_request
def before_any():
    ip = _get_client_ip()

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

    # Public paths that must be accessible without prior Keneviz token
    public_prefixes = (
        '/keneviz_widget.js',
        '/keneviz_challenge',
        '/keneviz_verify',
        '/robot_dogrulama',
        '/static',
        '/s/',
        '/healthz',
        '/keneviz_widget',  # just in case
        '/favicon.ico'
    )
    for p in public_prefixes:
        if request.path == p or request.path.startswith(p):
            # allow without CF header even if CF_REQUIRED (these must be reachable for verification)
            break
    else:
        # For all other paths require Cloudflare header when configured (allow localhost)
        if app.config['CF_REQUIRED']:
            if 'CF-Connecting-IP' not in request.headers and request.remote_addr not in ('127.0.0.1','::1'):
                return make_response('Access denied: Cloudflare required.', 403)

    # audit normal requests
    audit(ip, request.path, request.method, 'request')

# ---------------- Keneviz widget & verification API ----------------

@app.route('/keneviz_widget.js')
def keneviz_widget_js():
    """
    Serve a tiny JS widget that builds a "Keneviz: I'm not a robot" single-click button.
    It:
      - renders a button in #keneviz-widget
      - on click: fetch /keneviz_challenge, then /keneviz_verify
      - on success: dispatches window event 'keneviz-verified' with {token: ...}
      - sets hidden input #keneviz_token if present in DOM
      - server also sets HttpOnly cookie 'keneviz_vc' on verify
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
    Server will set HttpOnly cookie 'keneviz_vc' so subsequent requests carry the token.
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

    # return token and set HttpOnly cookie so browser will send it automatically
    resp = make_response(jsonify({'success': True, 'verification_token': vc_token, 'ttl': app.config['KENEVIZ_VC_TTL']}))
    max_age = app.config['KENEVIZ_VC_TTL']
    secure_flag = app.config['SESSION_COOKIE_SECURE']
    resp.set_cookie('keneviz_vc', vc_token, max_age=max_age, httponly=True, secure=secure_flag, samesite='Lax', path='/')
    return resp

def _check_vc_token(token: str, ip_check: bool = True, consume: bool = False) -> bool:
    """
    Validate verification token.
    If consume=True, mark the token as used (single-use). If consume=False, just check validity.
    """
    if not token:
        return False
    try:
        with _keneviz_lock:
            info = _keneviz_verifications.get(token)
            if not info:
                return False
            # lifetime
            if _now_ts() - info['ts'] > app.config['KENEVIZ_VC_TTL']:
                del _keneviz_verifications[token]
                return False
            if info.get('used'):
                return False
            if ip_check and info['ip'] != _get_client_ip():
                return False
            if consume:
                info['used'] = True
            return True
    except Exception:
        return False

def require_keneviz(f):
    """Decorator to protect endpoints. Accepts header X-KENEVIZ-VERIFIED or form field 'keneviz_token' or cookie 'keneviz_vc'."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # header / form / json
        token = request.headers.get('X-KENEVIZ-VERIFIED') or request.form.get('keneviz_token') or (request.get_json(silent=True) or {}).get('keneviz_token') if request.is_json else None
        # cookie fallback
        if not token:
            token = request.cookies.get('keneviz_vc')
        if not token or not _check_vc_token(token, ip_check=True, consume=True):
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
        # If cookie has valid token (don't consume here), allow show; otherwise redirect to robot_dogrulama
        token = request.cookies.get('keneviz_vc')
        if not token or not _check_vc_token(token, ip_check=True, consume=False):
            # redirect to robot verification with next param
            nxt = request.full_path if request.full_path and request.full_path != '/' else '/'
            nxt_enc = quote(nxt, safe='')
            return redirect(url_for('robot_dogrulama') + '?next=' + nxt_enc)
        # render main page (if template exists)
        if os.path.exists(os.path.join(app.template_folder or 'templates', 'index.html')):
            return render_template('index.html')
        else:
            # Minimal page example
            html = """
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Keneviz - main</title></head>
  <body>
    <h2>Keneviz - protected main page</h2>
    <p>Erişim başarılı, doğrulama mevcut.</p>
  </body>
</html>"""
            return render_template_string(html)
    except Exception:
        return '<h2>Keneviz - index error</h2>', 500

@app.route('/robot_dogrulama', methods=['GET'])
@limiter.limit('30 per minute')
def robot_dogrulama():
    """
    Render the verification page. After success the widget sets cookie (server does),
    and the page JS will redirect back to ?next=...
    """
    nxt = request.args.get('next') or '/'
    try:
        nxt = unquote(nxt)
    except Exception:
        nxt = '/'
    # If already have valid token, redirect back
    token = request.cookies.get('keneviz_vc')
    if token and _check_vc_token(token, ip_check=True, consume=False):
        return redirect(nxt)
    # Render small verification page with widget
    html = f"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Keneviz - Doğrulama</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
      body{{background:#07021a;color:#e6f7ff;font-family:system-ui,Arial;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}}
      .card{{background:linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01));padding:24px;border-radius:12px;max-width:420px;text-align:center}}
      #keneviz-widget{{margin-top:16px}}
      .hint{{opacity:0.9;margin-top:12px;font-size:0.95rem}}
    </style>
  </head>
  <body>
    <div class="card">
      <h2>Keneviz Doğrulama</h2>
      <p class="hint">Lütfen doğrulama butonuna tıklayın. Bu işlem sizi otomatik olarak siteye geri yönlendirecek.</p>
      <div id="keneviz-widget"></div>
      <input type="hidden" id="keneviz_token" name="keneviz_token" value="">
    </div>

    <script>
      // after verification, server sets cookie; but widget also emits event with token
      var next = {quote(nxt)};
      window.addEventListener('keneviz-verified', function(e){
        // short delay to ensure cookie from server is set, then redirect
        setTimeout(function(){ window.location = next; }, 450);
      });
    </script>
    <script src="/keneviz_widget.js"></script>
  </body>
</html>
"""
    return render_template_string(html)

# Example API endpoint (sanitized, parameterized usage if using DB)
@app.route('/api/<name>', methods=['GET','POST'])
@limiter.limit('30 per minute')
@require_keneviz
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

# Demo protected route (consumes token on use)
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

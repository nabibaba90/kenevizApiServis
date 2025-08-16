#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bot.py - Keneviz secure server (Render-friendly, persistent VC tokens, strong defaults)
"""
import os
import time
import sqlite3
import secrets
import re
import hmac
import base64
import hashlib
import threading
from urllib.parse import quote, unquote
from functools import wraps
from flask import Flask, request, jsonify, make_response, send_from_directory, render_template, render_template_string, redirect, url_for

# ---------------- Config & app ----------------
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(64)
    SESSION_COOKIE_HTTPONLY = True
    # Default to True because Render serves HTTPS by default; override with env if needed.
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() in ('1','true','yes')
    SESSION_COOKIE_SAMESITE = 'Lax'
    CF_REQUIRED = os.environ.get('CF_REQUIRED', 'True').lower() in ('1','true','yes')
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT') or '15 per minute'
    DB_PATH = os.environ.get('DB_PATH') or 'keneviz.db'
    # UPTIME_TOKEN (optional)
    UPTIME_TOKEN = os.environ.get('UPTIME_TOKEN') or "gPWNMXgR0BCIz8ozdGk5-AZUSVH7CJJ2E3fe7DbHgkQ"
    JOB_ALLOWLIST_IPS = [ip.strip() for ip in (os.environ.get('JOB_ALLOWLIST_IPS') or '').split(',') if ip.strip()]
    # Keneviz specifics
    KENEVIZ_CHALLENGE_TTL = int(os.environ.get('KENEVIZ_CHALLENGE_TTL') or 120)   # seconds
    KENEVIZ_VC_TTL = int(os.environ.get('KENEVIZ_VC_TTL') or 3600)               # seconds
    KENEVIZ_SECRET = os.environ.get('KENEVIZ_SECRET') or secrets.token_urlsafe(64)

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']

# ---------------- Basic imports that may be missing on some systems ---------------
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except Exception:
    Limiter = None

# ---------------- Rate limiter init (optional) ----------------
if Limiter:
    limiter = Limiter(key_func=get_remote_address, default_limits=[app.config['RATELIMIT_DEFAULT']])
    limiter.init_app(app)
else:
    # dummy decorator replacements
    def noop_decorator(f): return f
    limiter = None
    Limiter = None

# ---------------- DB init / helpers ----------------
def get_db_conn():
    conn = sqlite3.connect(app.config['DB_PATH'], check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_conn()
    cur = conn.cursor()
    # enable WAL for better concurrency / durability
    try:
        cur.execute("PRAGMA journal_mode=WAL;")
    except Exception:
        pass
    # audit table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        path TEXT,
        method TEXT,
        ts INTEGER,
        note TEXT
    );
    ''')
    # persistent keneviz verifications
    cur.execute('''
    CREATE TABLE IF NOT EXISTS keneviz_vc (
        token TEXT PRIMARY KEY,
        challenge_id TEXT,
        ip TEXT,
        ts INTEGER,
        used INTEGER DEFAULT 0
    );
    ''')
    # optional challenges table (minimal)
    cur.execute('''
    CREATE TABLE IF NOT EXISTS keneviz_challenge (
        challenge_id TEXT PRIMARY KEY,
        sig TEXT,
        ip TEXT,
        ts INTEGER,
        used INTEGER DEFAULT 0
    );
    ''')
    conn.commit()
    conn.close()

init_db()

def audit(ip, path, method, note=''):
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute('INSERT INTO audit (ip,path,method,ts,note) VALUES (?,?,?,?,?)', (ip, path, method, int(time.time()), note))
        conn.commit()
        conn.close()
    except Exception:
        pass

# ---------------- Helpers ----------------
def sanitize_input(v, max_len=2000):
    if v is None:
        return ''
    if not isinstance(v, str):
        v = str(v)
    v = v.strip()
    if len(v) > max_len:
        v = v[:max_len]
    # minimal cleaning (bleach recommended in requirements)
    return v

def _hmac_sign(msg: str) -> str:
    key = app.config['KENEVIZ_SECRET'].encode()
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()

def _now_ts() -> int:
    return int(time.time())

# ---------------- Basic DDoS / rate helpers ----------------
req_times = {}
blacklist = {}
MAX_WINDOW = 60
MAX_PER_WINDOW = 400
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
    # reasonably strict CSP; allow inline for our small widget but prefer 'self' and https
    resp.headers['Content-Security-Policy'] = "default-src 'self' https:; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:;"
    return resp

# ---------------- Request pre-checks ----------------
def _get_client_ip():
    return request.headers.get('CF-Connecting-IP') or request.remote_addr

@app.before_request
def before_any():
    ip = _get_client_ip()
    if is_blacklisted(ip):
        return make_response('Too many requests (temporary block).', 429)
    record_req(ip)

    # healthz allowances
    if request.path == '/healthz':
        token = request.headers.get('X-UPTIME-TOKEN') or request.args.get('token')
        if app.config['UPTIME_TOKEN'] and token and secrets.compare_digest(token, app.config['UPTIME_TOKEN']):
            audit(ip, request.path, request.method, 'health_ok_token')
            return None
        if ip in app.config['JOB_ALLOWLIST_IPS']:
            audit(ip, request.path, request.method, 'health_ok_ip')
            return None
        if app.config['CF_REQUIRED'] and 'CF-Connecting-IP' not in request.headers:
            return make_response('Health check blocked: missing CF header or token.', 403)
        return None

    # Public prefixes needed for verification flow
    public_prefixes = (
        '/keneviz_widget.js',
        '/keneviz_challenge',
        '/keneviz_verify',
        '/robot_dogrulama',
        '/static',
        '/s/',
        '/healthz',
        '/favicon.ico'
    )
    for p in public_prefixes:
        if request.path == p or request.path.startswith(p):
            break
    else:
        if app.config['CF_REQUIRED']:
            if 'CF-Connecting-IP' not in request.headers and request.remote_addr not in ('127.0.0.1','::1'):
                return make_response('Access denied: Cloudflare required.', 403)

    audit(ip, request.path, request.method, 'request')

# ---------------- Keneviz widget / challenge / verify  ----------------
def _persist_challenge(challenge_id, sig, ip, ts):
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute('INSERT OR REPLACE INTO keneviz_challenge (challenge_id, sig, ip, ts, used) VALUES (?,?,?,?,0)', (challenge_id, sig, ip, ts))
        conn.commit()
        conn.close()
    except Exception:
        pass

def _get_challenge_row(challenge_id):
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute('SELECT challenge_id, sig, ip, ts, used FROM keneviz_challenge WHERE challenge_id=?', (challenge_id,))
        row = cur.fetchone()
        conn.close()
        return row
    except Exception:
        return None

def _mark_challenge_used(challenge_id):
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute('UPDATE keneviz_challenge SET used=1 WHERE challenge_id=?', (challenge_id,))
        conn.commit()
        conn.close()
    except Exception:
        pass

def _persist_vc(token, challenge_id, ip, ts):
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute('INSERT OR REPLACE INTO keneviz_vc (token, challenge_id, ip, ts, used) VALUES (?,?,?,?,0)', (token, challenge_id, ip, ts))
        conn.commit()
        conn.close()
    except Exception:
        pass

def _get_vc_row(token):
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute('SELECT token, challenge_id, ip, ts, used FROM keneviz_vc WHERE token=?', (token,))
        row = cur.fetchone()
        conn.close()
        return row
    except Exception:
        return None

def _set_vc_used(token):
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute('UPDATE keneviz_vc SET used=1 WHERE token=?', (token,))
        conn.commit()
        conn.close()
    except Exception:
        pass

@app.route('/keneviz_widget.js')
def keneviz_widget_js():
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
      fetch('/keneviz_challenge', {method:'POST', credentials:'same-origin'}).then(function(r){ return r.json(); }).then(function(ch){
        if(!ch || !ch.challenge_id || !ch.sig){
          infoEl.innerText = ' hata (challenge).';
          btn.disabled = false;
          return;
        }
        fetch('/keneviz_verify', {
          method:'POST',
          credentials:'same-origin',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({challenge_id: ch.challenge_id, sig: ch.sig})
        }).then(function(r){ return r.json(); }).then(function(res){
          if(res && res.success && res.verification_token){
            infoEl.innerText = ' doğrulandı ✓';
            var hidden = document.getElementById('keneviz_token');
            if(hidden) hidden.value = res.verification_token;
            window.dispatchEvent(new CustomEvent('keneviz-verified', {detail: {token: res.verification_token}}));
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
def keneviz_challenge():
    ip = _get_client_ip()
    challenge_id = secrets.token_urlsafe(24)
    ts = _now_ts()
    payload = "{}|{}|{}".format(challenge_id, ts, ip)
    sig = _hmac_sign(payload)
    _persist_challenge(challenge_id, sig, ip, ts)
    audit(ip, request.path, request.method, 'keneviz_challenge')
    return jsonify({'challenge_id': challenge_id, 'sig': sig, 'ttl': app.config['KENEVIZ_CHALLENGE_TTL']})

@app.route('/keneviz_verify', methods=['POST'])
def keneviz_verify():
    data = request.get_json(force=True, silent=True) or {}
    challenge_id = sanitize_input(data.get('challenge_id'))
    sig = sanitize_input(data.get('sig'))
    ip = _get_client_ip()
    if not challenge_id or not sig:
        return jsonify({'success': False, 'error': 'missing'}), 400

    row = _get_challenge_row(challenge_id)
    if not row:
        return jsonify({'success': False, 'error': 'invalid_or_expired'}), 400

    # row fields: challenge_id, sig, ip, ts, used
    try:
        stored_sig = row['sig']
        stored_ip = row['ip']
        stored_ts = int(row['ts'])
        stored_used = int(row['used'])
    except Exception:
        return jsonify({'success': False, 'error': 'invalid_row'}), 400

    if stored_ip != ip:
        return jsonify({'success': False, 'error': 'ip_mismatch'}), 400
    if not hmac.compare_digest(stored_sig, sig):
        return jsonify({'success': False, 'error': 'bad_sig'}), 400
    if stored_used:
        return jsonify({'success': False, 'error': 'already_used'}), 400
    if _now_ts() - stored_ts > app.config['KENEVIZ_CHALLENGE_TTL']:
        return jsonify({'success': False, 'error': 'expired'}), 400

    # mark challenge used and issue VC token persisted in DB
    _mark_challenge_used(challenge_id)
    vc_ts = _now_ts()
    vc_payload = "vc|{}|{}|{}".format(challenge_id, vc_ts, ip)
    vc_sig = _hmac_sign(vc_payload)
    vc_token_raw = "{}|{}".format(vc_payload, vc_sig)
    vc_token = base64.urlsafe_b64encode(vc_token_raw.encode()).decode()
    _persist_vc(vc_token, challenge_id, ip, vc_ts)
    audit(ip, request.path, request.method, 'keneviz_verified')

    resp = make_response(jsonify({'success': True, 'verification_token': vc_token, 'ttl': app.config['KENEVIZ_VC_TTL']}))
    max_age = app.config['KENEVIZ_VC_TTL']
    resp.set_cookie('keneviz_vc', vc_token, max_age=max_age, httponly=True, secure=app.config['SESSION_COOKIE_SECURE'], samesite=app.config['SESSION_COOKIE_SAMESITE'], path='/')
    return resp

def _check_vc_token(token: str, ip_check: bool = True, consume: bool = False) -> bool:
    if not token:
        return False
    row = _get_vc_row(token)
    if not row:
        return False
    try:
        rec_ts = int(row['ts'])
        rec_ip = row['ip']
        rec_used = int(row['used'])
    except Exception:
        return False
    if rec_used:
        return False
    if _now_ts() - rec_ts > app.config['KENEVIZ_VC_TTL']:
        return False
    if ip_check and rec_ip != _get_client_ip():
        return False
    if consume:
        _set_vc_used(token)
    return True

def require_keneviz(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if request.headers.get('X-KENEVIZ-VERIFIED'):
            token = request.headers.get('X-KENEVIZ-VERIFIED')
        elif request.form.get('keneviz_token'):
            token = request.form.get('keneviz_token')
        elif request.is_json:
            j = request.get_json(silent=True) or {}
            token = j.get('keneviz_token')
        if not token:
            token = request.cookies.get('keneviz_vc')
        if not token or not _check_vc_token(token, ip_check=True, consume=True):
            audit(_get_client_ip(), request.path, request.method, 'keneviz_blocked')
            return make_response(jsonify({'error':'keneviz_required'}), 403)
        audit(_get_client_ip(), request.path, request.method, 'keneviz_ok')
        return f(*args, **kwargs)
    return decorated

# ---------------- Routes ----------------
@app.route('/')
def index():
    # If cookie has valid token (non-consuming), allow; otherwise redirect to verification
    token = request.cookies.get('keneviz_vc')
    if not token or not _check_vc_token(token, ip_check=True, consume=False):
        nxt = request.full_path if request.full_path and request.full_path != '/' else '/'
        nxt_enc = quote(nxt, safe='')
        return redirect('/robot_dogrulama?next=' + nxt_enc)
    # render templates/index.html if exists
    tpl_path = os.path.join(app.template_folder or 'templates', 'index.html')
    if os.path.exists(tpl_path):
        return render_template('index.html')
    return "<h2>Keneviz - Protected main</h2>", 200

@app.route('/robot_dogrulama', methods=['GET'])
def robot_dogrulama():
    nxt = request.args.get('next') or '/'
    try:
        nxt = unquote(nxt)
    except Exception:
        nxt = '/'
    token = request.cookies.get('keneviz_vc')
    if token and _check_vc_token(token, ip_check=True, consume=False):
        return redirect(nxt)
    # Prefer using a real template placed in templates/robot_dogrulama.html
    tpl = os.path.join(app.template_folder or 'templates', 'robot_dogrulama.html')
    if os.path.exists(tpl):
        return render_template('robot_dogrulama.html', next=nxt)
    # fallback HTML (safe - not an f-string; uses %s to inject next)
    html = """
<!doctype html>
<html lang="tr">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Keneviz Doğrulama</title>
<style>
body{background:#070217;color:#e6f7ff;font-family:system-ui,Arial;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}
.card{background:linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01));padding:20px;border-radius:10px;max-width:420px;text-align:center}
.circle{width:140px;height:140px;border-radius:50%;background:radial-gradient(circle at 30% 30%, rgba(255,255,255,0.03), rgba(255,255,255,0.01));border:4px solid rgba(255,255,255,0.04);display:flex;align-items:center;justify-content:center;margin:12px auto;cursor:pointer}
.inner{width:84px;height:84px;border-radius:50%;background:linear-gradient(135deg,#00f6ff,#ff00d6);display:flex;align-items:center;justify-content:center;font-weight:900;color:#001}
.spinner{width:76px;height:76px;border-radius:50%;border:6px solid rgba(255,255,255,0.08);border-top-color:#66ff99;animation:spin 1s linear infinite;display:none}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
  <div class="card">
    <h2>Keneviz Doğrulama</h2>
    <p>Lütfen daireye tıklayın.</p>
    <div id="circle" class="circle" role="button" tabindex="0" title="Doğrulamak için tıkla">
      <div class="inner" id="label">Doğrula</div>
      <div class="spinner" id="spin" aria-hidden="true"></div>
    </div>
    <p id="msg">Doğrulama birkaç saniye sürebilir.</p>
  </div>
<script>
(function(){
  var circle = document.getElementById('circle'), label = document.getElementById('label'), spin = document.getElementById('spin'), msg = document.getElementById('msg');
  function busy(b){ if(b){ label.style.display='none'; spin.style.display='block'; } else { label.style.display='flex'; spin.style.display='none'; } }
  async function getChallenge(){
    var r = await fetch('/keneviz_challenge', {method:'POST', credentials:'same-origin'});
    if(!r.ok) throw new Error('challenge');
    return r.json();
  }
  async function verify(ch, meta){
    var r = await fetch('/keneviz_verify', {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body: JSON.stringify(Object.assign({}, ch, {client_meta: meta}))});
    return r.json().catch(()=>({success:false}));
  }
  function collectQuick(){
    return { ua:navigator.userAgent||'', webdriver:!!navigator.webdriver, hw:navigator.hardwareConcurrency||0, touch:('ontouchstart' in window)||(navigator.maxTouchPoints&&navigator.maxTouchPoints>0), ts:Date.now() };
  }
  async function run(){
    try{
      busy(true); msg.textContent='Hazırlanıyor...';
      await new Promise(r=>setTimeout(r, 120+Math.random()*200));
      var pre = collectQuick();
      if(pre.webdriver){ msg.textContent='Bot benzeri tarayıcı tespit edildi.'; busy(false); return; }
      msg.textContent='Challenge alınıyor...';
      var ch = await getChallenge();
      msg.textContent='Analiz yapılıyor...';
      var moves = 0;
      function mm(){ moves++; }
      window.addEventListener('mousemove', mm, {passive:true});
      await new Promise(r=>setTimeout(r, 300));
      window.removeEventListener('mousemove', mm);
      var meta = {moves:moves};
      msg.textContent='Doğrulama gönderiliyor...';
      var ok = await verify(ch, Object.assign({}, pre, meta));
      if(ok && ok.success){
        msg.textContent='Doğrulama başarılı — yönlendiriliyorsun...';
        window.dispatchEvent(new CustomEvent('keneviz-verified', {detail:{token: ok.verification_token}}));
        setTimeout(function(){ try{ var p = new URLSearchParams(window.location.search); var nxt = p.get('next') || '/'; window.location = nxt; }catch(e){ window.location.reload(); } }, 500);
        return;
      }
      msg.textContent='Doğrulama başarısız veya şüpheli.'; busy(false);
    }catch(e){ console.error(e); msg.textContent='Doğrulama hatası.'; busy(false); }
  }
  circle.addEventListener('click', run);
  circle.addEventListener('keydown', function(e){ if(e.key==='Enter'||e.key===' ') run(); });
})();
</script>
</body>
</html>
""" % (quote(nxt))
    return html, 200, {'Content-Type':'text/html; charset=utf-8'}

@app.route('/s/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

@app.route('/healthz', methods=['GET'])
def healthz():
    return jsonify({'status':'ok','ts':int(time.time())})

# Example protected API endpoint
@app.route('/api/<name>', methods=['GET','POST'])
@require_keneviz
def api_proxy(name):
    name = sanitize_input(name, 100)
    params = request.args.to_dict() if request.method == 'GET' else request.form.to_dict()
    params = {k: sanitize_input(v) for k,v in params.items()}
    return jsonify({'api': name, 'params': params})

# ---------------- Run ----------------
if __name__ == '__main__':
    # Ensure cookies secure if running in production env
    if os.environ.get('FLASK_ENV') == 'production':
        app.config['SESSION_COOKIE_SECURE'] = True
    print('Starting keneviz bot... CF_REQUIRED=', app.config['CF_REQUIRED'])
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)

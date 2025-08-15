from flask import Flask, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Rate limit ayarı: IP başına dakika başına 15 istek
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["15 per minute"]
)
limiter.init_app(app)

@app.route('/')
@limiter.limit("15 per minute")  # İsteğe bağlı olarak route'a özel limit
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

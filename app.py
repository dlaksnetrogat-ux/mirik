from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, ChatRoom, Message
from functools import wraps
import secrets
import string
import os
import hmac
import hashlib
import base64
import json
import requests
from sqlalchemy import inspect
from authlib.jose import jwt, JsonWebKey

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-this-secret"),
    SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///database.db"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE="Lax",
)

if os.environ.get("FLASK_ENV") == "production" and app.config["SECRET_KEY"] == "dev-only-change-this-secret":
    raise RuntimeError("Set SECRET_KEY in production")

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Сначала войдите в аккаунт."

telegram_client_id = os.environ.get("TELEGRAM_CLIENT_ID", "").strip()
TELEGRAM_JWKS_URL = "https://oauth.telegram.org/.well-known/jwks.json"
TELEGRAM_ISSUER = "https://oauth.telegram.org"

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None

def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token

app.jinja_env.globals["csrf_token"] = csrf_token

def validate_csrf():
    expected = session.get("csrf_token")
    supplied = request.form.get("csrf_token", "")
    if not expected or not hmac.compare_digest(expected, supplied):
        abort(400, description="Недействительный CSRF-токен")

def post_only(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.method != "POST":
            abort(405)
        validate_csrf()
        return view(*args, **kwargs)
    return wrapped

def generate_code(length=8):
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

def telegram_enabled():
    return bool(telegram_client_id)

def verify_telegram_id_token(id_token, expected_nonce):
    if not telegram_enabled() or not id_token:
        return None
    try:
        parts = id_token.split(".")
        if len(parts) != 3:
            return None
        header_raw = parts[0] + "=" * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_raw.encode("ascii")))
        kid = header.get("kid")
        if not kid:
            return None

        response = requests.get(TELEGRAM_JWKS_URL, timeout=8)
        response.raise_for_status()
        key_set = JsonWebKey.import_key_set(response.json())
        key = key_set.find_by_kid(kid)
        if key is None:
            return None

        claims = jwt.decode(id_token, key)
        claims.validate()

        if claims.get("iss") != TELEGRAM_ISSUER:
            return None
        audience = claims.get("aud")
        if isinstance(audience, list):
            if str(telegram_client_id) not in {str(value) for value in audience}:
                return None
        elif str(audience) != str(telegram_client_id):
            return None
        if expected_nonce and claims.get("nonce") != expected_nonce:
            return None
        if not claims.get("sub"):
            return None
        return claims
    except Exception:
        return None

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' https://telegram.org; "
        "connect-src 'self'; "
        "img-src 'self' data: https://*.telegram.org https://cdn4.telesco.pe https://cdn5.telesco.pe; "
        "form-action 'self'; frame-ancestors 'self'"
    )
    return response

def initialize_database():
    db.create_all()
    if db.engine.url.get_backend_name() == "sqlite":
        inspector = inspect(db.engine)
        user_columns = {column["name"] for column in inspector.get_columns("user")}
        migrations = []
        if "is_active" not in user_columns:
            migrations.append("ALTER TABLE user ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1")
        if "telegram_id" not in user_columns:
            migrations.append("ALTER TABLE user ADD COLUMN telegram_id VARCHAR(64)")
        if "telegram_username" not in user_columns:
            migrations.append("ALTER TABLE user ADD COLUMN telegram_username VARCHAR(64)")
        if "display_name" not in user_columns:
            migrations.append("ALTER TABLE user ADD COLUMN display_name VARCHAR(160)")
        if "telegram_photo_url" not in user_columns:
            migrations.append("ALTER TABLE user ADD COLUMN telegram_photo_url VARCHAR(1000)")
        if migrations:
            with db.engine.begin() as connection:
                for statement in migrations:
                    connection.exec_driver_sql(statement)

with app.app_context():
    initialize_database()
    os.makedirs(os.path.join(app.static_folder, "avatars"), exist_ok=True)

@app.route("/")
def index():
    return redirect(url_for("dashboard" if current_user.is_authenticated else "login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        validate_csrf()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.is_active and user.check_password(password):
            user.online = True
            db.session.commit()
            login_user(user, remember=True)
            session.permanent = True
            return redirect(url_for("dashboard"))
        flash("Неверный email или пароль", "error")

    telegram_nonce = secrets.token_urlsafe(24)
    session["telegram_nonce"] = telegram_nonce
    return render_template(
        "login.html",
        telegram_enabled=telegram_enabled(),
        telegram_client_id=telegram_client_id,
        telegram_nonce=telegram_nonce,
    )

@app.route("/auth/telegram/callback", methods=["POST"])
def telegram_callback():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    payload = request.get_json(silent=True) or {}
    id_token = str(payload.get("id_token", "")).strip()
    expected_nonce = session.pop("telegram_nonce", None)
    claims = verify_telegram_id_token(id_token, expected_nonce)
    if not claims:
        flash("Не удалось подтвердить вход через Telegram. Проверьте Client ID и Web Login в BotFather.", "error")
        return redirect(url_for("login"))

    telegram_id = str(claims.get("sub", "")).strip()
    username = str(claims.get("preferred_username") or "").strip()
    display_name = str(claims.get("name") or "").strip() or (f"@{username}" if username else "Telegram user")
    photo_url = str(claims.get("picture") or "").strip()

    user = User.query.filter_by(telegram_id=telegram_id).first()
    if not user and username:
        user = User.query.filter_by(telegram_username=username).first()

    if not user:
        email = f"telegram_{telegram_id}@users.mirik.local"
        user = User(
            email=email,
            avatar="default.png",
            display_name=display_name[:160],
            telegram_id=telegram_id,
            telegram_username=username or None,
            telegram_photo_url=photo_url[:1000] or None,
            online=True,
        )
        user.set_password(secrets.token_urlsafe(32))
        db.session.add(user)
    else:
        user.display_name = display_name[:160]
        user.telegram_username = username or user.telegram_username
        user.telegram_photo_url = photo_url[:1000] or user.telegram_photo_url
        user.online = True

    db.session.commit()
    login_user(user, remember=True)
    session.permanent = True
    return redirect(url_for("dashboard"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        validate_csrf()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        if len(email) > 120 or "@" not in email:
            flash("Введите корректный email.", "error")
            return redirect(url_for("register"))
        if len(password) < 8:
            flash("Пароль должен содержать минимум 8 символов.", "error")
            return redirect(url_for("register"))
        if password != confirm_password:
            flash("Пароли не совпадают.", "error")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("Пользователь с таким email уже существует.", "error")
            return redirect(url_for("register"))
        user = User(email=email, avatar="default.png")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Регистрация прошла успешно. Теперь войдите в аккаунт.", "success")
        return redirect(url_for("login"))

    telegram_nonce = secrets.token_urlsafe(24)
    session["telegram_nonce"] = telegram_nonce
    return render_template(
        "register.html",
        telegram_enabled=telegram_enabled(),
        telegram_client_id=telegram_client_id,
        telegram_nonce=telegram_nonce,
    )

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", chat_rooms=current_user.chat_rooms)

@app.route("/create_chat", methods=["POST"])
@login_required
@post_only
def create_chat():
    chat_name = " ".join(request.form.get("chat_name", "").split())
    is_private = request.form.get("is_private") == "on"
    if not chat_name or len(chat_name) > 100:
        flash("Название чата должно быть от 1 до 100 символов.", "error")
        return redirect(url_for("dashboard"))
    code = None
    if is_private:
        for _ in range(10):
            candidate = generate_code()
            if not ChatRoom.query.filter_by(code=candidate).first():
                code = candidate
                break
        if code is None:
            flash("Не удалось создать уникальный код. Попробуйте ещё раз.", "error")
            return redirect(url_for("dashboard"))
    new_chat = ChatRoom(name=chat_name, is_private=is_private, code=code, created_by=current_user.id)
    new_chat.members.append(current_user)
    db.session.add(new_chat)
    db.session.commit()
    flash("Чат создан!", "success")
    return redirect(url_for("chat", chat_id=new_chat.id))

@app.route("/join_chat", methods=["POST"])
@login_required
@post_only
def join_chat():
    code = request.form.get("code", "").strip().upper()
    if not code or len(code) > 10:
        flash("Введите корректный код чата.", "error")
        return redirect(url_for("dashboard"))
    chat_room = ChatRoom.query.filter_by(code=code, is_private=True).first()
    if not chat_room:
        flash("Приватный чат с таким кодом не найден.", "error")
    elif current_user in chat_room.members:
        flash("Вы уже состоите в этом чате.", "info")
    else:
        chat_room.members.append(current_user)
        db.session.commit()
        flash("Вы присоединились к чату!", "success")
        return redirect(url_for("chat", chat_id=chat_room.id))
    return redirect(url_for("dashboard"))

@app.route("/chat/<int:chat_id>")
@login_required
def chat(chat_id):
    chat_room = db.session.get(ChatRoom, chat_id)
    if chat_room is None:
        abort(404)
    if current_user not in chat_room.members:
        flash("У вас нет доступа к этому чату.", "error")
        return redirect(url_for("dashboard"))
    messages = (Message.query.filter_by(chat_room_id=chat_id)
                .order_by(Message.timestamp.desc())
                .limit(100).all())
    messages.reverse()
    return render_template("chat.html", chat_room=chat_room, messages=messages)

@app.route("/send_message", methods=["POST"])
@login_required
@post_only
def send_message():
    try:
        chat_id = int(request.form.get("chat_id", "0"))
    except ValueError:
        abort(400, description="Некорректный ID чата")
    chat_room = db.session.get(ChatRoom, chat_id)
    if chat_room is None or current_user not in chat_room.members:
        abort(403)
    content = request.form.get("content", "").strip()
    if not content:
        flash("Сообщение не может быть пустым.", "error")
    elif len(content) > 2000:
        flash("Сообщение слишком длинное (максимум 2000 символов).", "error")
    else:
        db.session.add(Message(content=content, user_id=current_user.id, chat_room_id=chat_id))
        db.session.commit()
    return redirect(url_for("chat", chat_id=chat_id))

@app.route("/logout", methods=["POST"])
@login_required
@post_only
def logout():
    current_user.online = False
    db.session.commit()
    logout_user()
    session.clear()
    flash("Вы вышли из аккаунта.", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=os.environ.get("FLASK_DEBUG") == "1")

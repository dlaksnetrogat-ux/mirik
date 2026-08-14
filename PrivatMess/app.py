from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, ChatRoom, Message, user_chatroom
import random
import string
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация расширений
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Генерация случайного кода для чат-комнаты
def generate_code(length=6):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

# Создание таблиц в базе данных
with app.app_context():
    db.create_all()
    # Создаем несколько стандартных аватарок, если их нет
    avatars_dir = os.path.join(app.static_folder, 'avatars')
    if not os.path.exists(avatars_dir):
        os.makedirs(avatars_dir)
        # Здесь можно добавить код для создания стандартных аватарок

# Маршруты
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            user.online = True
            db.session.commit()
            login_user(user, remember=True)
            return redirect(url_for('dashboard'))
        else:
            flash('Неверный email или пароль')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Пароли не совпадают')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует')
            return redirect(url_for('register'))
        
        user = User(email=email)
        user.set_password(password)
        
        # Выбор случайного аватара
        avatars = ['avatar1.png', 'avatar2.png', 'avatar3.png', 'avatar4.png']
        user.avatar = random.choice(avatars)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Регистрация прошла успешно. Теперь вы можете войти.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Получаем все чат-комнаты пользователя
    user_chat_rooms = current_user.chat_rooms
    
    return render_template('dashboard.html', chat_rooms=user_chat_rooms)

@app.route('/create_chat', methods=['POST'])
@login_required
def create_chat():
    chat_name = request.form.get('chat_name')
    is_private = 'is_private' in request.form
    
    code = None
    if is_private:
        code = generate_code()
        # Убедимся, что код уникален
        while ChatRoom.query.filter_by(code=code).first():
            code = generate_code()
    
    new_chat = ChatRoom(
        name=chat_name, 
        is_private=is_private, 
        code=code,
        created_by=current_user.id
    )
    
    new_chat.members.append(current_user)
    db.session.add(new_chat)
    db.session.commit()
    
    flash('Чат-комната создана успешно!')
    return redirect(url_for('dashboard'))

@app.route('/join_chat', methods=['POST'])
@login_required
def join_chat():
    code = request.form.get('code')
    chat_room = ChatRoom.query.filter_by(code=code).first()
    
    if chat_room:
        if current_user not in chat_room.members:
            chat_room.members.append(current_user)
            db.session.commit()
            flash('Вы присоединились к чат-комнате!')
        else:
            flash('Вы уже в этой чат-комнате')
    else:
        flash('Чат-комната с таким кодом не найдена')
    
    return redirect(url_for('dashboard'))

@app.route('/chat/<int:chat_id>')
@login_required
def chat(chat_id):
    chat_room = ChatRoom.query.get_or_404(chat_id)
    
    # Проверяем, является ли пользователь участником чата
    if current_user not in chat_room.members:
        flash('У вас нет доступа к этому чату')
        return redirect(url_for('dashboard'))
    
    messages = Message.query.filter_by(chat_room_id=chat_id).order_by(Message.timestamp.asc()).all()
    return render_template('chat.html', chat_room=chat_room, messages=messages)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    chat_id = request.form.get('chat_id')
    content = request.form.get('content')
    
    if content.strip():
        new_message = Message(
            content=content,
            user_id=current_user.id,
            chat_room_id=chat_id
        )
        db.session.add(new_message)
        db.session.commit()
    
    return redirect(url_for('chat', chat_id=chat_id))

@app.route('/logout')
@login_required
def logout():
    current_user.online = False
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
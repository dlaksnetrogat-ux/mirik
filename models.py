from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


db = SQLAlchemy()


user_chatroom = db.Table(
    "user_chatroom",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), primary_key=True),
    db.Column("chat_room_id", db.Integer, db.ForeignKey("chat_room.id", ondelete="CASCADE"), primary_key=True),
)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    online = db.Column(db.Boolean, default=False, nullable=False)
    avatar = db.Column(db.String(100), default="default.png", nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    telegram_id = db.Column(db.String(64), unique=True, nullable=True, index=True)
    telegram_username = db.Column(db.String(64), nullable=True, index=True)
    display_name = db.Column(db.String(160), nullable=True)
    telegram_photo_url = db.Column(db.String(1000), nullable=True)

    messages = db.relationship(
        "Message",
        backref="author",
        lazy="select",
        cascade="all, delete-orphan",
    )
    chat_rooms = db.relationship(
        "ChatRoom",
        secondary=user_chatroom,
        backref=db.backref("members", lazy="select"),
    )
    created_chats = db.relationship(
        "ChatRoom",
        back_populates="created_by_user",
        foreign_keys="ChatRoom.created_by",
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    is_private = db.Column(db.Boolean, default=False, nullable=False)
    code = db.Column(db.String(10), unique=True, nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    created_by_user = db.relationship(
        "User",
        back_populates="created_chats",
        foreign_keys=[created_by],
    )
    messages = db.relationship(
        "Message",
        backref="chat_room",
        lazy="select",
        cascade="all, delete-orphan",
    )


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    chat_room_id = db.Column(db.Integer, db.ForeignKey("chat_room.id", ondelete="CASCADE"), nullable=False, index=True)

    __table_args__ = (
        db.Index("ix_message_chat_time", "chat_room_id", "timestamp"),
    )

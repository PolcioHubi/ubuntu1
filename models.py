from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"
    username = db.Column(db.String, primary_key=True, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime, server_default=func.now())
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    last_login = db.Column(db.DateTime, nullable=True)
    access_key_used = db.Column(db.String, nullable=True, unique=True)
    hubert_coins = db.Column(db.Integer, nullable=False, default=0)
    password_reset_token = db.Column(db.String, nullable=True, index=True)
    password_reset_expires = db.Column(db.DateTime, nullable=True)
    recovery_token = db.Column(db.String, nullable=True, index=True)

    # Relationships
    files = db.relationship(
        "File", backref="user", lazy=True, cascade="all, delete-orphan"
    )
    notifications = db.relationship(
        "Notification", backref="user", lazy=True, cascade="all, delete-orphan"
    )


class AccessKey(db.Model):
    __tablename__ = "access_keys"
    key = db.Column(db.String, primary_key=True, unique=True, nullable=False)
    description = db.Column(db.String, nullable=True)
    created_at = db.Column(db.DateTime, server_default=func.now())
    expires_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    used_count = db.Column(db.Integer, nullable=False, default=0)
    last_used = db.Column(db.DateTime, nullable=True)


class Notification(db.Model):
    __tablename__ = "notifications"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.String,
        db.ForeignKey("users.username", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    message = db.Column(db.String, nullable=False)
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, server_default=func.now())


class Announcement(db.Model):
    __tablename__ = "announcements"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    message = db.Column(db.String, nullable=False)
    type = db.Column(db.String, nullable=False, default="info")
    created_at = db.Column(db.DateTime, server_default=func.now())
    expires_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)


class File(db.Model):
    __tablename__ = "files"
    id = db.Column(db.Integer, primary_key=True)
    user_username = db.Column(
        db.String,
        db.ForeignKey("users.username", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    filename = db.Column(db.String, nullable=False)
    filepath = db.Column(db.String, nullable=False, unique=True)
    size = db.Column(db.Integer, nullable=False)
    modified_at = db.Column(db.DateTime, nullable=False)
    file_hash = db.Column(db.String, nullable=True)

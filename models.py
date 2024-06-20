from datetime import datetime
from . import db, bcrypt
from flask import current_app
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_ops = db.Column(db.Boolean, default=False)
    confirmed = db.Column(db.Boolean, default=False)

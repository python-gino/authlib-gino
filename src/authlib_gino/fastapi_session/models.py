import time

from gino import Gino
from sqlalchemy.dialects.postgresql import JSONB

from .gino_app import load_entry_point
from ..gino_oauth2.client_mixin import ClientMixin
from ..gino_oauth2.functions import id_generator
from ..gino_oauth2.tokens_mixins import AuthorizationCodeMixin, BearerTokenMixin

db = load_entry_point("db", Gino)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Text(), primary_key=True, default=id_generator("usr", 42))
    created_at = db.Column(
        db.Integer(), nullable=False, default=lambda: int(time.time())
    )
    profile = db.Column(JSONB(), nullable=False, default={})
    name = db.StringProperty()

    def get_user_id(self):
        return self.id


class Identity(db.Model):
    __tablename__ = "identities"

    id = db.Column(db.BigInteger(), primary_key=True)
    sub = db.Column(db.String(), nullable=False)
    idp = db.Column(db.String(), nullable=False)
    user_id = db.Column(db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(
        db.Integer(), nullable=False, default=lambda: int(time.time())
    )
    profile = db.Column(JSONB(), nullable=False, default={})
    identities_idp_sub_idx = db.Index(
        "identities_idp_sub_idx", "sub", "idp", unique=True
    )


class Client(db.Model, ClientMixin):
    __tablename__ = "clients"

    user_id = db.Column(db.ForeignKey("users.id"), nullable=False)


class AuthorizationCode(db.Model, AuthorizationCodeMixin):
    __tablename__ = "authorization_codes"

    client_id = db.Column(db.ForeignKey("clients.client_id"), nullable=False)
    user_id = db.Column(db.ForeignKey("users.id"), nullable=False)


class Session(db.Model):
    __tablename__ = "sessions"

    id = db.Column(db.Text(), primary_key=True, default=id_generator("ssn", 48))
    client_id = db.Column(db.ForeignKey("clients.client_id"), nullable=False)
    user_id = db.Column(db.ForeignKey("users.id"), nullable=False)
    scope = db.Column(db.Text(), nullable=False)
    created_at = db.Column(
        db.Integer(), nullable=False, default=lambda: int(time.time())
    )
    terminated_at = db.Column(db.Integer())

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.tokens = []

    def add_token(self, token):
        self.tokens.append(token)


class BearerToken(db.Model, BearerTokenMixin):
    __tablename__ = "bearer_tokens"

    session_id = db.Column(db.ForeignKey("sessions.id"), nullable=False)
    client_id = db.Column(db.ForeignKey("clients.client_id"), nullable=False)
    user_id = db.Column(db.ForeignKey("users.id"), nullable=False)

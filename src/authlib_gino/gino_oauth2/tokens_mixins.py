from authlib.integrations.sqla_oauth2 import (
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)
from sqlalchemy import Column, Text, Boolean, Integer, Index, text

from .functions import id_generator


class AuthorizationCodeMixin(OAuth2AuthorizationCodeMixin):
    code = Column(Text(), primary_key=True, default=id_generator("ath", 48))
    client_id = Column(Text())
    code_challenge_method = Column(Text())
    used = Column(Boolean(), default=False)
    nonce_index = Index(
        "auth_code_nonce_index", "nonce", "auth_time", postgresql_where=text("not used")
    )


class BearerTokenMixin(OAuth2TokenMixin):
    refresh_token = Column(Text(), primary_key=True, default=id_generator("ref", 48))
    access_token = Column(Text(), nullable=False)
    client_id = Column(Text())
    token_type = Column(Text())
    revoked_at = Column(Integer())

    @property
    def revoked(self):
        return self.revoked_at is not None

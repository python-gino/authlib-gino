from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin
from gino.json_support import ArrayProperty, StringProperty
from sqlalchemy import Column, Text, Boolean
from sqlalchemy.dialects.postgresql import JSONB

from .functions import id_generator


class ClientMixin(OAuth2ClientMixin):
    client_id = Column(Text(), primary_key=True, default=id_generator("cli", 42))
    client_secret = Column(Text())

    _client_metadata = Column(JSONB)
    redirect_uris = ArrayProperty(default=[], prop_name="_client_metadata")
    token_endpoint_auth_method = StringProperty(
        default="client_secret_basic", prop_name="_client_metadata"
    )
    grant_types = ArrayProperty(default=[], prop_name="_client_metadata")
    response_types = ArrayProperty(default=[], prop_name="_client_metadata")
    client_name = StringProperty(prop_name="_client_metadata")
    client_uri = StringProperty(prop_name="_client_metadata")
    logo_uri = StringProperty(prop_name="_client_metadata")
    scope = StringProperty(default="", prop_name="_client_metadata")
    contacts = ArrayProperty(default=[], prop_name="_client_metadata")
    tos_uri = StringProperty(prop_name="_client_metadata")
    policy_uri = StringProperty(prop_name="_client_metadata")
    jwks_uri = StringProperty(prop_name="_client_metadata")
    jwks = ArrayProperty(default=[], prop_name="_client_metadata")
    software_id = StringProperty(prop_name="_client_metadata")
    software_version = StringProperty(prop_name="_client_metadata")
    audience = StringProperty(prop_name="_client_metadata")

    is_active = Column(Boolean(), nullable=False, default=True)

    @property
    def client_metadata(self):
        return self._client_metadata

    def set_client_metadata(self, value):
        self._client_metadata = value

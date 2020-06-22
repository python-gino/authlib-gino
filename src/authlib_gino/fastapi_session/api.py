from typing import Union, Tuple, Optional

from authlib.jose import jwt
from authlib.jose.errors import ExpiredTokenError, JoseError
from authlib.oauth2.rfc6749.util import scope_to_list
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oidc.discovery import OpenIDProviderMetadata
from authlib.oidc.discovery import get_well_known_url
from fastapi import HTTPException
from fastapi.params import Depends
from fastapi.security import SecurityScopes
from starlette import status

from ..fastapi_session import config
from ..fastapi_session.impl import (
    AuthorizationCodeGrant,
    OpenIDCode,
    RefreshTokenGrant,
    JWTBearer,
)
from ..fastapi_session.impl import (
    AuthorizationServer,
    save_token,
)
from ..fastapi_session.models import User, Client, Identity
from ..starlette_oauth2.async_authenticate_client import ClientAuthentication

SCOPES = dict(openid="Any user login requires this scope.", admin="Admin permissions.")
OPENID_CONFIGURATION_ENDPOINT = get_well_known_url("")
AUTHORIZATION_ENDPOINT = "/oauth2/authorize"
TOKEN_ENDPOINT = "/oauth2/token"
USERINFO_ENDPOINT = "/userinfo"
JWKS_URI = "/.well-known/jwks.json"

oidc_scheme = JWTBearer(
    AUTHORIZATION_ENDPOINT,
    TOKEN_ENDPOINT,
    scheme_name="oidc",
    scopes=SCOPES,
    auto_error=False,
)
metadata = OpenIDProviderMetadata(
    issuer=config.JWT_ISSUER,
    authorization_endpoint=config.JWT_ISSUER + AUTHORIZATION_ENDPOINT,
    token_endpoint=config.JWT_ISSUER + TOKEN_ENDPOINT,
    userinfo_endpoint=config.JWT_ISSUER + USERINFO_ENDPOINT,
    jwks_uri=config.JWT_ISSUER + JWKS_URI,
    registration_endpoint=None,
    scopes_supported=list(SCOPES.keys()),
    response_types_supported=["code"],
    subject_types_supported=["public"],
    id_token_signing_alg_values_supported=[config.JWT_ALGORITHM],
)
auth = AuthorizationServer(Client.get, save_token, metadata, ClientAuthentication)
metadata["token_endpoint_auth_methods_supported"] = auth.auth_methods
if config.DEBUG:
    from unittest.mock import patch

    mock = {}
    for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
        mock[key] = metadata[key].replace("http://", "https://")
    with patch.dict(metadata, mock):
        metadata.validate()
else:
    metadata.validate()
auth.register_grant(
    AuthorizationCodeGrant, [OpenIDCode(require_nonce=True), CodeChallenge()],
)
auth.register_grant(RefreshTokenGrant)


def access_token(raise_on_error=True):
    def _access_token(
        security_scopes: SecurityScopes,
        token: Tuple[bool, Union[dict, HTTPException]] = Depends(oidc_scheme),
    ) -> Optional[dict]:
        success, payload = token
        if not success:
            if raise_on_error:
                raise payload
            else:
                return None
        if set(security_scopes.scopes) - current_scopes(payload):
            error = HTTPException(status_code=status.HTTP_404_NOT_FOUND)
            if raise_on_error:
                raise error
            else:
                return None
        return payload

    return _access_token


def current_user(
    token: Optional[dict] = Depends(access_token(raise_on_error=False)),
) -> Optional[User]:
    if token is None:
        return None
    rv = User(id=token["sub"])
    rv.current_identity = Identity(id=token["idt"])
    return rv


def require_user(token: dict = Depends(access_token())) -> User:
    return current_user(token)


def current_scopes(
    token: Optional[dict] = Depends(access_token(raise_on_error=False)),
) -> set:
    if token is None:
        return set()
    return set(scope_to_list(token["sco"]))


def login_context(token: str):
    if not token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    try:
        token = jwt.decode(token, config.JWT_PUBLIC_KEY)
        token.validate()
    except ExpiredTokenError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except JoseError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return token["ctx"]

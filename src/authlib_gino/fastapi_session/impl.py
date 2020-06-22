import logging
import time
from typing import Union, Tuple

from authlib.common.security import generate_token
from authlib.jose import jwt
from authlib.jose.errors import ExpiredTokenError, JoseError
from authlib.oauth2 import OAuth2Request
from authlib.oidc.core import UserInfo
from fastapi import HTTPException
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.security.utils import get_authorization_scheme_param
from starlette.requests import Request
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_400_BAD_REQUEST

from .models import db, Identity
from ..async_grants.authorization_code import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from ..async_grants.oidc_code import OpenIDCode as _OpenIDCode
from ..async_grants.refresh_token import RefreshTokenGrant as _RefreshTokenGrant
from ..fastapi_session import config
from ..fastapi_session.models import (
    User,
    AuthorizationCode,
    Session,
    BearerToken,
)
from ..starlette_oauth2.authorization_server import (
    AuthorizationServer as _AuthorizationServer,
)

log = logging.getLogger(__name__)


class AuthorizationServer(_AuthorizationServer):
    def _generate_access_token(self, client, grant_type, user, scope):
        now = int(time.time())
        token = jwt.encode(
            dict(alg=config.JWT_ALGORITHM),
            dict(
                iss=config.JWT_ISSUER,
                sub=str(user.get_user_id()),
                idt=str(user.get_identity_id()),
                aud=client.audience,
                exp=now + config.JWT_TOKEN_TTL,
                iat=now,
                sco=scope,
            ),
            config.JWT_PRIVATE_KEY,
        )
        return token.decode("ASCII")

    def _generate_refresh_token(self, client, grant_type, user, scope):
        return f"ref:{generate_token(48)}"

    def _get_expires(self, client, grant_type):
        return config.JWT_TOKEN_TTL


async def save_token(token: dict, request: OAuth2Request):
    now = int(time.time())
    data = dict(
        client_id=request.client_id,
        user_id=request.user.get_user_id(),
        identity_id=request.user.get_identity_id(),
        issued_at=now,
        **token,
    )
    if isinstance(request.credential, BearerToken):
        data["session_id"] = request.credential.session_id
    else:
        session = await Session.create(
            client_id=data["client_id"],
            user_id=data["user_id"],
            current_identity_id=data["identity_id"],
            scope=data["scope"],
            created_at=now,
        )
        data["session_id"] = session.id
    return await BearerToken.create(**data)


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    async def save_authorization_code(self, code, request: OAuth2Request):
        code_challenge = request.data.get("code_challenge")
        code_challenge_method = request.data.get("code_challenge_method")
        await AuthorizationCode.create(
            code=code,
            client_id=request.client_id,
            user_id=request.user.get_user_id(),
            identity_id=request.user.get_identity_id(),
            scope=request.scope,
            redirect_uri=request.redirect_uri,
            auth_time=int(time.time()),
            nonce=request.data.get("nonce"),
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )

    async def query_authorization_code(self, code, client):
        return await (
            AuthorizationCode.query.where(AuthorizationCode.code == code)
            .where(~AuthorizationCode.used)
            .where(AuthorizationCode.client_id == client.client_id)
            .gino.first()
        )

    async def delete_authorization_code(self, authorization_code: AuthorizationCode):
        await authorization_code.update(used=True).apply()

    async def authenticate_user(self, authorization_code: AuthorizationCode):
        return await (
            Identity.outerjoin(User)
            .select()
            .where(Identity.id == authorization_code.identity_id)
            .where(User.id == authorization_code.user_id)
            .gino.load(User.load(current_identity=Identity))
            .first()
        )


class RefreshTokenGrant(_RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]
    INCLUDE_NEW_REFRESH_TOKEN = True

    async def authenticate_refresh_token(self, refresh_token):
        return await (
            BearerToken.query.select_from(BearerToken.outerjoin(Session))
            .where(BearerToken.refresh_token == refresh_token)
            .where(BearerToken.revoked_at.is_(None))
            .where(
                Session.created_at + config.SESSION_TTL * 3600 * 24 > int(time.time())
            )
            .where(Session.terminated_at.is_(None))
            .gino.first()
        )

    async def authenticate_user(self, credential: BearerToken):
        return await (
            Identity.outerjoin(User)
            .select()
            .where(Identity.id == credential.identity_id)
            .where(User.id == credential.user_id)
            .gino.load(User.load(current_identity=Identity))
            .first()
        )

    async def revoke_old_credential(self, credential: BearerToken):
        await credential.update(revoked_at=int(time.time())).apply()


class OpenIDCode(_OpenIDCode):
    async def exists_nonce(self, nonce, request):
        return await db.scalar(
            db.exists()
            .where(AuthorizationCode.nonce == nonce)
            .where(~AuthorizationCode.used)
            .where(AuthorizationCode.auth_time > int(time.time()) + 300)
            .select()
        )

    def get_jwt_config(self, grant):
        return {
            "key": config.JWT_PRIVATE_KEY,
            "alg": config.JWT_ALGORITHM,
            "iss": config.JWT_ISSUER,
            "exp": config.JWT_TOKEN_TTL,
        }

    def generate_user_info(self, user, scope):
        return UserInfo(sub=str(user.get_user_id()))


class JWTBearer(OAuth2AuthorizationCodeBearer):
    async def __call__(
        self, request: Request
    ) -> Tuple[bool, Union[dict, HTTPException]]:
        authorization: str = request.headers.get("Authorization")
        scheme, token = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            token = request.cookies.get(config.JWT_ACCESS_TOKEN_COOKIE)
        if not token:
            error = HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
            if self.auto_error:
                raise error
            else:
                return False, error

        try:
            token = jwt.decode(token, config.JWT_PUBLIC_KEY)
            token.validate()
        except ExpiredTokenError as e:
            error = HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail=str(e))
            if self.auto_error:
                raise error
            else:
                return False, error
        except JoseError as e:
            error = HTTPException(status_code=HTTP_400_BAD_REQUEST, detail=str(e))
            if self.auto_error:
                raise error
            else:
                return False, error

        return True, token

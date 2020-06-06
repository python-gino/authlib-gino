"""
Partially copied from authlib/oauth2/rfc6749/authorization_server.py
"""
import asyncio

from authlib.common.security import generate_token
from authlib.oauth2 import AuthorizationServer as _AuthorizationServer
from authlib.oauth2.rfc6749 import OAuth2Error, InvalidGrantError, OAuth2Request
from authlib.oauth2.rfc6750 import BearerToken as BearerTokenGenerator
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class AuthorizationServer(_AuthorizationServer):
    def __init__(self, query_client, save_token, metadata, client_auth_cls):
        super().__init__(
            query_client, save_token, self._generate_token, metadata,
        )
        self._bearer_token_generator = BearerTokenGenerator(
            self._generate_access_token,
            self._generate_refresh_token,
            self._get_expires,
        )
        self._client_auth = client_auth_cls(query_client)

    async def _generate_token(
        self, client, grant_type, user, scope, expires_in, include_refresh_token
    ):
        return await asyncio.get_running_loop().run_in_executor(
            None,
            self._bearer_token_generator,
            client,
            grant_type,
            user,
            scope,
            expires_in,
            include_refresh_token,
        )

    def _generate_access_token(self, client, grant_type, user, scope):
        return generate_token(42)

    def _generate_refresh_token(self, client, grant_type, user, scope):
        return generate_token(48)

    def _get_expires(self, client, grant_type):
        return self._bearer_token_generator.GRANT_TYPES_EXPIRES_IN.get(
            grant_type, self._bearer_token_generator.DEFAULT_EXPIRES_IN
        )

    def create_json_request(self, request):
        # TODO
        pass

    async def create_oauth2_request(self, request: Request):
        body = None
        if request.method == "POST":
            body = await request.form()
        return OAuth2Request(request.method, str(request.url), body, request.headers)

    async def create_authorization_response(
        self, request: Request = None, grant_user=None
    ):
        request = await self.create_oauth2_request(request)
        try:
            grant = self.get_authorization_grant(request)
        except InvalidGrantError as error:
            return self.handle_error_response(request, error)

        try:
            redirect_uri = await grant.validate_authorization_request()
            args = await grant.create_authorization_response(redirect_uri, grant_user)
            return self.handle_response(*args)
        except OAuth2Error as error:
            return self.handle_error_response(request, error)

    async def create_token_response(self, request=None):
        request = await self.create_oauth2_request(request)
        try:
            grant = self.get_token_grant(request)
        except InvalidGrantError as error:
            return self.handle_error_response(request, error)

        try:
            await grant.validate_token_request()
            args = await grant.create_token_response()
            return self.handle_response(*args)
        except OAuth2Error as error:
            return self.handle_error_response(request, error)

    def handle_response(self, status, body, headers):
        return (JSONResponse if isinstance(body, dict) else Response)(
            body, status, dict(headers)
        )

    async def validate_consent_request(self, request: Request):
        request = await self.create_oauth2_request(request)
        grant = self.get_authorization_grant(request)

        await grant.validate_consent_request()
        if not hasattr(grant, "prompt"):
            grant.prompt = None
        return grant

    @property
    def auth_methods(self):
        return self._client_auth.methods()

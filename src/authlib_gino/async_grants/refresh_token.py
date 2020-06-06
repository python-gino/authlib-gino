"""
Partially copied from authlib/oauth2/rfc6749/grants/refresh_token.py
"""
import logging

from authlib.oauth2.rfc6749 import UnauthorizedClientError, InvalidRequestError
from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant

from .base import BaseGrant

log = logging.getLogger(__name__)


class RefreshTokenGrant(BaseGrant, _RefreshTokenGrant):
    async def validate_token_request(self):
        client = await self._validate_request_client()
        self.request.client = client
        token = await self._validate_request_token(client)
        self._validate_token_scope(token)
        self.request.credential = token

    async def _validate_request_client(self):
        # require client authentication for confidential clients or for any
        # client that was issued client credentials (or with other
        # authentication requirements)
        client = await self.authenticate_token_endpoint_client()
        log.debug("Validate token request of %r", client)

        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError()

        return client

    async def _validate_request_token(self, client=None):
        refresh_token = self.request.form.get("refresh_token")
        if refresh_token is None:
            raise InvalidRequestError('Missing "refresh_token" in request.',)

        token = await self.authenticate_refresh_token(refresh_token)
        if not token or token.get_client_id() != client.get_client_id():
            raise InvalidRequestError('Invalid "refresh_token" in request.',)
        return token

    async def create_token_response(self):
        credential = self.request.credential
        user = await self.authenticate_user(credential)
        if not user:
            raise InvalidRequestError('There is no "user" for this token.')

        client = self.request.client
        token = await self.issue_token(client, user, credential)
        log.debug("Issue token %r to %r", token, client)

        self.request.user = user
        await self.save_token(token)
        await self.execute_hook("process_token", token=token)
        await self.revoke_old_credential(credential)
        return 200, token, self.TOKEN_RESPONSE_HEADER

    async def issue_token(self, client, user, credential):
        expires_in = credential.get_expires_in()
        scope = self.request.scope
        if not scope:
            scope = credential.get_scope()

        token = await self.generate_token(
            client,
            self.GRANT_TYPE,
            user=user,
            expires_in=expires_in,
            scope=scope,
            include_refresh_token=self.INCLUDE_NEW_REFRESH_TOKEN,
        )
        return token

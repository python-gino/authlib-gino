"""
Partially copied from authlib/oauth2/rfc6749/grants/authorization_code.py
"""
import logging

from authlib.common.urls import add_params_to_uri
from authlib.oauth2.rfc6749 import (
    InvalidClientError,
    OAuth2Error,
    UnauthorizedClientError,
    AccessDeniedError,
    InvalidRequestError,
)
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)

from .base import BaseGrant

log = logging.getLogger(__name__)


class AuthorizationCodeGrant(BaseGrant, _AuthorizationCodeGrant):
    async def validate_consent_request(self):
        redirect_uri = await self.validate_authorization_request()
        await self.execute_hook("after_validate_consent_request", redirect_uri)

    async def validate_authorization_request(self):
        return await validate_code_authorization_request(self)

    async def create_authorization_response(self, redirect_uri, grant_user):
        state = self.request.state
        if grant_user:
            self.request.user = grant_user

            code = self.generate_authorization_code()
            await self.save_authorization_code(code, self.request)

            params = [("code", code)]
            if state:
                params.append(("state", state))
            uri = add_params_to_uri(redirect_uri, params)
            headers = [('Location', uri)]
            return 302, '', headers

        else:
            raise AccessDeniedError(state=state, redirect_uri=redirect_uri)

    async def validate_token_request(self):
        client = await self.authenticate_token_endpoint_client()

        log.debug("Validate token request of %r", client)
        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError()

        code = self.request.form.get("code")
        if code is None:
            raise InvalidRequestError('Missing "code" in request.')

        # ensure that the authorization code was issued to the authenticated
        # confidential client, or if the client is public, ensure that the
        # code was issued to "client_id" in the request
        authorization_code = await self.query_authorization_code(code, client)
        if not authorization_code:
            raise InvalidRequestError('Invalid "code" in request.')

        # validate redirect_uri parameter
        log.debug("Validate token redirect_uri of %r", client)
        redirect_uri = self.request.redirect_uri
        original_redirect_uri = authorization_code.get_redirect_uri()
        if original_redirect_uri and redirect_uri != original_redirect_uri:
            raise InvalidRequestError('Invalid "redirect_uri" in request.')

        # save for create_token_response
        self.request.client = client
        self.request.credential = authorization_code
        await self.execute_hook("after_validate_token_request")

    async def create_token_response(self):
        client = self.request.client
        authorization_code = self.request.credential

        user = await self.authenticate_user(authorization_code)
        if not user:
            raise InvalidRequestError('There is no "user" for this code.')

        scope = authorization_code.get_scope()
        token = await self.generate_token(
            client,
            self.GRANT_TYPE,
            user=user,
            scope=client.get_allowed_scope(scope),
            include_refresh_token=client.check_grant_type("refresh_token"),
        )
        log.debug("Issue token %r to %r", token, client)

        self.request.user = user
        await self.save_token(token)
        await self.execute_hook("process_token", token=token)
        await self.delete_authorization_code(authorization_code)
        return 200, token, self.TOKEN_RESPONSE_HEADER


async def validate_code_authorization_request(grant):
    client_id = grant.request.client_id
    log.debug("Validate authorization request of %r", client_id)

    if client_id is None:
        raise InvalidClientError(state=grant.request.state)

    client = await grant.server.query_client(client_id)
    if not client or not client.is_active:
        raise InvalidClientError(state=grant.request.state)

    redirect_uri = grant.validate_authorization_redirect_uri(grant.request, client)
    response_type = grant.request.response_type
    if not client.check_response_type(response_type):
        raise UnauthorizedClientError(
            "The client is not authorized to use "
            '"response_type={}"'.format(response_type),
            state=grant.request.state,
            redirect_uri=redirect_uri,
        )

    try:
        grant.request.client = client
        grant.validate_requested_scope()
        await grant.execute_hook("after_validate_authorization_request")
    except OAuth2Error as error:
        error.redirect_uri = redirect_uri
        raise error
    return redirect_uri

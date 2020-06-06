import logging

from authlib.oauth2.rfc6749 import OAuth2Error
from fastapi import FastAPI, APIRouter, Security, Request, Form, Query
from starlette.responses import JSONResponse

from .api import (
    AUTHORIZATION_ENDPOINT,
    TOKEN_ENDPOINT,
    OPENID_CONFIGURATION_ENDPOINT,
    USERINFO_ENDPOINT,
    JWKS_URI,
    auth,
    current_user,
    metadata,
)
from ..fastapi_session import config
from ..fastapi_session.models import User

log = logging.getLogger(__name__)
router = APIRouter()


@router.get(OPENID_CONFIGURATION_ENDPOINT, summary="OpenID Configuration")
def openid_configuration():
    return metadata


@router.get(JWKS_URI, summary="JWK keys")
def jwks():
    return dict(keys=[config.JWT_PUBLIC_KEY])


# noinspection PyUnusedLocal
@router.get(AUTHORIZATION_ENDPOINT)
async def authorization_endpoint(
    request: Request,
    scope: str = Query(
        ...,
        description='OpenID Connect requests MUST contain the "openid" scope value. '
        "If the openid scope value is not present, the behavior is entirely "
        "unspecified. Other scope values MAY be present. Scope values used that are "
        "not understood will be ignored.",
        regex=r"\bopenid\b",
    ),
    response_type: str = Query(
        ...,
        description="OAuth 2.0 Response Type value that determines the authorization "
        "processing flow to be used, including what parameters are returned from the "
        "endpoints used. Because only the Authorization Code Flow is supported, this "
        'value MUST be "code".',
        regex=r"^code$",
    ),
    client_id: str = Query(
        ...,
        description="OAuth 2.0 Client Identifier valid at the Authorization Server.",
    ),
    redirect_uri: str = Query(
        ...,
        description="Redirection URI to which the response will be sent. This URI MUST "
        "exactly match one of the Redirection URI values for the Client pre-registered "
        "at the OpenID Provider. The Redirection URI MAY use an alternate scheme, such "
        "as one that is intended to identify a callback into a native application.",
    ),
    state: str = Query(
        None,
        description="RECOMMENDED. Opaque value used to maintain state between the "
        "request and the callback. Typically, Cross-Site Request Forgery (CSRF, XSRF) "
        "mitigation is done by cryptographically binding the value of this parameter "
        "with a browser cookie.",
    ),
    nonce: str = Query(
        None,
        description="OPTIONAL. String value used to associate a Client session with "
        "an ID Token, and to mitigate replay attacks. The value is passed through "
        "unmodified from the Authentication Request to the ID Token. Sufficient "
        "entropy MUST be present in the nonce values used to prevent attackers from "
        "guessing values.",
    ),
    code_challenge: str = Query(
        None,
        description="A PKCE (RFC7636) challenge derived from the code verifier to be "
        "verified against later.",
    ),
    code_challenge_method: str = Query(
        None, description="A method that was used to derive code challenge."
    ),
):
    """
    The Authorization Endpoint performs Authentication of the End-User. This is done by
    sending the User Agent to the Authorization Server's Authorization Endpoint for
    Authentication and Authorization, using request parameters defined by OAuth 2.0 and
    additional parameters and parameter values defined by OpenID Connect.
    """
    if config.DEBUG and config.USE_DEMO_LOGIN:
        from .demo_login import confirm_login

        return await confirm_login(request)

    try:
        grant = await auth.validate_consent_request(request)
        return dict(
            scope=grant.request.scope,
            hint="Replace 'authorize' with 'login' in URL to continue",
        )
    except OAuth2Error as error:
        return JSONResponse(dict(error.get_body()), status_code=error.status_code)


# noinspection PyUnusedLocal
@router.post(TOKEN_ENDPOINT)
async def token_endpoint(
    request: Request,
    nonce: str = None,
    grant_type: str = Form(
        ...,
        description='Value MUST be one of "authorization_code" or "refresh_token".',
        regex="^(authorization_code|refresh_token)$",
    ),
    refresh_token: str = Form(
        None, description="The refresh token issued to the client."
    ),
    code: str = Form(
        None,
        description="The authorization code received from the authorization server. "
        'Required if "grant_type" is "authorization_code".',
    ),
    redirect_uri: str = Form(
        None,
        description='Its values MUST be identical as the "redirect_uri" parameter '
        "included in the authorization request. "
        'Required if "grant_type" is "authorization_code".',
    ),
    client_id: str = Form(
        None,
        description='Required if "grant_type" is "authorization_code" for '
        "confidential clients only.",
    ),
    client_secret: str = Form(
        None,
        description='Required if "grant_type" is "authorization_code". for '
        "confidential clients only",
    ),
    code_verifier: str = Form(
        None,
        description="A cryptographically random string that is used to correlate the "
        "authorization request to the token request.",
    ),
):
    """
    The token endpoint is used by the client to obtain an access token by
    presenting its authorization grant or refresh token.
    """
    return await auth.create_token_response(request)


@router.get(USERINFO_ENDPOINT, summary="UserInfo Endpoint. Login required.")
async def userinfo(user: User = Security(current_user)):
    """
    Protected Resource that, when presented with an Access Token by the Client, returns
    authorized information about the End-User represented by the corresponding
    Authorization Grant.
    """
    user = await user.query.gino.first()
    return user.to_dict()


def init_app(app: FastAPI):
    app.swagger_ui_init_oauth = {
        "clientId": "cli:swagger-ui",
        "usePkceWithAuthorizationCodeGrant": True,
        "additionalQueryStringParams": dict(nonce="public-nonce"),
    }
    app.include_router(router, tags=["OpenID Connect"])

"""
Partially copied from authlib/oidc/core/grants/code.py
"""
import logging

from authlib.oauth2.rfc6749 import InvalidRequestError
from authlib.oidc.core import OpenIDCode as _OpenIDCode

log = logging.getLogger(__name__)


class OpenIDCode(_OpenIDCode):
    async def validate_openid_authorization_request(self, grant):
        await validate_nonce(grant.request, self.exists_nonce, self.require_nonce)


async def validate_nonce(request, exists_nonce, required):
    nonce = request.data.get("nonce")
    if not nonce:
        if required:
            raise InvalidRequestError('Missing "nonce" in request.')
        return True

    if await exists_nonce(nonce, request):
        raise InvalidRequestError("Replay attack")

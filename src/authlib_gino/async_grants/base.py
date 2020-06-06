"""
Partially copied from authlib/oauth2/rfc6749/grants/base.py
"""
from authlib.oauth2.rfc6749.grants import BaseGrant as _BaseGrant


class BaseGrant(_BaseGrant):
    async def authenticate_token_endpoint_client(self):
        client = await self.server.authenticate_client(
            self.request, self.TOKEN_ENDPOINT_AUTH_METHODS
        )
        self.server.send_signal("after_authenticate_client", client=client, grant=self)
        return client

    async def execute_hook(self, hook_type, *args, **kwargs):
        for hook in self._hooks[hook_type]:
            coro = hook(self, *args, **kwargs)
            if hasattr(coro, "__await__"):
                await coro

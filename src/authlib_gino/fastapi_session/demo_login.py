import time

from fastapi import Depends
from starlette.requests import Request

from .api import auth, login_context
from .models import Identity
from .models import db
from ..fastapi_session.models import User


async def demo_login(request: Request, context=Depends(login_context)):
    # request should contain all parameters in AUTHORIZATION_ENDPOINT
    user = await (
        Identity.outerjoin(User)
        .select()
        .where(Identity.sub == "demo")
        .where(Identity.idp == "demo")
        .gino.load(User.load(current_identity=Identity))
        .first()
    )
    if user is None:
        async with db.transaction():
            user = await User.create(
                created_at=int(time.time()), profile='{"name": "demo"}'
            )
            user.current_identity = await Identity.create(
                sub="demo", idp="demo", user_id=user.id, created_at=user.created_at,
            )
    return await auth.create_authorization_response(request, user, context)

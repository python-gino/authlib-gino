import time

from fastapi import APIRouter, Security, FastAPI, HTTPException, Depends
from starlette.status import HTTP_404_NOT_FOUND

from .api import current_user, current_scopes
from .models import db
from ..fastapi_session import config
from ..fastapi_session.models import BearerToken, Session

router = APIRouter()


def sessions_query(scopes: set = Security(current_scopes), user=Security(current_user)):
    rv = (
        BearerToken.outerjoin(Session)
        .select()
        .where(BearerToken.revoked_at.is_(None))
        .where(
            Session.created_at + (config.SESSION_TTL * 3600 * 24) > db.bindparam("now")
        )
        .where(Session.terminated_at.is_(None))
    )
    if "admin" not in scopes:
        rv = rv.where(Session.user_id == user.id)
    return rv.execution_options(loader=Session.distinct().load(add_token=BearerToken))


@router.get("/sessions", summary="List all active sessions.")
async def sessions(query=Depends(sessions_query)):
    """
    List all active sessions for all users if we have admin permission, or list only for
    the current user.
    """
    rv = []
    for session in await (
        query.order_by(Session.user_id, Session.created_at.desc()).gino.all(
            now=int(time.time())
        )
    ):
        s = session.to_dict()
        s["tokens"] = [t.to_dict() for t in session.tokens]
        rv.append(s)
    return rv


@router.delete("/sessions", summary="Delete all active sessions.")
async def kill_all_sessions(query=Depends(sessions_query)):
    """
    Terminate all active sessions for all users if we have admin permission,
    or terminate only for the current user.
    """
    updates = (
        Session.update.values(terminated_at=db.bindparam("now"))
        .where(Session.id.in_(query.with_only_columns([Session.id]).alias()))
        .returning(Session.id)
        .cte("updates")
    )
    num = await db.func.count(updates.c.id).gino.scalar(now=int(time.time()))
    return dict(success=True, num_of_sessions=num)


@router.delete("/sessions/{session_id}", summary="Terminate a given session.")
async def kill_session(session_id: str, query=Depends(sessions_query)):
    """
    Admin user could terminate any user's session, normal user are limited to his own
    sessions.
    """
    session = await (
        query.where(Session.id == session_id)
        .order_by((BearerToken.issued_at + BearerToken.expires_in).desc())
        .gino.first(now=int(time.time()))
    )
    if not session:
        raise HTTPException(HTTP_404_NOT_FOUND, "No such active session")

    await session.update(terminated_at=int(time.time())).apply()
    return dict(
        success=True,
        ttl=int(
            session.tokens[0].issued_at + session.tokens[0].expires_in - time.time()
        ),
    )


def init_app(app: FastAPI):
    app.include_router(router, tags=["Session Management"])

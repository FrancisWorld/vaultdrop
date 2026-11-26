from typing import Annotated

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field

from ..deps import SESSION_COOKIE, ContainerDep, CurrentUser, SessionToken, client_source

router = APIRouter(prefix="/v1/auth", tags=["auth"])

Username = Annotated[str, Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")]


class Credentials(BaseModel):
    username: Username
    password: str = Field(min_length=12, max_length=256)


class Identity(BaseModel):
    user_id: str
    username: str


def _set_cookie(response: Response, container: ContainerDep, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=container.settings.cookie_secure,
        max_age=container.settings.session_ttl_seconds,
        path="/",
    )


@router.post("/register", response_model=Identity)
def register(body: Credentials, response: Response, container: ContainerDep) -> Identity:
    user, token = container.accounts.register(body.username, body.password)
    _set_cookie(response, container, token)
    return Identity(user_id=user.id, username=user.username)


@router.post("/login", response_model=Identity)
def login(
    body: Credentials, request: Request, response: Response, container: ContainerDep
) -> Identity:
    user, token = container.accounts.login(body.username, body.password, client_source(request))
    _set_cookie(response, container, token)
    return Identity(user_id=user.id, username=user.username)


@router.post("/logout")
def logout(
    response: Response, container: ContainerDep, token: SessionToken = None
) -> dict[str, str]:
    container.accounts.logout(token)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"status": "logged out"}


@router.get("/me", response_model=Identity)
def me(user: CurrentUser) -> Identity:
    return Identity(user_id=user.id, username=user.username)

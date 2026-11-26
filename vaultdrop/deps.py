from typing import Annotated

from fastapi import Cookie, Depends, Request

from .auth import authenticate
from .container import Container
from .models import User

SESSION_COOKIE = "vaultdrop_session"


def get_container(request: Request) -> Container:
    container: Container = request.app.state.container
    return container


ContainerDep = Annotated[Container, Depends(get_container)]
SessionToken = Annotated[str | None, Cookie(alias=SESSION_COOKIE)]


def current_user(container: ContainerDep, token: SessionToken = None) -> User:
    with container.database.session() as db:
        return authenticate(db, token)


CurrentUser = Annotated[User, Depends(current_user)]


def client_source(request: Request) -> str:
    return request.client.host if request.client else "unknown"

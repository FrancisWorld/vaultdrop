from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from ..deps import ContainerDep, client_source

router = APIRouter(prefix="/v1/shares", tags=["shares"])


class RedeemRequest(BaseModel):
    token: str = Field(min_length=20, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    password: str | None = Field(default=None, max_length=256)


class RedeemResponse(BaseModel):
    download_url: str
    filename: str
    size_bytes: int


@router.post("/redeem", response_model=RedeemResponse)
def redeem(body: RedeemRequest, request: Request, container: ContainerDep) -> RedeemResponse:
    result = container.shares.redeem(body.token, body.password, client_source(request))
    return RedeemResponse(
        download_url=result.download_url, filename=result.filename, size_bytes=result.size_bytes
    )

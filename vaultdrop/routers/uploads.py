import datetime as dt
from typing import Annotated, Any

from fastapi import APIRouter, Header
from pydantic import BaseModel, Field, field_validator

from ..deps import ContainerDep, CurrentUser
from ..planning import MIN_PART_SIZE
from ..s3 import is_safe_filename
from ..services.uploads import PartRef

router = APIRouter(prefix="/v1/uploads", tags=["uploads"])

MAX_UPLOAD_BYTES = 5 * 1024**3
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class InitiateRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(gt=0, le=MAX_UPLOAD_BYTES)
    sha256: Sha256 | None = None
    part_size: int = Field(default=8 * 1024 * 1024, ge=MIN_PART_SIZE, le=100 * 1024 * 1024)

    @field_validator("filename")
    @classmethod
    def safe_filename(cls, value: str) -> str:
        if not is_safe_filename(value):
            raise ValueError("filename must not contain control characters or path separators")
        return value


class PartUrl(BaseModel):
    part_number: int
    url: str


class Ticket(BaseModel):
    upload_id: str
    part_size: int
    part_count: int
    expires_at: dt.datetime
    urls: list[PartUrl]


class PartBody(BaseModel):
    part_number: int = Field(ge=1, le=10000)
    etag: str = Field(min_length=1, max_length=255)


class CompleteRequest(BaseModel):
    parts: list[PartBody] = Field(min_length=1, max_length=10000)


class RecordPartRequest(BaseModel):
    etag: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(gt=0)
    sha256: Sha256


@router.post("", response_model=Ticket)
def initiate(
    body: InitiateRequest,
    user: CurrentUser,
    container: ContainerDep,
    idempotency_key: Annotated[str | None, Header(min_length=1, max_length=128)] = None,
) -> Ticket:
    ticket = container.uploads.initiate(
        user.id,
        filename=body.filename,
        size_bytes=body.size_bytes,
        sha256=body.sha256,
        part_size=body.part_size,
        idempotency_key=idempotency_key,
    )
    return Ticket(
        upload_id=ticket.upload_id,
        part_size=ticket.part_size,
        part_count=ticket.part_count,
        expires_at=ticket.expires_at,
        urls=[PartUrl(**item) for item in ticket.urls],
    )


@router.get("/{upload_id}")
def status(upload_id: str, user: CurrentUser, container: ContainerDep) -> dict[str, Any]:
    view = container.uploads.status(user.id, upload_id)
    return {
        "upload_id": view.upload_id,
        "status": view.status,
        "part_size": view.part_size,
        "part_count": view.part_count,
        "recorded_parts": [
            {
                "part_number": p.part_number,
                "etag": p.etag,
                "size_bytes": p.size_bytes,
                "sha256": p.sha256,
            }
            for p in view.recorded
        ],
        "stored_parts": [
            {
                "part_number": int(p["PartNumber"]),
                "etag": str(p["ETag"]).strip('"'),
                "size_bytes": int(p["Size"]),
            }
            for p in view.stored
        ],
        "pending_urls": view.pending_urls,
    }


@router.post("/{upload_id}/parts/{part_number}")
def record_part(
    upload_id: str,
    part_number: int,
    body: RecordPartRequest,
    user: CurrentUser,
    container: ContainerDep,
) -> dict[str, str]:
    created = container.uploads.record_part(
        user.id, upload_id, part_number, body.etag, body.size_bytes, body.sha256
    )
    return {"status": "recorded" if created else "already-recorded"}


@router.post("/{upload_id}/complete")
def complete(
    upload_id: str, body: CompleteRequest, user: CurrentUser, container: ContainerDep
) -> dict[str, str | int]:
    record = container.uploads.complete(
        user.id, upload_id, [PartRef(p.part_number, p.etag) for p in body.parts]
    )
    return {"file_id": record.id, "sha256": record.sha256, "size_bytes": record.size_bytes}


@router.delete("/{upload_id}", status_code=204)
def abort(upload_id: str, user: CurrentUser, container: ContainerDep) -> None:
    container.uploads.abort(user.id, upload_id)


@router.post("/expired/sweep")
def sweep(user: CurrentUser, container: ContainerDep) -> dict[str, int]:
    return {"aborted": container.uploads.sweep_expired(user.id)}

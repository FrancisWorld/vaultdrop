from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from ..deps import ContainerDep, CurrentUser

router = APIRouter(tags=["files"])


class ShareRequest(BaseModel):
    password: str | None = Field(default=None, min_length=1, max_length=256)
    expires_in_seconds: int | None = Field(default=None, ge=60, le=30 * 86400)
    max_downloads: int | None = Field(default=None, ge=1, le=100_000)


@router.get("/v1/files")
def list_files(user: CurrentUser, container: ContainerDep) -> list[dict[str, Any]]:
    return [
        {
            "id": f.id,
            "filename": f.filename,
            "size_bytes": f.size_bytes,
            "sha256": f.sha256,
            "created_at": f.created_at.isoformat(),
        }
        for f in container.files.list(user.id)
    ]


@router.delete("/v1/files/{file_id}", status_code=204)
def delete_file(file_id: str, user: CurrentUser, container: ContainerDep) -> None:
    container.files.delete(user.id, file_id)


@router.post("/v1/files/{file_id}/shares")
def create_share(
    file_id: str, body: ShareRequest, user: CurrentUser, container: ContainerDep
) -> dict[str, str]:
    token, share = container.shares.create(
        user.id,
        file_id,
        password=body.password,
        expires_in_seconds=body.expires_in_seconds,
        max_downloads=body.max_downloads,
    )
    return {"share_id": share.id, "token": token, "path": f"/s/{token}"}


@router.get("/v1/shares")
def list_shares(user: CurrentUser, container: ContainerDep) -> list[dict[str, Any]]:
    return [
        {
            "id": s.id,
            "file_id": s.file_id,
            "expires_at": s.expires_at.isoformat() if s.expires_at else None,
            "downloads": s.downloads,
            "max_downloads": s.max_downloads,
            "password_protected": s.password_hash is not None,
        }
        for s in container.shares.list(user.id)
    ]


@router.delete("/v1/shares/{share_id}", status_code=204)
def revoke_share(share_id: str, user: CurrentUser, container: ContainerDep) -> None:
    container.shares.revoke(user.id, share_id)

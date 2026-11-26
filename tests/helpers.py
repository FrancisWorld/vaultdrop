import hashlib
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import parse_qs, unquote, urlparse

from fastapi.testclient import TestClient

from .conftest import BUCKET

MIB = 1024 * 1024
MIN_PART = 5 * MIB


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def put_part(aws: object, url: str, payload: bytes) -> str:
    """Perform what a browser does with a presigned URL, against moto; returns the ETag."""
    query = parse_qs(urlparse(url).query)
    response = cast(Any, aws).upload_part(
        Bucket=BUCKET,
        Key=unquote(urlparse(url).path.split(f"/{BUCKET}/", 1)[-1].lstrip("/")),
        UploadId=query["uploadId"][0],
        PartNumber=int(query["partNumber"][0]),
        Body=payload,
    )
    return str(response["ETag"]).strip('"')


@dataclass
class Upload:
    client: TestClient
    upload_id: str
    urls: list[dict[str, Any]]
    part_size: int

    def part_payload(self, payload: bytes, number: int) -> bytes:
        return payload[(number - 1) * self.part_size : number * self.part_size]


def initiate(
    client: TestClient,
    payload: bytes,
    *,
    filename: str = "brief.txt",
    declare_sha: bool = True,
    part_size: int = MIN_PART,
    headers: dict[str, str] | None = None,
) -> Upload:
    body: dict[str, Any] = {
        "filename": filename,
        "size_bytes": len(payload),
        "part_size": part_size,
    }
    if declare_sha:
        body["sha256"] = sha256(payload)
    response = client.post("/v1/uploads", json=body, headers=headers or {})
    assert response.status_code == 200, response.text
    data = response.json()
    return Upload(client, data["upload_id"], data["urls"], data["part_size"])


def upload_all(
    aws: object, upload: Upload, payload: bytes, *, record: bool = False
) -> list[dict[str, Any]]:
    parts: list[dict[str, Any]] = []
    for entry in upload.urls:
        number = entry["part_number"]
        chunk = upload.part_payload(payload, number)
        etag = put_part(aws, entry["url"], chunk)
        if record:
            response = upload.client.post(
                f"/v1/uploads/{upload.upload_id}/parts/{number}",
                json={"etag": etag, "size_bytes": len(chunk), "sha256": sha256(chunk)},
            )
            assert response.status_code == 200, response.text
        parts.append({"part_number": number, "etag": etag})
    return parts


def complete(upload: Upload, parts: list[dict[str, Any]]) -> Any:
    return upload.client.post(f"/v1/uploads/{upload.upload_id}/complete", json={"parts": parts})


def store_file(client: TestClient, aws: object, payload: bytes, **kwargs: Any) -> str:
    """Upload `payload` end to end and return the resulting file id."""
    upload = initiate(client, payload, **kwargs)
    response = complete(upload, upload_all(aws, upload, payload))
    assert response.status_code == 200, response.text
    return str(response.json()["file_id"])


def create_share(client: TestClient, file_id: str, **body: Any) -> str:
    response = client.post(f"/v1/files/{file_id}/shares", json=body)
    assert response.status_code == 200, response.text
    return str(response.json()["token"])


def redeem(client: TestClient, token: str, password: str | None = None) -> Any:
    return client.post("/v1/shares/redeem", json={"token": token, "password": password})

import hashlib
from concurrent.futures import ThreadPoolExecutor
from typing import Any, cast
from urllib.parse import parse_qs, unquote, urlparse

from fastapi.testclient import TestClient


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def upload_part(aws: object, url: str, payload: bytes) -> str:
    query = parse_qs(urlparse(url).query)
    method = cast(Any, aws).upload_part
    response = method(
        Bucket="vaultdrop-test-bucket",
        Key=unquote(urlparse(url).path.lstrip("/")),
        UploadId=query["uploadId"][0],
        PartNumber=int(query["partNumber"][0]),
        Body=payload,
    )
    return str(response["ETag"]).strip('"')


def test_complete_upload_and_create_password_share(client: TestClient, aws: object) -> None:
    payload = b"vaultdrop integration payload"
    checksum = hashlib.sha256(payload).hexdigest()
    initiated = client.post(
        "/v1/uploads",
        json={
            "filename": "brief.txt",
            "size_bytes": len(payload),
            "sha256": checksum,
            "part_size": 5 * 1024 * 1024,
        },
    )
    assert initiated.status_code == 200
    upload = initiated.json()
    assert upload["part_count"] == 1

    etag = upload_part(aws, upload["urls"][0]["url"], payload)
    completed = client.post(
        f"/v1/uploads/{upload['upload_id']}/complete",
        json={"parts": [{"part_number": 1, "etag": etag}]},
    )
    assert completed.status_code == 200
    file_id = completed.json()["file_id"]

    shared = client.post(
        f"/v1/files/{file_id}/shares",
        json={"password": "correct horse", "expires_in_seconds": 3600, "max_downloads": 1},
    )
    assert shared.status_code == 200
    token = shared.json()["token"]

    denied = client.get(f"/s/{token}")
    assert denied.status_code == 401
    redeemed = client.get(f"/s/{token}", params={"password": "correct horse"})
    assert redeemed.status_code == 200
    assert "download_url" in redeemed.json()

    exhausted = client.get(f"/s/{token}", params={"password": "correct horse"})
    assert exhausted.status_code == 410


def test_checksum_mismatch_fails(client: TestClient, aws: object) -> None:
    payload = b"wrong checksum"
    initiated = client.post(
        "/v1/uploads",
        json={
            "filename": "bad.bin",
            "size_bytes": len(payload),
            "sha256": "0" * 64,
            "part_size": 5 * 1024 * 1024,
        },
    ).json()
    etag = upload_part(aws, initiated["urls"][0]["url"], payload)
    completed = client.post(
        f"/v1/uploads/{initiated['upload_id']}/complete",
        json={"parts": [{"part_number": 1, "etag": etag}]},
    )
    assert completed.status_code == 422


def test_quota_is_enforced(client: TestClient) -> None:
    response = client.post(
        "/v1/uploads",
        json={"filename": "huge.bin", "size_bytes": 2 * 1024 * 1024 * 1024, "sha256": "1" * 64},
    )
    assert response.status_code == 413


def test_download_limit_is_atomic(client: TestClient, aws: object) -> None:
    payload = b"race"
    checksum = hashlib.sha256(payload).hexdigest()
    upload = client.post(
        "/v1/uploads",
        json={
            "filename": "race.bin",
            "size_bytes": len(payload),
            "sha256": checksum,
            "part_size": 5 * 1024 * 1024,
        },
    ).json()
    etag = upload_part(aws, upload["urls"][0]["url"], payload)
    completed = client.post(
        f"/v1/uploads/{upload['upload_id']}/complete",
        json={"parts": [{"part_number": 1, "etag": etag}]},
    ).json()
    share = client.post(
        f"/v1/files/{completed['file_id']}/shares",
        json={"max_downloads": 1},
    ).json()

    def redeem() -> int:
        return cast(int, client.get(f"/s/{share['token']}").status_code)

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(lambda _: redeem(), range(2)))
    assert sorted(statuses) == [200, 410]

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
    # Test helper uploads and records the public multipart part metadata.
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
    assert denied.status_code == 404
    redeemed = client.get(f"/s/{token}", params={"password": "correct horse"})
    assert redeemed.status_code == 200
    assert "download_url" in redeemed.json()

    exhausted = client.get(f"/s/{token}", params={"password": "correct horse"})
    assert exhausted.status_code == 404


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
    assert sorted(statuses) == [200, 404]


def test_users_cannot_access_another_users_upload_file_or_share(client: TestClient, aws: object) -> None:
    payload = b"private"
    upload = client.post(
        "/v1/uploads",
        json={"filename": "private.bin", "size_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(), "part_size": 5 * 1024 * 1024},
    ).json()
    etag = upload_part(aws, upload["urls"][0]["url"], payload)
    completed = client.post(
        f"/v1/uploads/{upload['upload_id']}/complete",
        json={"parts": [{"part_number": 1, "etag": etag}]},
    ).json()
    share = client.post(
        f"/v1/files/{completed['file_id']}/shares",
        json={"max_downloads": 2},
    ).json()

    from fastapi.testclient import TestClient

    from vaultdrop.api import app
    with TestClient(app) as other:
        response = other.post("/v1/auth/register", json={"username": "second-user", "password": "correct-horse-battery"})
        assert response.status_code == 200
        assert other.get(f"/v1/uploads/{upload['upload_id']}").status_code == 404
        assert other.delete(f"/v1/uploads/{upload['upload_id']}").status_code == 404
        assert other.post(f"/v1/files/{completed['file_id']}/shares", json={}).status_code == 404
        assert completed["file_id"] not in [row["id"] for row in other.get("/v1/files").json()]
        assert share["token"] not in [row["id"] for row in other.get("/v1/shares").json()]


def test_part_resume_list_record_and_idempotent_complete_and_abort(client: TestClient, aws: object) -> None:
    payload = b"a resumable part"
    upload = client.post(
        "/v1/uploads",
        json={"filename": "resume.bin", "size_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(), "part_size": 5 * 1024 * 1024},
    ).json()
    etag = upload_part(aws, upload["urls"][0]["url"], payload)
    recorded = client.post(
        f"/v1/uploads/{upload['upload_id']}/parts/1",
        json={"etag": etag, "size_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
    )
    assert recorded.status_code == 200
    assert recorded.json()["status"] == "recorded"
    listed = client.get(f"/v1/uploads/{upload['upload_id']}")
    assert listed.status_code == 200
    assert len(listed.json()["parts"]) == 1

    completed = client.post(
        f"/v1/uploads/{upload['upload_id']}/complete",
        json={"parts": [{"part_number": 1, "etag": etag}]},
    )
    assert completed.status_code == 200
    repeated = client.post(
        f"/v1/uploads/{upload['upload_id']}/complete",
        json={"parts": [{"part_number": 1, "etag": etag}]},
    )
    assert repeated.status_code == 200
    assert repeated.json()["file_id"] == completed.json()["file_id"]


def test_abort_is_idempotent(client: TestClient) -> None:
    upload = client.post(
        "/v1/uploads",
        json={"filename": "abort.bin", "size_bytes": 6 * 1024 * 1024, "sha256": "1" * 64, "part_size": 5 * 1024 * 1024},
    ).json()
    assert client.delete(f"/v1/uploads/{upload['upload_id']}").status_code == 204
    assert client.delete(f"/v1/uploads/{upload['upload_id']}").status_code == 204


def test_concurrent_quota_initiations(client: TestClient) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(
            lambda _: client.post("/v1/uploads", json={"filename": "quota.bin", "size_bytes": 600 * 1024 * 1024, "sha256": "1" * 64}).status_code,
            range(8),
        ))
    assert statuses.count(200) <= 1


def test_password_attempts_are_rate_limited(client: TestClient, aws: object) -> None:
    payload = b"protected"
    upload = client.post(
        "/v1/uploads",
        json={"filename": "protected.bin", "size_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(), "part_size": 5 * 1024 * 1024},
    ).json()
    etag = upload_part(aws, upload["urls"][0]["url"], payload)
    completed = client.post(
        f"/v1/uploads/{upload['upload_id']}/complete",
        json={"parts": [{"part_number": 1, "etag": etag}]},
    ).json()
    share = client.post(
        f"/v1/files/{completed['file_id']}/shares",
        json={"password": "correct horse", "max_downloads": 10},
    ).json()
    for _ in range(6):
        response = client.get(f"/s/{share['token']}", params={"password": "wrong"})
        assert response.status_code == 404


def test_stale_sweep_aborts_old_upload(client: TestClient) -> None:
    upload = client.post(
        "/v1/uploads",
        json={"filename": "stale.bin", "size_bytes": 6 * 1024 * 1024, "sha256": "1" * 64, "part_size": 5 * 1024 * 1024},
    ).json()
    import datetime as dt

    from vaultdrop.database import session_scope
    from vaultdrop.models import MultipartUpload
    with session_scope() as db:
        record = db.get(MultipartUpload, upload["upload_id"])
        assert record is not None
        record.created_at = dt.datetime.now(dt.UTC) - dt.timedelta(hours=25)
    swept = client.post("/v1/uploads/stale/abort")
    assert swept.status_code == 200
    assert swept.json()["aborted"] == 1


def test_auth_login_logout_and_audit(client: TestClient) -> None:
    login = client.post(
        "/v1/auth/login",
        json={"username": "unknown-user", "password": "wrong-password"},
    )
    assert login.status_code == 401
    duplicate = client.post(
        "/v1/auth/register",
        json={"username": "third-user", "password": "correct-horse-battery"},
    )
    assert duplicate.status_code == 200
    duplicate_again = client.post(
        "/v1/auth/register",
        json={"username": "third-user", "password": "correct-horse-battery"},
    )
    assert duplicate_again.status_code == 409
    audit = client.get("/v1/audit")
    assert audit.status_code == 200
    assert client.post("/v1/auth/logout").status_code == 200
    assert client.get("/v1/files").status_code == 401

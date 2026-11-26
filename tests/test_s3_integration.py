"""Multipart resume against a real S3-compatible server, over real HTTP.

Skipped unless VAULTDROP_TEST_S3_ENDPOINT is set (CI points it at a Garage
container; see .github/workflows/ci.yml). Part uploads are plain HTTP PUTs to
presigned URLs, exactly what the browser does, so no mocking sits between the
API and the storage engine.
"""

import hashlib
import os
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from vaultdrop import migrate
from vaultdrop.api import create_app
from vaultdrop.config import Settings

from .conftest import PASSWORD
from .helpers import MIB, complete, initiate, sha256

ENDPOINT = os.environ.get("VAULTDROP_TEST_S3_ENDPOINT")
ORIGIN = "http://localhost:8000"

pytestmark = [
    pytest.mark.s3_service,
    pytest.mark.skipif(
        not ENDPOINT and os.environ.get("VAULTDROP_REQUIRE_SERVICES") != "1",
        reason="set VAULTDROP_TEST_S3_ENDPOINT to run against a real S3 service",
    ),
]


@pytest.fixture
def real_app(database_url: str) -> FastAPI:
    settings = Settings(
        _env_file=None,
        database_url=database_url,
        s3_bucket=os.environ.get("VAULTDROP_TEST_S3_BUCKET", "vaultdrop-it"),
        s3_endpoint=ENDPOINT,
        s3_public_endpoint=ENDPOINT,
        aws_region=os.environ.get("VAULTDROP_TEST_S3_REGION", "us-east-1"),
        s3_path_style=True,
        s3_bootstrap=True,
        s3_sse=None,
        allowed_origins=ORIGIN,
        cookie_secure=False,
        argon2_memory_kib=1024,
        argon2_time_cost=1,
        sweep_interval_seconds=0,
    )
    migrate.upgrade(database_url)
    return create_app(settings)


@pytest.fixture
def api(real_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(real_app) as client:
        client.post("/v1/auth/register", json={"username": "it-user", "password": PASSWORD})
        yield client


def put(url: str, data: bytes) -> str:
    response = httpx.put(url, content=data, headers={"Origin": ORIGIN}, timeout=60)
    assert response.status_code == 200, response.text
    return response.headers["etag"].strip('"')


def record(client: TestClient, upload_id: str, number: int, etag: str, chunk: bytes) -> None:
    response = client.post(
        f"/v1/uploads/{upload_id}/parts/{number}",
        json={"etag": etag, "size_bytes": len(chunk), "sha256": sha256(chunk)},
    )
    assert response.status_code == 200, response.text


def test_interrupted_upload_resumes_and_downloads_identical_bytes(api: TestClient) -> None:
    payload = os.urandom(11 * MIB)  # parts of 5, 5 and 1 MiB
    upload = initiate(api, payload, declare_sha=False)
    first = payload[: 5 * MIB]
    record(api, upload.upload_id, 1, put(upload.urls[0]["url"], first), first)
    # ... the client now "crashes". A new session resumes from what storage reports:
    status = api.get(f"/v1/uploads/{upload.upload_id}").json()
    assert [p["part_number"] for p in status["stored_parts"]] == [1]
    assert [u["part_number"] for u in status["pending_urls"]] == [2, 3]
    assert [p["part_number"] for p in status["recorded_parts"]] == [1]

    parts: list[dict[str, Any]] = [{"part_number": 1, "etag": status["stored_parts"][0]["etag"]}]
    for entry in status["pending_urls"]:
        number = entry["part_number"]
        chunk = payload[(number - 1) * 5 * MIB : number * 5 * MIB]
        etag = put(entry["url"], chunk)
        record(api, upload.upload_id, number, etag, chunk)
        parts.append({"part_number": number, "etag": etag})
    done = complete(upload, parts)
    assert done.status_code == 200, done.text
    assert done.json()["sha256"] == hashlib.sha256(payload).hexdigest()

    token = api.post(f"/v1/files/{done.json()['file_id']}/shares", json={}).json()["token"]
    redeemed = api.post("/v1/shares/redeem", json={"token": token}).json()
    fetched = httpx.get(redeemed["download_url"], timeout=60)
    assert fetched.status_code == 200 and fetched.content == payload


def test_digest_mismatch_deletes_the_object_from_real_storage(
    api: TestClient, real_app: FastAPI
) -> None:
    payload = b"corrupted on the way up"
    upload = initiate(api, payload)
    etag = put(upload.urls[0]["url"], b"something else entirely")  # wrong length
    bad = complete(upload, [{"part_number": 1, "etag": etag}])
    assert bad.status_code == 422  # storage's part size does not match the plan

    s3 = real_app.state.container.s3

    def object_keys() -> list[str]:
        listing = s3.client.list_objects_v2(Bucket=s3.bucket).get("Contents", [])
        return sorted(o["Key"] for o in listing)

    before = object_keys()
    same_size = initiate(api, payload)
    etag = put(same_size.urls[0]["url"], b"X" * len(payload))
    failed = complete(same_size, [{"part_number": 1, "etag": etag}])
    assert failed.status_code == 422 and "SHA-256" in failed.json()["detail"]
    assert object_keys() == before  # the unverified object is gone
    assert api.get(f"/v1/uploads/{same_size.upload_id}").json()["status"] == "failed"


def test_abort_discards_the_multipart_upload_in_storage(api: TestClient, real_app: FastAPI) -> None:
    upload = initiate(api, os.urandom(6 * MIB))
    put(upload.urls[0]["url"], os.urandom(5 * MIB))
    s3 = real_app.state.container.s3
    assert s3.client.list_multipart_uploads(Bucket=s3.bucket).get("Uploads")
    assert api.delete(f"/v1/uploads/{upload.upload_id}").status_code == 204
    assert not s3.client.list_multipart_uploads(Bucket=s3.bucket).get("Uploads")
    assert api.delete(f"/v1/uploads/{upload.upload_id}").status_code == 204


@pytest.mark.skipif(
    os.environ.get("VAULTDROP_TEST_S3_CORS") != "1", reason="CORS enforcement is storage specific"
)
def test_browser_cors_rules_expose_the_etag(api: TestClient) -> None:
    upload = initiate(api, b"cors")
    url = upload.urls[0]["url"]
    preflight = httpx.options(
        url, headers={"Origin": ORIGIN, "Access-Control-Request-Method": "PUT"}, timeout=30
    )
    assert preflight.headers["access-control-allow-origin"] == ORIGIN
    response = httpx.put(url, content=b"cors", headers={"Origin": ORIGIN}, timeout=30)
    assert "etag" in response.headers["access-control-expose-headers"].lower()

"""Races against the real datastore.

These run on whichever backend `VAULTDROP_TEST_DATABASE_URL` selects (SQLite by
default; CI also runs the whole suite on PostgreSQL, where the row and advisory
locks are what is actually under test).
"""

import threading
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from vaultdrop.models import (
    AttemptLog,
    AuditEvent,
    FileRecord,
    MultipartPart,
    MultipartUpload,
    ShareLink,
    User,
)
from vaultdrop.repositories import user_usage

from .conftest import PASSWORD, db_scalar
from .helpers import MIB, create_share, initiate, put_part, redeem, sha256, store_file, upload_all

MB400 = 400 * MIB


def race(count: int, task: Callable[[int], Any]) -> list[Any]:
    """Run `task` in `count` threads released at the same instant."""
    gate = threading.Barrier(count)

    def run(index: int) -> Any:
        gate.wait(timeout=30)
        return task(index)

    with ThreadPoolExecutor(max_workers=count) as pool:
        return list(pool.map(run, range(count)))


def test_download_limit_is_never_exceeded(client: TestClient, aws: object, app: FastAPI) -> None:
    token = create_share(client, store_file(client, aws, b"race"), max_downloads=5)
    statuses = Counter(race(25, lambda _: redeem(TestClient(app), token).status_code))
    assert statuses == {200: 5, 404: 20}
    assert db_scalar(app, select(ShareLink.downloads)) == 5
    assert (
        db_scalar(
            app, select(func.count(AuditEvent.id)).where(AuditEvent.action == "share.redeemed")
        )
        == 5
    )


def test_password_share_download_limit_under_concurrent_correct_guesses(
    client: TestClient, aws: object, app: FastAPI
) -> None:
    token = create_share(
        client, store_file(client, aws, b"race"), password="correct horse", max_downloads=3
    )
    anonymous = [TestClient(app, client=(f"10.0.0.{i}", 1)) for i in range(12)]
    statuses = Counter(race(12, lambda i: redeem(anonymous[i], token, "correct horse").status_code))
    assert statuses == {200: 3, 404: 9}
    assert db_scalar(app, select(ShareLink.downloads)) == 3


def test_quota_reservations_cannot_overcommit(
    client: TestClient, app: FastAPI, aws: object
) -> None:
    def initiate_big(_: int) -> int:
        return int(
            client.post(
                "/v1/uploads", json={"filename": "big.bin", "size_bytes": MB400}
            ).status_code
        )

    statuses = Counter(race(10, initiate_big))
    assert statuses == {200: 2, 413: 8}  # 1 GiB quota fits two 400 MiB reservations, never three
    with app.state.container.database.session() as db:
        user_id = db.scalar(select(User.id))
        assert user_id and user_usage(db, user_id) == 2 * MB400
    assert len(aws.list_multipart_uploads(Bucket="vaultdrop-test-bucket").get("Uploads", [])) == 2  # type: ignore[attr-defined]


def test_wrong_password_guesses_are_limited_exactly(
    client: TestClient, aws: object, app: FastAPI
) -> None:
    token = create_share(client, store_file(client, aws, b"race"), password="correct horse")
    attacker = TestClient(app, client=("192.0.2.10", 1))
    statuses = Counter(race(30, lambda _: redeem(attacker, token, "guess").status_code))
    assert statuses == {403: 5, 429: 25}  # the limit holds even when all guesses arrive at once
    assert db_scalar(app, select(func.count(AttemptLog.id))) == 5


def test_login_throttle_holds_under_concurrency(client: TestClient, app: FastAPI) -> None:
    attacker = TestClient(app, client=("192.0.2.20", 1))
    body = {"username": "alice", "password": "wrong-password-1"}
    statuses = Counter(race(20, lambda _: attacker.post("/v1/auth/login", json=body).status_code))
    assert statuses == {401: 5, 429: 15}


def test_concurrent_completion_creates_exactly_one_file(
    client: TestClient, app: FastAPI, aws: object
) -> None:
    payload = b"complete me from many tabs"
    upload = initiate(client, payload)
    parts = upload_all(aws, upload, payload)
    results = race(
        6, lambda _: client.post(f"/v1/uploads/{upload.upload_id}/complete", json={"parts": parts})
    )
    assert [r.status_code for r in results] == [200] * 6
    assert len({r.json()["file_id"] for r in results}) == 1
    assert db_scalar(app, select(func.count(FileRecord.id))) == 1
    assert (
        db_scalar(
            app, select(func.count(AuditEvent.id)).where(AuditEvent.action == "upload.completed")
        )
        == 1
    )


def test_concurrent_initiations_with_one_idempotency_key(client: TestClient, app: FastAPI) -> None:
    body = {"filename": "once.bin", "size_bytes": 1000}
    results = race(
        8, lambda _: client.post("/v1/uploads", json=body, headers={"Idempotency-Key": "k-1"})
    )
    assert [r.status_code for r in results] == [200] * 8
    assert len({r.json()["upload_id"] for r in results}) == 1
    assert db_scalar(app, select(func.count(MultipartUpload.id))) == 1
    assert db_scalar(app, select(func.sum(MultipartUpload.reserved_bytes))) == 1000


def test_concurrent_part_recording_is_idempotent(
    client: TestClient, app: FastAPI, aws: object
) -> None:
    payload = b"one part, many reporters"
    upload = initiate(client, payload, declare_sha=False)
    etag = put_part(aws, upload.urls[0]["url"], payload)
    body = {"etag": etag, "size_bytes": len(payload), "sha256": sha256(payload)}
    results = race(8, lambda _: client.post(f"/v1/uploads/{upload.upload_id}/parts/1", json=body))
    assert [r.status_code for r in results] == [200] * 8
    assert Counter(r.json()["status"] for r in results) == {"recorded": 1, "already-recorded": 7}
    assert db_scalar(app, select(func.count(MultipartPart.id))) == 1


def test_concurrent_registrations_of_one_username(app: FastAPI) -> None:
    def register(_: int) -> int:
        return int(
            TestClient(app)
            .post("/v1/auth/register", json={"username": "highlander", "password": PASSWORD})
            .status_code
        )

    assert Counter(race(8, register)) == {200: 1, 409: 7}


def test_abort_racing_complete_leaves_a_consistent_state(
    client: TestClient, app: FastAPI, aws: object
) -> None:
    payload = b"abort or complete, never both"
    upload = initiate(client, payload)
    parts = upload_all(aws, upload, payload)

    def act(index: int) -> int:
        if index % 2:
            return int(client.delete(f"/v1/uploads/{upload.upload_id}").status_code)
        return int(
            client.post(
                f"/v1/uploads/{upload.upload_id}/complete", json={"parts": parts}
            ).status_code
        )

    race(6, act)
    status = db_scalar(app, select(MultipartUpload.status))
    files = db_scalar(app, select(func.count(FileRecord.id)))
    assert (status, files) in {("complete", 1), ("aborted", 0)}
    reserved = db_scalar(app, select(MultipartUpload.reserved_bytes))
    assert reserved == 0

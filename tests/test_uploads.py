import datetime as dt
import os
from typing import Any, cast

import pytest
from botocore.exceptions import ClientError
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from vaultdrop.models import AuditEvent, FileRecord, MultipartUpload, UploadStatus, User, utcnow
from vaultdrop.repositories import user_usage

from .conftest import BUCKET, db_execute, db_scalar, new_user
from .helpers import MIB, complete, initiate, put_part, sha256, store_file, upload_all

GIB = 1024**3


def usage(app: FastAPI, username: str) -> int:
    with app.state.container.database.session() as db:
        user_id = db.scalar(select(User.id).where(User.username == username))
        assert user_id
        return user_usage(db, user_id)


def set_quota(app: FastAPI, username: str, quota: int) -> None:
    db_execute(app, update(User).where(User.username == username).values(quota_bytes=quota))


def open_uploads(aws: object) -> list[Any]:
    return cast(list[Any], cast(Any, aws).list_multipart_uploads(Bucket=BUCKET).get("Uploads", []))


def test_complete_with_declared_digest_stores_verified_file(
    client: TestClient, aws: object
) -> None:
    payload = os.urandom(11 * MIB)  # 5 + 5 + 1 MiB parts
    upload = initiate(client, payload)
    assert len(upload.urls) == 3
    response = complete(upload, upload_all(aws, upload, payload))
    assert response.status_code == 200
    body = response.json()
    assert body["sha256"] == sha256(payload) and body["size_bytes"] == len(payload)
    listed = client.get("/v1/files").json()
    assert [(f["id"], f["size_bytes"]) for f in listed] == [(body["file_id"], len(payload))]
    stored = cast(Any, aws).get_object(
        Bucket=BUCKET, Key=cast(Any, aws).list_objects_v2(Bucket=BUCKET)["Contents"][0]["Key"]
    )
    assert stored["Body"].read() == payload


def test_object_key_never_contains_the_filename(client: TestClient, aws: object) -> None:
    store_file(client, aws, b"x", filename="secret-plans (final).pdf")
    keys = [o["Key"] for o in cast(Any, aws).list_objects_v2(Bucket=BUCKET)["Contents"]]
    assert all("secret" not in key for key in keys)


def test_resume_lists_stored_parts_and_issues_fresh_urls_for_the_rest(
    client: TestClient, aws: object
) -> None:
    payload = os.urandom(11 * MIB)
    upload = initiate(client, payload)
    put_part(aws, upload.urls[0]["url"], upload.part_payload(payload, 1))  # then the "browser dies"

    status = client.get(f"/v1/uploads/{upload.upload_id}").json()
    assert [p["part_number"] for p in status["stored_parts"]] == [1]
    assert [u["part_number"] for u in status["pending_urls"]] == [2, 3]

    parts = [{"part_number": 1, "etag": status["stored_parts"][0]["etag"]}]
    for entry in status["pending_urls"]:
        etag = put_part(aws, entry["url"], upload.part_payload(payload, entry["part_number"]))
        parts.append({"part_number": entry["part_number"], "etag": etag})
    assert complete(upload, parts).status_code == 200


def test_browser_mode_integrity_from_recorded_part_digests(client: TestClient, aws: object) -> None:
    payload = os.urandom(6 * MIB)
    upload = initiate(client, payload, declare_sha=False)
    parts = upload_all(aws, upload, payload, record=True)
    response = complete(upload, parts)
    assert response.status_code == 200
    assert response.json()["sha256"] == sha256(payload)  # server-attested whole-object digest


def test_complete_requires_some_integrity_data(client: TestClient, aws: object) -> None:
    payload = b"unverifiable"
    upload = initiate(client, payload, declare_sha=False)
    response = complete(upload, upload_all(aws, upload, payload))
    assert response.status_code == 422
    assert "integrity" in response.json()["detail"].lower()


def test_whole_object_digest_mismatch_deletes_object_and_persists_failure(
    client: TestClient, app: FastAPI, aws: object
) -> None:
    payload = b"tampered in transit"
    upload = initiate(client, payload)
    parts = upload_all(aws, upload, payload)
    db_execute(app, update(MultipartUpload).values(sha256="0" * 64))
    response = complete(upload, parts)
    assert response.status_code == 422
    assert "SHA-256" in response.json()["detail"]
    assert cast(Any, aws).list_objects_v2(Bucket=BUCKET).get("KeyCount", 0) == 0
    assert db_scalar(app, select(MultipartUpload.status)) == UploadStatus.FAILED
    assert (
        usage(app, "alice") == 0
    )  # reservation released and the failure survived the error response
    assert complete(upload, parts).status_code == 409
    assert (
        db_scalar(
            app,
            select(func.count(AuditEvent.id)).where(
                AuditEvent.action == "upload.verification_failed"
            ),
        )
        == 1
    )
    assert client.get("/v1/files").json() == []


def test_recorded_part_digest_mismatch_is_caught_at_completion(
    client: TestClient, aws: object
) -> None:
    payload = os.urandom(6 * MIB)
    upload = initiate(client, payload, declare_sha=False)
    parts = upload_all(aws, upload, payload)
    first = upload.part_payload(payload, 1)
    lie = client.post(
        f"/v1/uploads/{upload.upload_id}/parts/1",
        json={
            "etag": parts[0]["etag"],
            "size_bytes": len(first),
            "sha256": sha256(b"something else"),
        },
    )
    assert lie.status_code == 200  # storage confirms the part exists; the digest is only claimed
    second = upload.part_payload(payload, 2)
    client.post(
        f"/v1/uploads/{upload.upload_id}/parts/2",
        json={"etag": parts[1]["etag"], "size_bytes": len(second), "sha256": sha256(second)},
    )
    response = complete(upload, parts)
    assert response.status_code == 422
    assert "part 1" in response.json()["detail"]


def test_oversized_part_is_rejected_but_upload_stays_resumable(
    client: TestClient, aws: object
) -> None:
    payload = os.urandom(5 * MIB + 10)
    upload = initiate(client, payload)
    first_url, last_url = upload.urls[0]["url"], upload.urls[1]["url"]
    bad_etag = put_part(aws, first_url, os.urandom(6 * MIB))  # more than the plan allows
    last_etag = put_part(aws, last_url, payload[5 * MIB :])
    response = complete(
        upload, [{"part_number": 1, "etag": bad_etag}, {"part_number": 2, "etag": last_etag}]
    )
    assert response.status_code == 422
    assert "does not match the upload plan" in response.json()["detail"]
    good_etag = put_part(aws, first_url, payload[: 5 * MIB])  # re-upload overwrites the part
    assert (
        complete(
            upload, [{"part_number": 1, "etag": good_etag}, {"part_number": 2, "etag": last_etag}]
        ).status_code
        == 200
    )


def test_declared_size_cannot_be_smuggled_past_quota(
    client: TestClient, app: FastAPI, aws: object
) -> None:
    payload = os.urandom(5 * MIB + 10)
    set_quota(app, "alice", len(payload))
    upload = initiate(client, payload)
    stray = put_part(aws, upload.urls[0]["url"], os.urandom(5 * MIB))
    last = put_part(aws, upload.urls[1]["url"], os.urandom(500 * 1024))
    response = complete(
        upload, [{"part_number": 1, "etag": stray}, {"part_number": 2, "etag": last}]
    )
    assert response.status_code == 422
    assert client.get("/v1/files").json() == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda parts: parts[:-1],
        lambda parts: parts + [{"part_number": 9, "etag": "abc"}],
        lambda parts: parts + parts[:1],
        lambda parts: [{**parts[0], "etag": "0" * 32}, *parts[1:]],
    ],
    ids=["missing-part", "unknown-part", "duplicate-part", "wrong-etag"],
)
def test_malformed_part_lists_are_rejected(client: TestClient, aws: object, mutate: Any) -> None:
    payload = os.urandom(6 * MIB)
    upload = initiate(client, payload)
    parts = upload_all(aws, upload, payload)
    assert complete(upload, mutate(parts)).status_code == 422
    assert complete(upload, parts).status_code == 200  # the upload was left intact


def test_complete_is_idempotent(client: TestClient, app: FastAPI, aws: object) -> None:
    payload = b"complete me twice"
    upload = initiate(client, payload)
    parts = upload_all(aws, upload, payload)
    first, second = complete(upload, parts), complete(upload, parts)
    assert first.status_code == second.status_code == 200
    assert first.json()["file_id"] == second.json()["file_id"]
    assert db_scalar(app, select(func.count(FileRecord.id))) == 1


def test_complete_recovers_when_storage_assembled_the_object_before_a_crash(
    client: TestClient, aws: object
) -> None:
    payload = b"crash after storage complete"
    upload = initiate(client, payload)
    parts = upload_all(aws, upload, payload)
    key = cast(Any, aws).list_multipart_uploads(Bucket=BUCKET)["Uploads"][0]
    cast(Any, aws).complete_multipart_upload(
        Bucket=BUCKET,
        Key=key["Key"],
        UploadId=key["UploadId"],
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": parts[0]["etag"]}]},
    )
    assert complete(upload, parts).status_code == 200


def test_complete_after_storage_lost_the_upload_fails_cleanly(
    client: TestClient, app: FastAPI, aws: object
) -> None:
    payload = b"lifecycle rule aborted me"
    upload = initiate(client, payload)
    parts = upload_all(aws, upload, payload)
    entry = open_uploads(aws)[0]
    cast(Any, aws).abort_multipart_upload(
        Bucket=BUCKET, Key=entry["Key"], UploadId=entry["UploadId"]
    )
    assert complete(upload, parts).status_code == 410
    assert usage(app, "alice") == 0
    assert client.get(f"/v1/uploads/{upload.upload_id}").json()["status"] == "failed"


def test_expired_uploads_cannot_be_completed_or_extended(
    client: TestClient, app: FastAPI, aws: object
) -> None:
    payload = b"too slow"
    upload = initiate(client, payload)
    parts = upload_all(aws, upload, payload)
    db_execute(app, update(MultipartUpload).values(expires_at=utcnow() - dt.timedelta(minutes=1)))
    assert complete(upload, parts).status_code == 410
    record = client.post(
        f"/v1/uploads/{upload.upload_id}/parts/1",
        json={"etag": "x", "size_bytes": 1, "sha256": "0" * 64},
    )
    assert record.status_code == 410
    assert client.get(f"/v1/uploads/{upload.upload_id}").json()["pending_urls"] == []
    assert usage(app, "alice") == 0  # an expired reservation no longer counts


def test_record_part_verifies_against_storage(client: TestClient, aws: object) -> None:
    payload = os.urandom(6 * MIB)
    upload = initiate(client, payload)
    path = f"/v1/uploads/{upload.upload_id}/parts"
    chunk = upload.part_payload(payload, 1)
    body = {"etag": "ab" * 16, "size_bytes": len(chunk), "sha256": sha256(chunk)}

    assert client.post(f"{path}/1", json=body).status_code == 422  # never uploaded
    etag = put_part(aws, upload.urls[0]["url"], chunk)
    assert (
        client.post(f"{path}/1", json={**body, "etag": "ab" * 16}).status_code == 422
    )  # wrong etag
    assert (
        client.post(
            f"{path}/1", json={**body, "etag": etag, "size_bytes": len(chunk) - 1}
        ).status_code
        == 422
    )
    assert client.post(f"{path}/0", json={**body, "etag": etag}).status_code == 422
    assert client.post(f"{path}/3", json={**body, "etag": etag}).status_code == 422
    assert client.post(f"{path}/1", json={**body, "etag": etag}).json() == {"status": "recorded"}
    assert client.post(f"{path}/1", json={**body, "etag": etag}).json() == {
        "status": "already-recorded"
    }
    conflict = client.post(f"{path}/1", json={**body, "etag": etag, "sha256": "1" * 64})
    assert conflict.status_code == 409


def test_abort_is_idempotent_releases_quota_and_aborts_storage(
    client: TestClient, app: FastAPI, aws: object
) -> None:
    upload = initiate(client, b"x" * 100)
    assert usage(app, "alice") == 100 and len(open_uploads(aws)) == 1
    assert client.delete(f"/v1/uploads/{upload.upload_id}").status_code == 204
    assert client.delete(f"/v1/uploads/{upload.upload_id}").status_code == 204
    assert usage(app, "alice") == 0 and open_uploads(aws) == []
    assert complete(upload, [{"part_number": 1, "etag": "x"}]).status_code == 409


def test_completed_uploads_cannot_be_aborted(client: TestClient, aws: object) -> None:
    payload = b"keep me"
    upload = initiate(client, payload)
    complete(upload, upload_all(aws, upload, payload))
    assert client.delete(f"/v1/uploads/{upload.upload_id}").status_code == 409


def test_quota_counts_reservations_files_and_frees_on_delete(
    client: TestClient, app: FastAPI, aws: object
) -> None:
    set_quota(app, "alice", 1000)
    first = initiate(client, b"a" * 600)
    too_big = client.post("/v1/uploads", json={"filename": "b", "size_bytes": 401})
    assert too_big.status_code == 413
    exact = initiate(client, b"b" * 400)  # exactly at the limit is allowed
    assert usage(app, "alice") == 1000
    assert client.delete(f"/v1/uploads/{exact.upload_id}").status_code == 204

    complete(first, upload_all(aws, first, b"a" * 600))
    assert usage(app, "alice") == 600  # a finished file keeps counting
    assert client.post("/v1/uploads", json={"filename": "c", "size_bytes": 401}).status_code == 413
    file_id = client.get("/v1/files").json()[0]["id"]
    assert client.delete(f"/v1/files/{file_id}").status_code == 204
    assert usage(app, "alice") == 0
    assert initiate(client, b"c" * 1000).upload_id


def test_quota_is_per_user(client: TestClient, app: FastAPI) -> None:
    set_quota(app, "alice", 10)
    bob = new_user(app, "bob-user")
    assert client.post("/v1/uploads", json={"filename": "a", "size_bytes": 11}).status_code == 413
    assert bob.post("/v1/uploads", json={"filename": "a", "size_bytes": 11}).status_code == 200


def test_sizes_beyond_32_bits_are_reserved_and_summed(client: TestClient, app: FastAPI) -> None:
    set_quota(app, "alice", 20 * GIB)
    for _ in range(2):
        response = client.post(
            "/v1/uploads",
            json={"filename": "big.bin", "size_bytes": 5 * GIB, "part_size": 100 * MIB},
        )
        assert response.status_code == 200
    assert usage(app, "alice") == 10 * GIB
    assert (
        client.post(
            "/v1/uploads", json={"filename": "big.bin", "size_bytes": 5 * GIB + 1}
        ).status_code
        == 422
    )


@pytest.mark.parametrize(
    "body",
    [
        {"filename": "a", "size_bytes": 0},
        {"filename": "a", "size_bytes": -5},
        {"filename": "a", "size_bytes": 5 * GIB + 1},
        {"filename": "a", "size_bytes": 10, "part_size": 5 * MIB - 1},
        {"filename": "a", "size_bytes": 10, "part_size": 101 * MIB},
        {"filename": "a", "size_bytes": 10, "sha256": "A" * 64},
        {"filename": "a", "size_bytes": 10, "sha256": "abc"},
        {"filename": "", "size_bytes": 10},
        {"filename": "x" * 256, "size_bytes": 10},
        {"filename": "a/b", "size_bytes": 10},
        {"filename": "..\\evil", "size_bytes": 10},
        {"filename": "line\r\nbreak: injected", "size_bytes": 10},
        {"filename": "nul\x00byte", "size_bytes": 10},
        {"filename": "..", "size_bytes": 10},
        {"filename": "   ", "size_bytes": 10},
    ],
)
def test_initiate_rejects_invalid_requests(
    client: TestClient, aws: object, body: dict[str, Any]
) -> None:
    assert client.post("/v1/uploads", json=body).status_code == 422
    assert open_uploads(aws) == []


def test_idempotency_key_replays_the_same_upload(
    client: TestClient, app: FastAPI, aws: object
) -> None:
    headers = {"Idempotency-Key": "retry-1"}
    first = initiate(client, b"x" * 50, headers=headers)
    second = initiate(client, b"x" * 50, headers=headers)
    assert first.upload_id == second.upload_id
    assert usage(app, "alice") == 50 and len(open_uploads(aws)) == 1
    different = client.post(
        "/v1/uploads", json={"filename": "other", "size_bytes": 50}, headers=headers
    )
    assert different.status_code == 409
    client.delete(f"/v1/uploads/{first.upload_id}")
    assert (
        client.post(
            "/v1/uploads",
            json={"filename": "brief.txt", "size_bytes": 50, "sha256": sha256(b"x" * 50)},
            headers=headers,
        ).status_code
        == 409
    )


def test_users_cannot_touch_each_others_uploads_or_files(
    client: TestClient, app: FastAPI, aws: object
) -> None:
    payload = b"private"
    upload = initiate(client, payload)
    other = new_user(app, "mallory-1")
    base = f"/v1/uploads/{upload.upload_id}"
    assert other.get(base).status_code == 404
    assert other.delete(base).status_code == 404
    assert (
        other.post(
            f"{base}/complete", json={"parts": [{"part_number": 1, "etag": "x"}]}
        ).status_code
        == 404
    )
    assert (
        other.post(
            f"{base}/parts/1", json={"etag": "x", "size_bytes": 1, "sha256": "0" * 64}
        ).status_code
        == 404
    )
    file_id = cast(str, complete(upload, upload_all(aws, upload, payload)).json()["file_id"])
    assert other.delete(f"/v1/files/{file_id}").status_code == 404
    assert other.post(f"/v1/files/{file_id}/shares", json={}).status_code == 404
    assert other.get("/v1/files").json() == []


def test_storage_outage_on_initiate_leaves_no_reservation(
    client: TestClient, app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(**_: Any) -> None:
        raise ClientError(
            {"Error": {"Code": "InternalError", "Message": "boom"}}, "CreateMultipartUpload"
        )

    monkeypatch.setattr(app.state.container.s3.client, "create_multipart_upload", fail)
    response = client.post("/v1/uploads", json={"filename": "a", "size_bytes": 10})
    assert response.status_code == 502
    assert usage(app, "alice") == 0 and db_scalar(app, select(func.count(MultipartUpload.id))) == 0


def test_database_failure_after_storage_create_aborts_the_orphan(
    client: TestClient, aws: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*_: Any, **__: Any) -> None:
        raise RuntimeError("database went away")

    monkeypatch.setattr("vaultdrop.services.uploads.audit", explode)
    with pytest.raises(RuntimeError):
        client.post("/v1/uploads", json={"filename": "a", "size_bytes": 10})
    assert open_uploads(aws) == []


def test_storage_outage_on_abort_keeps_the_upload_active(
    client: TestClient, app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    upload = initiate(client, b"x" * 10)

    def fail(**_: Any) -> None:
        raise ClientError(
            {"Error": {"Code": "ServiceUnavailable", "Message": "down"}}, "AbortMultipartUpload"
        )

    monkeypatch.setattr(app.state.container.s3.client, "abort_multipart_upload", fail)
    assert client.delete(f"/v1/uploads/{upload.upload_id}").status_code == 502
    assert usage(app, "alice") == 10  # still reserved: the abort did not happen


def test_unreadable_stored_object_during_verification_is_a_502_not_a_corrupt_record(
    client: TestClient, app: FastAPI, aws: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"storage flakes while hashing"
    upload = initiate(client, payload)
    parts = upload_all(aws, upload, payload)

    def fail(**_: Any) -> None:
        raise ClientError({"Error": {"Code": "InternalError", "Message": "x"}}, "GetObject")

    monkeypatch.setattr(app.state.container.s3.client, "get_object", fail)
    assert complete(upload, parts).status_code == 502
    monkeypatch.undo()
    assert complete(upload, parts).status_code == 200  # retry succeeds: nothing was half-committed


def test_sweep_endpoint_only_touches_own_expired_uploads(
    client: TestClient, app: FastAPI, aws: object
) -> None:
    mine = initiate(client, b"a" * 10)
    other = new_user(app, "other-person")
    theirs = initiate(other, b"b" * 10)
    db_execute(app, update(MultipartUpload).values(expires_at=utcnow() - dt.timedelta(hours=1)))
    assert client.post("/v1/uploads/expired/sweep").json() == {"aborted": 1}
    assert client.get(f"/v1/uploads/{mine.upload_id}").json()["status"] == "aborted"
    assert other.get(f"/v1/uploads/{theirs.upload_id}").json()["status"] == "active"
    assert len(open_uploads(aws)) == 1


def test_audit_trail_records_the_upload_lifecycle_for_the_owner_only(
    client: TestClient, app: FastAPI, aws: object
) -> None:
    store_file(client, aws, b"audited")
    actions = [event["action"] for event in client.get("/v1/audit").json()]
    assert {"auth.registered", "upload.initiated", "upload.completed"} <= set(actions)
    bob = new_user(app, "bob-user")
    assert "upload.completed" not in [e["action"] for e in bob.get("/v1/audit").json()]
    assert client.get("/v1/audit", params={"limit": 1}).json().__len__() == 1
    assert client.get("/v1/audit", params={"limit": 0}).status_code == 422

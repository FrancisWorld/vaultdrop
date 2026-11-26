import datetime as dt
from typing import Any, cast
from urllib.parse import parse_qs, unquote, urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from vaultdrop.models import AttemptLog, AuditEvent, ShareLink, utcnow

from .conftest import BUCKET, db_execute, db_scalar, new_user
from .helpers import create_share, redeem, store_file


@pytest.fixture
def file_id(client: TestClient, aws: object) -> str:
    return store_file(client, aws, b"shared payload", filename="my report.pdf")


def downloads(app: FastAPI) -> int:
    return int(cast(int, db_scalar(app, select(ShareLink.downloads))))


def test_redeem_returns_a_working_presigned_url_with_a_safe_disposition(
    client: TestClient, aws: object, file_id: str
) -> None:
    token = create_share(client, file_id)
    anonymous = TestClient(client.app)
    response = redeem(anonymous, token)
    assert response.status_code == 200
    body = response.json()
    assert body["filename"] == "my report.pdf" and body["size_bytes"] == 14
    query = parse_qs(urlparse(body["download_url"]).query)
    assert query["response-content-disposition"] == ["attachment; filename*=UTF-8''my%20report.pdf"]
    key = unquote(urlparse(body["download_url"]).path.split(f"/{BUCKET}/", 1)[-1].lstrip("/"))
    assert cast(Any, aws).get_object(Bucket=BUCKET, Key=key)["Body"].read() == b"shared payload"


def test_download_counter_and_limit(client: TestClient, app: FastAPI, file_id: str) -> None:
    token = create_share(client, file_id, max_downloads=2)
    assert [redeem(client, token).status_code for _ in range(3)] == [200, 200, 404]
    assert downloads(app) == 2  # the rejected attempt did not consume a slot


def test_unlimited_shares_keep_counting(client: TestClient, app: FastAPI, file_id: str) -> None:
    token = create_share(client, file_id)
    for _ in range(3):
        assert redeem(client, token).status_code == 200
    assert downloads(app) == 3


def test_expired_share_is_unavailable(client: TestClient, app: FastAPI, file_id: str) -> None:
    token = create_share(client, file_id, expires_in_seconds=3600)
    assert redeem(client, token).status_code == 200
    db_execute(app, update(ShareLink).values(expires_at=utcnow() - dt.timedelta(seconds=1)))
    assert redeem(client, token).status_code == 404


def test_unknown_and_malformed_tokens(client: TestClient) -> None:
    assert redeem(client, "A" * 43).status_code == 404
    assert redeem(client, "short").status_code == 422
    assert redeem(client, "../../etc/passwd" + "a" * 20).status_code == 422
    assert client.get("/v1/shares/redeem").status_code in {404, 405}  # redemption is POST-only


def test_every_unavailable_reason_looks_identical(
    client: TestClient, app: FastAPI, file_id: str
) -> None:
    exhausted = create_share(client, file_id, max_downloads=1)
    redeem(client, exhausted)
    unknown = redeem(client, "B" * 43)
    spent = redeem(client, exhausted)
    assert unknown.status_code == spent.status_code == 404
    assert unknown.json() == spent.json()


def test_password_protected_share_flow(client: TestClient, app: FastAPI, file_id: str) -> None:
    token = create_share(client, file_id, password="correct horse")
    assert redeem(client, token).status_code == 401
    assert redeem(client, token, "").status_code == 401
    assert redeem(client, token, "wrong").status_code == 403
    assert downloads(app) == 0  # failed guesses never consume downloads
    assert redeem(client, token, "correct horse").status_code == 200
    stored = db_scalar(app, select(ShareLink.password_hash))
    assert isinstance(stored, str) and stored.startswith("$argon2id$")


def test_missing_password_is_not_counted_as_a_guess(
    client: TestClient, app: FastAPI, file_id: str
) -> None:
    token = create_share(client, file_id, password="correct horse")
    for _ in range(10):
        assert redeem(client, token).status_code == 401
    assert db_scalar(app, select(func.count(AttemptLog.id))) == 0


def test_password_guessing_is_rate_limited_per_source(
    client: TestClient, app: FastAPI, file_id: str
) -> None:
    token = create_share(client, file_id, password="correct horse")
    attacker = TestClient(app, client=("198.51.100.5", 1))
    assert [redeem(attacker, token, "guess").status_code for _ in range(5)] == [403] * 5
    blocked = redeem(
        attacker, token, "correct horse"
    )  # even the right password is refused while blocked
    assert blocked.status_code == 429 and int(blocked.headers["retry-after"]) > 0
    assert (
        redeem(TestClient(app, client=("198.51.100.6", 1)), token, "correct horse").status_code
        == 200
    )


def test_rate_limit_window_expires_and_success_resets_history(
    client: TestClient, app: FastAPI, file_id: str
) -> None:
    token = create_share(client, file_id, password="correct horse")
    user = TestClient(app, client=("198.51.100.7", 1))
    for _ in range(5):
        redeem(user, token, "guess")
    assert redeem(user, token, "correct horse").status_code == 429
    db_execute(app, update(AttemptLog).values(attempted_at=utcnow() - dt.timedelta(hours=1)))
    for _ in range(4):
        assert redeem(user, token, "guess").status_code == 403
    assert redeem(user, token, "correct horse").status_code == 200
    assert db_scalar(app, select(func.count(AttemptLog.id))) == 0  # success wiped the ledger
    assert [redeem(user, token, "guess").status_code for _ in range(5)] == [403] * 5


def test_share_creation_validation(client: TestClient, file_id: str) -> None:
    url = f"/v1/files/{file_id}/shares"
    for body in (
        {"expires_in_seconds": 10},
        {"expires_in_seconds": 10**9},
        {"max_downloads": 0},
        {"max_downloads": 10**6},
        {"password": ""},
    ):
        assert client.post(url, json=body).status_code == 422
    assert client.post("/v1/files/does-not-exist/shares", json={}).status_code == 404


def test_tokens_are_random_and_only_their_hash_is_stored(
    client: TestClient, app: FastAPI, file_id: str
) -> None:
    first, second = create_share(client, file_id), create_share(client, file_id)
    assert first != second and len(first) >= 43
    assert (
        db_scalar(app, select(func.count(ShareLink.id)).where(ShareLink.token_hash == first)) == 0
    )


def test_listing_and_revoking_shares(client: TestClient, app: FastAPI, file_id: str) -> None:
    token = create_share(client, file_id, password="pw-123456", max_downloads=3)
    listed = client.get("/v1/shares").json()
    assert listed[0]["password_protected"] is True and listed[0]["max_downloads"] == 3
    assert "token" not in listed[0]
    stranger = new_user(app, "stranger-1")
    assert stranger.delete(f"/v1/shares/{listed[0]['id']}").status_code == 404
    assert stranger.get("/v1/shares").json() == []
    assert client.delete(f"/v1/shares/{listed[0]['id']}").status_code == 204
    assert redeem(client, token, "pw-123456").status_code == 404


def test_deleting_a_file_kills_its_shares_and_removes_the_object(
    client: TestClient, aws: object, file_id: str
) -> None:
    token = create_share(client, file_id)
    assert client.delete(f"/v1/files/{file_id}").status_code == 204
    assert client.delete(f"/v1/files/{file_id}").status_code == 404
    assert redeem(client, token).status_code == 404
    assert cast(Any, aws).list_objects_v2(Bucket=BUCKET).get("KeyCount", 0) == 0
    assert client.get("/v1/shares").json() == []


def test_file_delete_survives_a_storage_outage_without_leaving_live_shares(
    client: TestClient, app: FastAPI, file_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from botocore.exceptions import ClientError

    token = create_share(client, file_id)

    def fail(**_: Any) -> None:
        raise ClientError({"Error": {"Code": "InternalError", "Message": "x"}}, "DeleteObject")

    monkeypatch.setattr(app.state.container.s3.client, "delete_object", fail)
    assert client.delete(f"/v1/files/{file_id}").status_code == 204
    assert redeem(client, token).status_code == 404


def test_redemptions_are_audited_for_the_owner_only(
    client: TestClient, app: FastAPI, file_id: str
) -> None:
    token = create_share(client, file_id)
    redeem(TestClient(app), token)
    owner_view = [e["action"] for e in client.get("/v1/audit").json()]
    assert "share.redeemed" in owner_view and "share.created" in owner_view
    assert "share.redeemed" not in [
        e["action"] for e in new_user(app, "snoop-1").get("/v1/audit").json()
    ]
    detail = db_scalar(app, select(AuditEvent.detail).where(AuditEvent.action == "share.redeemed"))
    assert isinstance(detail, str) and "testclient" not in detail  # source IPs are stored hashed


def test_share_page_serves_the_app_shell_and_never_the_file(
    client: TestClient, file_id: str
) -> None:
    token = create_share(client, file_id)
    page = TestClient(client.app).get(f"/s/{token}")
    assert page.status_code == 200 and "text/html" in page.headers["content-type"]
    assert "download_url" not in page.text
    assert page.headers["cache-control"] == "no-store"


def test_large_tokens_do_not_break_redeem(client: TestClient) -> None:
    assert redeem(client, "a" * 129).status_code == 422

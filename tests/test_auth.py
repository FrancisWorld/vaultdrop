import datetime as dt

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from vaultdrop.api import create_app
from vaultdrop.config import Settings
from vaultdrop.models import AttemptLog, User, UserSession, utcnow

from .conftest import PASSWORD, db_execute, db_scalar, new_user

PROTECTED = [
    ("GET", "/v1/auth/me"),
    ("GET", "/v1/files"),
    ("DELETE", "/v1/files/x"),
    ("POST", "/v1/files/x/shares"),
    ("GET", "/v1/shares"),
    ("DELETE", "/v1/shares/x"),
    ("POST", "/v1/uploads"),
    ("GET", "/v1/uploads/x"),
    ("POST", "/v1/uploads/x/parts/1"),
    ("POST", "/v1/uploads/x/complete"),
    ("DELETE", "/v1/uploads/x"),
    ("POST", "/v1/uploads/expired/sweep"),
    ("GET", "/v1/audit"),
]


@pytest.mark.parametrize(("method", "path"), PROTECTED)
def test_every_protected_route_rejects_anonymous_callers(
    app: FastAPI, method: str, path: str
) -> None:
    anonymous = TestClient(app)
    response = anonymous.request(method, path, json={})
    assert response.status_code == 401


@pytest.mark.parametrize("cookie", ["", "garbage", "a.b", "x" * 200, "' OR 1=1 --"])
def test_forged_session_cookies_are_rejected(app: FastAPI, cookie: str) -> None:
    anonymous = TestClient(app, cookies={"vaultdrop_session": cookie})
    assert anonymous.get("/v1/auth/me").status_code == 401


def test_register_sets_hardened_cookie_and_hashes_password(
    client: TestClient, app: FastAPI
) -> None:
    secure = create_app(
        Settings(
            _env_file=None,
            database_url=app.state.container.settings.database_url,
            s3_bucket="vaultdrop-test-bucket",
            argon2_memory_kib=1024,
            argon2_time_cost=1,
            sweep_interval_seconds=0,
            cookie_secure=True,
        )
    )
    with TestClient(secure) as other:
        response = other.post("/v1/auth/register", json={"username": "carol", "password": PASSWORD})
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=strict" in cookie

    stored = db_scalar(app, select(User.password_hash).where(User.username == "alice"))
    assert isinstance(stored, str) and stored.startswith("$argon2id$") and PASSWORD not in stored


def test_session_token_is_stored_only_as_a_digest(client: TestClient, app: FastAPI) -> None:
    token = client.cookies["vaultdrop_session"]
    assert db_scalar(app, select(UserSession.id).where(UserSession.token_hash == token)) is None
    assert db_scalar(app, select(UserSession.id)) is not None


def test_usernames_are_case_insensitive_and_unique(client: TestClient) -> None:
    again = TestClient(client.app)
    response = again.post("/v1/auth/register", json={"username": "ALICE", "password": PASSWORD})
    assert response.status_code == 409


@pytest.mark.parametrize(
    "body",
    [
        {"username": "ab", "password": PASSWORD},
        {"username": "has space", "password": PASSWORD},
        {"username": "valid-name", "password": "short"},
        {"username": "valid-name", "password": "x" * 300},
        {"username": "valid-name"},
    ],
)
def test_registration_validates_input(app: FastAPI, body: dict[str, str]) -> None:
    assert TestClient(app).post("/v1/auth/register", json=body).status_code == 422


def test_registration_can_be_disabled(settings: Settings, aws: object) -> None:
    closed = create_app(settings.model_copy(update={"allow_registration": False}))
    with TestClient(closed) as client:
        response = client.post("/v1/auth/register", json={"username": "dave", "password": PASSWORD})
    assert response.status_code == 403


def test_login_failures_do_not_reveal_whether_a_user_exists(client: TestClient) -> None:
    other = TestClient(client.app)
    unknown = other.post("/v1/auth/login", json={"username": "nobody", "password": PASSWORD})
    wrong = other.post("/v1/auth/login", json={"username": "alice", "password": "wrong-password-1"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_login_issues_a_new_session(client: TestClient) -> None:
    other = TestClient(client.app)
    response = other.post("/v1/auth/login", json={"username": "Alice", "password": PASSWORD})
    assert response.status_code == 200
    assert other.get("/v1/auth/me").json()["username"] == "alice"


def test_login_is_throttled_per_source_and_username(client: TestClient, app: FastAPI) -> None:
    attacker = TestClient(app, client=("203.0.113.7", 1))
    for _ in range(5):
        assert (
            attacker.post(
                "/v1/auth/login", json={"username": "alice", "password": "wrong-password-1"}
            ).status_code
            == 401
        )
    blocked = attacker.post("/v1/auth/login", json={"username": "alice", "password": PASSWORD})
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0
    elsewhere = TestClient(app, client=("203.0.113.8", 1))
    assert (
        elsewhere.post(
            "/v1/auth/login", json={"username": "alice", "password": PASSWORD}
        ).status_code
        == 200
    )


def test_successful_login_clears_the_failure_history(client: TestClient, app: FastAPI) -> None:
    user = TestClient(app, client=("203.0.113.9", 1))
    for _ in range(4):
        user.post("/v1/auth/login", json={"username": "alice", "password": "wrong-password-1"})
    assert (
        user.post("/v1/auth/login", json={"username": "alice", "password": PASSWORD}).status_code
        == 200
    )
    assert db_scalar(app, select(AttemptLog.id).where(AttemptLog.scope == "login")) is None


def test_logout_revokes_the_session_server_side(client: TestClient) -> None:
    stolen = client.cookies["vaultdrop_session"]
    assert client.post("/v1/auth/logout").status_code == 200
    assert client.get("/v1/files").status_code == 401
    replay = TestClient(client.app, cookies={"vaultdrop_session": stolen})
    assert replay.get("/v1/files").status_code == 401


def test_expired_sessions_are_rejected(client: TestClient, app: FastAPI) -> None:
    db_execute(app, update(UserSession).values(expires_at=utcnow() - dt.timedelta(seconds=1)))
    assert client.get("/v1/auth/me").status_code == 401


def test_sessions_are_independent_between_users(client: TestClient, app: FastAPI) -> None:
    bob = new_user(app, "bob-user")
    assert bob.get("/v1/auth/me").json()["username"] == "bob-user"
    assert client.get("/v1/auth/me").json()["username"] == "alice"

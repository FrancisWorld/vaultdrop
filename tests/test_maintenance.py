import datetime as dt
import time
from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from vaultdrop.api import create_app
from vaultdrop.config import Settings
from vaultdrop.models import AttemptLog, MultipartUpload, UploadStatus, UserSession, utcnow

from .conftest import BUCKET, db_execute, db_scalar
from .helpers import initiate


def test_run_once_sweeps_uploads_sessions_and_old_attempts(
    client: TestClient, app: FastAPI, aws: object
) -> None:
    initiate(client, b"x" * 100)
    initiate(client, b"y" * 100)
    past = utcnow() - dt.timedelta(days=2)
    db_execute(app, update(MultipartUpload).values(expires_at=past))
    db_execute(app, update(UserSession).values(expires_at=past))
    with app.state.container.database.session() as db:
        db.add(AttemptLog(scope="login", key_hash="a" * 64, attempted_at=past))
        db.add(AttemptLog(scope="login", key_hash="b" * 64))

    result = app.state.container.maintenance.run_once()
    assert result == {"uploads_aborted": 2, "sessions_purged": 1, "attempts_purged": 1}
    assert (
        db_scalar(
            app,
            select(func.count(MultipartUpload.id)).where(
                MultipartUpload.status == UploadStatus.ACTIVE
            ),
        )
        == 0
    )
    assert cast(Any, aws).list_multipart_uploads(Bucket=BUCKET).get("Uploads", []) == []
    assert db_scalar(app, select(func.count(AttemptLog.id))) == 1
    assert app.state.container.maintenance.run_once() == {
        "uploads_aborted": 0,
        "sessions_purged": 0,
        "attempts_purged": 0,
    }


def test_sweep_processes_more_than_one_batch(client: TestClient, app: FastAPI) -> None:
    for _ in range(5):
        initiate(client, b"z" * 10)
    db_execute(app, update(MultipartUpload).values(expires_at=utcnow() - dt.timedelta(hours=1)))
    assert app.state.container.uploads.sweep_expired(batch=2) == 5


def test_background_sweeper_runs_and_stops_with_the_app(settings: Settings, aws: object) -> None:
    app = create_app(settings.model_copy(update={"sweep_interval_seconds": 1}))
    with TestClient(app) as client:
        client.post(
            "/v1/auth/register", json={"username": "sweepy", "password": "correct-horse-battery"}
        )
        upload = client.post("/v1/uploads", json={"filename": "a", "size_bytes": 10}).json()
        db_execute(app, update(MultipartUpload).values(expires_at=utcnow() - dt.timedelta(hours=1)))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if client.get(f"/v1/uploads/{upload['upload_id']}").json()["status"] == "aborted":
                break
            time.sleep(0.2)
        else:
            raise AssertionError("sweeper never aborted the expired upload")

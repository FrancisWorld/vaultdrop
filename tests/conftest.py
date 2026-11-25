import os
from collections.abc import Iterator

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

os.environ["VAULTDROP_DATABASE_URL"] = "sqlite:///./test-vaultdrop.db"
os.environ["VAULTDROP_S3_BUCKET"] = "vaultdrop-test-bucket"


@pytest.fixture(autouse=True)
def clean_database() -> Iterator[None]:
    from vaultdrop.database import Base, engine

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def aws() -> Iterator[object]:
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="vaultdrop-test-bucket")
        yield client


@pytest.fixture
def client(aws: object) -> Iterator[TestClient]:
    from vaultdrop.api import app

    with TestClient(app) as test_client:
        yield test_client

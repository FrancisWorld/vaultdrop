import pytest
from fastapi.testclient import TestClient

from vaultdrop.api import content_security_policy, create_app
from vaultdrop.config import Settings
from vaultdrop.s3 import content_disposition, is_safe_filename

from .conftest import PASSWORD


def test_security_headers_on_api_and_static_responses(client: TestClient) -> None:
    for path in ("/health", "/v1/files", "/"):
        headers = client.get(path).headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["referrer-policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert client.get("/v1/files").headers["cache-control"] == "no-store"


def test_csp_has_no_wildcards_inline_code_or_arbitrary_https(client: TestClient) -> None:
    csp = client.get("/").headers["content-security-policy"]
    directives = dict(item.split(" ", 1) for item in csp.split("; "))
    assert directives["default-src"] == "'none'"
    assert directives["script-src"] == "'self'"
    assert directives["style-src"] == "'self'"
    assert "unsafe" not in csp and "*" not in csp
    assert not {"https:", "http:", "data:"} & set(csp.replace(";", "").split())
    assert directives["connect-src"].split() == [
        "'self'",
        "https://vaultdrop-test-bucket.s3.amazonaws.com",
    ]


def test_csp_connects_only_to_the_configured_storage_origin(
    settings: Settings, aws: object
) -> None:
    local = settings.model_copy(
        update={
            "s3_endpoint": "http://s3.internal:3900",
            "s3_public_endpoint": "http://localhost:3900",
            "s3_path_style": True,
        }
    )
    app = create_app(local)
    csp = app.state.container.s3.browser_origin
    assert csp == "http://localhost:3900"
    assert "connect-src 'self' http://localhost:3900;" in content_security_policy(csp)


def test_presigned_urls_use_the_public_endpoint_not_the_internal_one(
    settings: Settings, aws: object
) -> None:
    local = settings.model_copy(
        update={
            "s3_endpoint": "http://s3.internal:3900",
            "s3_public_endpoint": "http://localhost:3900",
            "s3_path_style": True,
        }
    )
    s3 = create_app(local).state.container.s3
    url = s3.presign_part("user/key", "upload-id", 1)
    assert url.startswith("http://localhost:3900/vaultdrop-test-bucket/user/key?")
    assert s3.client.meta.endpoint_url == "http://s3.internal:3900"


def test_hsts_only_when_cookies_are_secure(
    client: TestClient, settings: Settings, aws: object
) -> None:
    assert "strict-transport-security" not in client.get("/health").headers
    secure = create_app(settings.model_copy(update={"cookie_secure": True}))
    assert "max-age" in TestClient(secure).get("/health").headers["strict-transport-security"]


def test_cross_origin_state_changes_are_rejected(client: TestClient) -> None:
    hostile = {"Origin": "https://evil.example"}
    assert client.post("/v1/auth/logout", headers=hostile).status_code == 403
    assert client.delete("/v1/files/x", headers=hostile).status_code == 403
    assert (
        client.get("/v1/files", headers=hostile).status_code == 200
    )  # reads are not state changes
    assert (
        client.post("/v1/auth/logout", headers={"Origin": "http://testserver"}).status_code == 200
    )
    assert (
        client.post("/v1/auth/logout", headers={"Origin": "http://localhost:8000"}).status_code
        == 200
    )


def test_no_cors_headers_are_ever_granted(client: TestClient) -> None:
    response = client.options(
        "/v1/files",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in response.headers


def test_domain_errors_are_json_without_internals(client: TestClient) -> None:
    response = client.get("/v1/uploads/not-mine")
    assert response.status_code == 404 and response.json() == {"detail": "Upload not found"}


@pytest.mark.parametrize("name", ["report.pdf", "naïve café.txt", "名前.txt", "a b (1).bin"])
def test_safe_filenames_accepted(name: str) -> None:
    assert is_safe_filename(name)


@pytest.mark.parametrize("name", ["", " ", ".", "..", "a/b", "a\\b", "a\nb", "a\x00b", "a\x7fb"])
def test_unsafe_filenames_rejected(name: str) -> None:
    assert not is_safe_filename(name)


def test_content_disposition_cannot_be_broken_out_of() -> None:
    header = content_disposition('evil"; filename=x\r\nSet-Cookie: a=b')
    assert "\r" not in header and "\n" not in header and '"' not in header
    assert header.startswith("attachment; filename*=UTF-8''")
    assert content_disposition("naïve.txt") == "attachment; filename*=UTF-8''na%C3%AFve.txt"


def test_blank_optional_settings_become_none() -> None:
    parsed = Settings(_env_file=None, s3_endpoint="", s3_sse=" ", s3_kms_key_id="")
    assert parsed.s3_endpoint is None and parsed.s3_sse is None and parsed.s3_kms_key_id is None


def test_origin_list_is_normalised() -> None:
    parsed = Settings(_env_file=None, allowed_origins="http://a.test/, http://b.test ,")
    assert parsed.origins == {"http://a.test", "http://b.test"}


def test_static_ui_has_no_inline_script_or_style(client: TestClient) -> None:
    html = client.get("/").text
    assert "<script>" not in html and "onclick" not in html and "style=" not in html


def test_register_then_cookie_is_the_only_credential(client: TestClient) -> None:
    other = TestClient(client.app)
    assert (
        other.get(
            "/v1/files", headers={"X-User-Id": "alice", "Authorization": "Bearer alice"}
        ).status_code
        == 401
    )
    assert client.get("/v1/files").status_code == 200
    assert PASSWORD

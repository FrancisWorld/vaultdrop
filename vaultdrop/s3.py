import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import quote, urlsplit

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from .config import Settings
from .errors import StorageUnavailable

READ_CHUNK = 1024 * 1024
_MISSING_UPLOAD = {"NoSuchUpload", "404"}


class UploadGone(Exception):
    """The multipart upload no longer exists in object storage."""


def content_disposition(filename: str) -> str:
    """RFC 6266 attachment header that cannot be broken out of by the filename."""
    return f"attachment; filename*=UTF-8''{quote(filename, safe='')}"


class S3Service:
    """Thin wrapper over the S3 operations VaultDrop needs.

    Two clients are used: `client` talks to storage from the server (possibly via
    an internal hostname), while `presigner` signs URLs against the endpoint the
    browser can actually reach.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.bucket = settings.s3_bucket
        self.client = self._build(settings.s3_endpoint)
        public = settings.s3_public_endpoint or settings.s3_endpoint
        self.presigner = self.client if public == settings.s3_endpoint else self._build(public)

    def _build(self, endpoint: str | None) -> Any:
        config = Config(
            signature_version="s3v4",
            s3={"addressing_style": "path" if self.settings.s3_path_style else "auto"},
            retries={"max_attempts": 3, "mode": "standard"},
        )
        kwargs: dict[str, Any] = {"region_name": self.settings.aws_region}
        if endpoint:
            kwargs["endpoint_url"] = endpoint
        return boto3.client("s3", config=config, **kwargs)

    @property
    def browser_origin(self) -> str:
        """Origin the browser talks to for presigned requests (used in the CSP)."""
        url = self.presigner.generate_presigned_url(
            "get_object", Params={"Bucket": self.bucket, "Key": "probe"}, ExpiresIn=60
        )
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.netloc}"

    def bootstrap(self) -> None:
        """Development helper: create the bucket and browser CORS rules if missing."""
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except ClientError:
            params: dict[str, Any] = {"Bucket": self.bucket}
            if self.settings.aws_region != "us-east-1":
                params["CreateBucketConfiguration"] = {
                    "LocationConstraint": self.settings.aws_region
                }
            self.client.create_bucket(**params)
        self.client.put_bucket_cors(
            Bucket=self.bucket,
            CORSConfiguration={
                # One rule per origin: some servers echo the whole list back, which
                # browsers reject as an invalid Access-Control-Allow-Origin value.
                "CORSRules": [
                    {
                        "AllowedOrigins": [origin],
                        "AllowedMethods": ["PUT", "GET", "HEAD"],
                        "AllowedHeaders": ["*"],
                        "ExposeHeaders": ["ETag"],
                        "MaxAgeSeconds": 3600,
                    }
                    for origin in sorted(self.settings.origins)
                ]
            },
        )

    def _guard(self, operation: str, error: Exception) -> StorageUnavailable:
        return StorageUnavailable(f"Object storage failed during {operation}")

    def create_multipart(self, key: str) -> str:
        params: dict[str, Any] = {"Bucket": self.bucket, "Key": key}
        if self.settings.s3_sse:
            params["ServerSideEncryption"] = self.settings.s3_sse
            if self.settings.s3_kms_key_id and self.settings.s3_sse == "aws:kms":
                params["SSEKMSKeyId"] = self.settings.s3_kms_key_id
        try:
            return str(self.client.create_multipart_upload(**params)["UploadId"])
        except (ClientError, BotoCoreError) as error:
            raise self._guard("create_multipart_upload", error) from error

    def presign_part(self, key: str, upload_id: str, part_number: int) -> str:
        return str(
            self.presigner.generate_presigned_url(
                "upload_part",
                Params={
                    "Bucket": self.bucket,
                    "Key": key,
                    "UploadId": upload_id,
                    "PartNumber": part_number,
                },
                ExpiresIn=self.settings.presigned_expiry_seconds,
                HttpMethod="PUT",
            )
        )

    def presign_download(self, key: str, filename: str) -> str:
        return str(
            self.presigner.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.bucket,
                    "Key": key,
                    "ResponseContentDisposition": content_disposition(filename),
                },
                ExpiresIn=self.settings.presigned_expiry_seconds,
            )
        )

    def list_parts(self, key: str, upload_id: str) -> list[dict[str, Any]]:
        parts: list[dict[str, Any]] = []
        try:
            pages = self.client.get_paginator("list_parts").paginate(
                Bucket=self.bucket, Key=key, UploadId=upload_id
            )
            for page in pages:
                parts.extend(page.get("Parts", []))
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") in _MISSING_UPLOAD:
                raise UploadGone from error
            raise self._guard("list_parts", error) from error
        except BotoCoreError as error:
            raise self._guard("list_parts", error) from error
        return parts

    def get_part(self, key: str, upload_id: str, part_number: int) -> dict[str, Any] | None:
        """Return storage's record of one part, or None if it was never uploaded."""
        try:
            response = self.client.list_parts(
                Bucket=self.bucket,
                Key=key,
                UploadId=upload_id,
                PartNumberMarker=part_number - 1,
                MaxParts=1,
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") in _MISSING_UPLOAD:
                raise UploadGone from error
            raise self._guard("list_parts", error) from error
        except BotoCoreError as error:
            raise self._guard("list_parts", error) from error
        for part in response.get("Parts", []):
            if int(part["PartNumber"]) == part_number:
                return dict(part)
        return None

    def complete_multipart(self, key: str, upload_id: str, parts: list[dict[str, Any]]) -> None:
        try:
            self.client.complete_multipart_upload(
                Bucket=self.bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") in _MISSING_UPLOAD:
                raise UploadGone from error
            raise self._guard("complete_multipart_upload", error) from error
        except BotoCoreError as error:
            raise self._guard("complete_multipart_upload", error) from error

    def abort_multipart(self, key: str, upload_id: str) -> None:
        """Abort an upload; an upload that is already gone counts as aborted."""
        try:
            self.client.abort_multipart_upload(Bucket=self.bucket, Key=key, UploadId=upload_id)
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") not in _MISSING_UPLOAD:
                raise self._guard("abort_multipart_upload", error) from error
        except BotoCoreError as error:
            raise self._guard("abort_multipart_upload", error) from error

    def delete_object(self, key: str) -> None:
        try:
            self.client.delete_object(Bucket=self.bucket, Key=key)
        except (ClientError, BotoCoreError) as error:
            raise self._guard("delete_object", error) from error

    def object_size(self, key: str) -> int | None:
        try:
            return int(self.client.head_object(Bucket=self.bucket, Key=key)["ContentLength"])
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") in {"404", "NoSuchKey", "NotFound"}:
                return None
            raise self._guard("head_object", error) from error
        except BotoCoreError as error:
            raise self._guard("head_object", error) from error

    def stream_object(self, key: str) -> Iterator[bytes]:
        """Yield the object in bounded chunks; never holds more than `READ_CHUNK` bytes."""
        try:
            body = self.client.get_object(Bucket=self.bucket, Key=key)["Body"]
        except (ClientError, BotoCoreError) as error:
            raise self._guard("get_object", error) from error
        try:
            yield from body.iter_chunks(READ_CHUNK)
        except (ClientError, BotoCoreError) as error:
            raise self._guard("get_object", error) from error
        finally:
            body.close()


_UNSAFE_NAME = re.compile(r"[\x00-\x1f\x7f/\\]")


def is_safe_filename(name: str) -> bool:
    return bool(name.strip()) and not _UNSAFE_NAME.search(name) and name not in {".", ".."}

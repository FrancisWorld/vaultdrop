from typing import Any, BinaryIO, cast

import boto3
from botocore.config import Config

from .config import get_settings


class S3Service:
    def __init__(self) -> None:
        settings = get_settings()
        kwargs: dict[str, object] = {"region_name": settings.aws_region}
        if settings.s3_endpoint:
            kwargs["endpoint_url"] = settings.s3_endpoint
        self.client = boto3.client("s3", config=Config(signature_version="s3v4"), **kwargs)
        self.bucket = settings.s3_bucket

    def ensure_bucket(self) -> None:
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except Exception:
            region = get_settings().aws_region
            params: dict[str, Any] = {"Bucket": self.bucket}
            if region != "us-east-1":
                params["CreateBucketConfiguration"] = {"LocationConstraint": region}
            self.client.create_bucket(**params)

    def create_multipart(self, key: str, filename: str) -> str:
        response = self.client.create_multipart_upload(
            Bucket=self.bucket,
            Key=key,
            ContentDisposition=f"attachment; filename={filename}",
            ServerSideEncryption="aws:kms",
        )
        return str(response["UploadId"])

    def presign_part(self, key: str, upload_id: str, part_number: int) -> str:
        return str(
            self.client.generate_presigned_url(
                "upload_part",
                Params={
                    "Bucket": self.bucket,
                    "Key": key,
                    "UploadId": upload_id,
                    "PartNumber": part_number,
                },
                ExpiresIn=get_settings().presigned_expiry_seconds,
                HttpMethod="PUT",
            )
        )

    def complete_multipart(
        self, key: str, upload_id: str, parts: list[dict[str, int | str]]
    ) -> None:
        self.client.complete_multipart_upload(
            Bucket=self.bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )

    def abort_multipart(self, key: str, upload_id: str) -> None:
        self.client.abort_multipart_upload(Bucket=self.bucket, Key=key, UploadId=upload_id)

    def delete_object(self, key: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=key)

    def head(self, key: str) -> dict[str, object]:
        return dict(self.client.head_object(Bucket=self.bucket, Key=key))

    def download_stream(self, key: str) -> BinaryIO:
        response = self.client.get_object(Bucket=self.bucket, Key=key)
        body = response["Body"]
        if not hasattr(body, "read"):
            raise RuntimeError("S3 returned no readable object body")
        return cast(BinaryIO, body)

    def presigned_download(self, key: str, filename: str) -> str:
        return str(
            self.client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.bucket,
                    "Key": key,
                    "ResponseContentDisposition": f"attachment; filename={filename}",
                },
                ExpiresIn=get_settings().presigned_expiry_seconds,
            )
        )

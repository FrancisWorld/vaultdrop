"""One-shot development bootstrap for the Garage S3 container.

Assigns the single-node layout, imports the access key given in the environment,
creates the bucket and grants the key access. Idempotent: safe to run on every
`docker compose up`. Uses only the standard library.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

ADMIN = os.environ.get("GARAGE_ADMIN_URL", "http://garage:3903") + "/v2"
TOKEN = os.environ["GARAGE_ADMIN_TOKEN"]
KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
SECRET = os.environ["AWS_SECRET_ACCESS_KEY"]
BUCKET = os.environ["VAULTDROP_S3_BUCKET"]


def call(method: str, path: str, body: dict | None = None) -> dict:
    request = urllib.request.Request(
        f"{ADMIN}/{path}",
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read() or b"{}")


def wait_for_admin() -> dict:
    for _ in range(60):
        try:
            return call("GET", "GetClusterStatus")
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            time.sleep(1)
    sys.exit("garage admin API never became reachable")


def main() -> None:
    status = wait_for_admin()
    node = status["nodes"][0]["id"]
    if status["layoutVersion"] == 0:
        call(
            "POST",
            "UpdateClusterLayout",
            {"roles": [{"id": node, "zone": "local", "capacity": 1_073_741_824, "tags": []}]},
        )
        call("POST", "ApplyClusterLayout", {"version": 1})
        print("layout applied")
    try:
        call(
            "POST",
            "ImportKey",
            {"name": "vaultdrop", "accessKeyId": KEY_ID, "secretAccessKey": SECRET},
        )
        print("key imported")
    except urllib.error.HTTPError as error:
        if error.code not in (409, 400):
            raise
    try:
        bucket = call("POST", "CreateBucket", {"globalAlias": BUCKET})
        print("bucket created")
    except urllib.error.HTTPError as error:
        if error.code != 409:
            raise
        bucket = call("GET", f"GetBucketInfo?globalAlias={BUCKET}")
    call(
        "POST",
        "AllowBucketKey",
        {
            "bucketId": bucket["id"],
            "accessKeyId": KEY_ID,
            "permissions": {"read": True, "write": True, "owner": True},
        },
    )
    print("garage ready")


if __name__ == "__main__":
    main()

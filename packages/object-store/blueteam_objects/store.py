"""Raw event / evidence object store. Local filesystem is always real; S3 is optional."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

from blueteam_common.hashing import sha256_hex
from blueteam_common.ids import new_id


@dataclass(frozen=True)
class ObjectRef:
    object_id: str
    uri: str
    sha256: str
    bytes_written: int
    backend: str


class ObjectStore(Protocol):
    backend: str

    def put(self, tenant_id: str, key: str, payload: bytes, *, content_type: str = "application/json") -> ObjectRef: ...

    def get(self, uri: str) -> bytes: ...

    def ping(self) -> bool: ...


class LocalObjectStore:
    backend = "local"

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, tenant_id: str, key: str, payload: bytes, *, content_type: str = "application/json") -> ObjectRef:
        digest = sha256_hex(payload)
        safe_key = key.replace("\\", "/").lstrip("/")
        path = self.root / tenant_id / safe_key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        uri = f"local://{tenant_id}/{safe_key}"
        return ObjectRef(new_id("obj"), uri, digest, len(payload), self.backend)

    def get(self, uri: str) -> bytes:
        if not uri.startswith("local://"):
            raise ValueError("not a local object uri")
        relative = uri.removeprefix("local://")
        path = self.root / relative
        return path.read_bytes()

    def ping(self) -> bool:
        self.root.mkdir(parents=True, exist_ok=True)
        probe = self.root / ".health"
        probe.write_text("ok", encoding="utf-8")
        return probe.read_text(encoding="utf-8") == "ok"


class S3ObjectStore:
    """Path-style S3/MinIO PUT/GET. Missing credentials stay unconfigured, not faked."""

    backend = "s3"

    def __init__(self, endpoint: str, bucket: str, access_key: str, secret_key: str) -> None:
        if not endpoint or not access_key or not secret_key:
            raise ValueError("s3 endpoint and credentials are required")
        self.endpoint = endpoint.rstrip("/")
        self.bucket = bucket
        self.access_key = access_key
        self.secret_key = secret_key

    def _url(self, key: str) -> str:
        return f"{self.endpoint}/{self.bucket}/{key}"

    def put(self, tenant_id: str, key: str, payload: bytes, *, content_type: str = "application/json") -> ObjectRef:
        import httpx

        object_key = f"{tenant_id}/{key}"
        digest = sha256_hex(payload)
        response = httpx.put(
            self._url(object_key),
            content=payload,
            headers={
                "Content-Type": content_type,
                "x-amz-content-sha256": digest,
                "Authorization": f"AWS {self.access_key}:{_unsigned_hint(self.secret_key)}",
            },
            timeout=8.0,
        )
        if response.status_code >= 400:
            raise RuntimeError(f"s3 put failed: {response.status_code}")
        return ObjectRef(new_id("obj"), f"s3://{self.bucket}/{object_key}", digest, len(payload), self.backend)

    def get(self, uri: str) -> bytes:
        import httpx

        key = uri.split(f"s3://{self.bucket}/", 1)[-1] if uri.startswith("s3://") else uri
        response = httpx.get(self._url(key), timeout=8.0)
        response.raise_for_status()
        return response.content

    def ping(self) -> bool:
        import httpx

        response = httpx.get(f"{self.endpoint}/{self.bucket}", timeout=4.0)
        return response.status_code < 500


def _unsigned_hint(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def open_store(*, root: str | Path | None = None, endpoint: str = "", bucket: str = "", access_key: str = "", secret_key: str = "") -> ObjectStore:
    if endpoint and access_key and secret_key:
        return S3ObjectStore(endpoint, bucket or "blueteam-evidence", access_key, secret_key)
    parsed = urlparse(str(root or "./data/objects"))
    path = parsed.path or str(root or "./data/objects")
    return LocalObjectStore(path)

"""Private object storage for original email evidence and generated reports.

Local mode preserves the existing developer workflow. Supabase mode stores
objects in a private bucket using the service-role key on the backend only.
"""
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import httpx

from backend.app.core.config import settings


class ArtifactStorageError(RuntimeError):
    """Raised when an evidence object cannot be stored or retrieved safely."""


def is_remote_storage() -> bool:
    return settings.EVIDENCE_STORAGE_BACKEND == "supabase"


def validate_storage_configuration() -> None:
    backend = settings.EVIDENCE_STORAGE_BACKEND
    if backend not in {"local", "supabase"}:
        raise ArtifactStorageError("Unsupported evidence storage backend")
    if backend == "supabase":
        if not settings.SUPABASE_URL.startswith("https://") or not settings.SUPABASE_SERVICE_ROLE_KEY:
            raise ArtifactStorageError("Supabase evidence storage is not configured")
        if not settings.SUPABASE_BUCKET:
            raise ArtifactStorageError("Supabase storage bucket is not configured")


def _safe_key(key: str) -> str:
    if not isinstance(key, str) or not key or "\\" in key:
        raise ArtifactStorageError("Invalid object key")
    path = PurePosixPath(key)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ArtifactStorageError("Invalid object key")
    return str(path)


def _local_path(key: str) -> Path:
    key = _safe_key(key)
    if key.startswith("reports/"):
        root = Path(settings.REPORTS_DIR).resolve()
        relative = key[len("reports/"):]
    else:
        root = Path(settings.UPLOAD_DIR).resolve()
        relative = key
    destination = (root / relative).resolve()
    if not destination.is_relative_to(root):
        raise ArtifactStorageError("Object key escapes configured storage root")
    return destination


def _remote_url(key: str | None = None) -> str:
    validate_storage_configuration()
    base = settings.SUPABASE_URL.rstrip("/")
    bucket = quote(settings.SUPABASE_BUCKET, safe="")
    suffix = f"/{quote(key, safe='/')}" if key else ""
    return f"{base}/storage/v1/object/{bucket}{suffix}"


def _remote_headers(content_type: str | None = None) -> dict:
    headers = {
        "apikey": settings.SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {settings.SUPABASE_SERVICE_ROLE_KEY}",
    }
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def put_bytes(key: str, content: bytes, content_type: str = "application/octet-stream") -> str:
    """Store a new private object without overwriting an existing object."""
    key = _safe_key(key)
    if not isinstance(content, bytes):
        raise TypeError("Storage payload must be bytes")
    if is_remote_storage():
        try:
            with httpx.Client(timeout=settings.STORAGE_TIMEOUT_SECONDS) as client:
                response = client.post(
                    _remote_url(key),
                    content=content,
                    headers={**_remote_headers(content_type), "x-upsert": "false"},
                )
                response.raise_for_status()
        except httpx.HTTPError as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            raise ArtifactStorageError(f"Remote evidence upload failed (HTTP {status or 'network error'})") from exc
    else:
        path = _local_path(key)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = None
        try:
            import os
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            raise ArtifactStorageError("An object with this key already exists")
        except Exception:
            if descriptor is not None:
                import os
                os.close(descriptor)
            path.unlink(missing_ok=True)
            raise
    return key


def get_bytes(key: str) -> bytes:
    """Read a private object. Missing objects raise FileNotFoundError."""
    key = _safe_key(key)
    if is_remote_storage():
        try:
            with httpx.Client(timeout=settings.STORAGE_TIMEOUT_SECONDS) as client:
                response = client.get(_remote_url(key), headers=_remote_headers())
                if response.status_code == 404:
                    raise FileNotFoundError(key)
                response.raise_for_status()
                return response.content
        except FileNotFoundError:
            raise
        except httpx.HTTPError as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            raise ArtifactStorageError(f"Remote evidence download failed (HTTP {status or 'network error'})") from exc
    path = _local_path(key)
    if not path.is_file():
        raise FileNotFoundError(key)
    return path.read_bytes()


def delete_object(key: str) -> None:
    """Delete one object, primarily for transaction rollback cleanup."""
    key = _safe_key(key)
    if is_remote_storage():
        try:
            with httpx.Client(timeout=settings.STORAGE_TIMEOUT_SECONDS) as client:
                response = client.request(
                    "DELETE",
                    _remote_url(),
                    json={"prefixes": [key]},
                    headers=_remote_headers("application/json"),
                )
                response.raise_for_status()
        except httpx.HTTPError as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            raise ArtifactStorageError(f"Remote evidence cleanup failed (HTTP {status or 'network error'})") from exc
    else:
        _local_path(key).unlink(missing_ok=True)

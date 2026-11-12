import httpx
import pytest

from backend.app.core.config import settings
from backend.app.services import artifact_storage


def test_local_storage_round_trip_and_permissions(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "EVIDENCE_STORAGE_BACKEND", "local")
    monkeypatch.setattr(settings, "UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setattr(settings, "REPORTS_DIR", str(tmp_path / "reports"))

    assert artifact_storage.put_bytes("ART-test.eml", b"original bytes", "message/rfc822") == "ART-test.eml"
    stored = tmp_path / "uploads" / "ART-test.eml"
    assert stored.read_bytes() == b"original bytes"
    assert stored.stat().st_mode & 0o777 == 0o600
    assert artifact_storage.get_bytes("ART-test.eml") == b"original bytes"

    report_key = "reports/session/report.pdf"
    artifact_storage.put_bytes(report_key, b"%PDF synthetic", "application/pdf")
    assert (tmp_path / "reports" / "session" / "report.pdf").read_bytes() == b"%PDF synthetic"
    artifact_storage.delete_object(report_key)
    assert not (tmp_path / "reports" / "session" / "report.pdf").exists()


@pytest.mark.parametrize("key", ["../outside", "/absolute", "folder/../../outside", r"folder\\outside"])
def test_storage_rejects_unsafe_object_keys(key):
    with pytest.raises(artifact_storage.ArtifactStorageError):
        artifact_storage.put_bytes(key, b"no")


def test_supabase_storage_uses_authenticated_private_object_api(monkeypatch):
    monkeypatch.setattr(settings, "EVIDENCE_STORAGE_BACKEND", "supabase")
    monkeypatch.setattr(settings, "SUPABASE_URL", "https://project-ref.supabase.co")
    monkeypatch.setattr(settings, "SUPABASE_SERVICE_ROLE_KEY", "server-only-test-key")
    monkeypatch.setattr(settings, "SUPABASE_BUCKET", "private-evidence")

    seen = []
    def handler(request):
        seen.append(request)
        if request.method == "POST":
            return httpx.Response(200, json={"Key": "private-evidence/ART-test.eml"}, request=request)
        if request.method == "GET":
            return httpx.Response(200, content=b"remote evidence", request=request)
        if request.method == "DELETE":
            return httpx.Response(200, json={"message": "success"}, request=request)
        return httpx.Response(405, request=request)

    original_client = httpx.Client
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(artifact_storage.httpx, "Client", lambda **kwargs: original_client(transport=transport, **kwargs))

    artifact_storage.put_bytes("ART-test.eml", b"remote evidence", "message/rfc822")
    assert artifact_storage.get_bytes("ART-test.eml") == b"remote evidence"
    artifact_storage.delete_object("ART-test.eml")

    assert [request.method for request in seen] == ["POST", "GET", "DELETE"]
    assert all(request.headers["authorization"] == "Bearer server-only-test-key" for request in seen)
    assert seen[0].headers["content-type"] == "message/rfc822"
    assert seen[0].content == b"remote evidence"
    assert seen[0].headers["x-upsert"] == "false"
    assert seen[2].url.path.endswith("/storage/v1/object/private-evidence")
    assert "ART-test.eml" in seen[2].read().decode()


def test_supabase_storage_maps_missing_object_to_file_not_found(monkeypatch):
    monkeypatch.setattr(settings, "EVIDENCE_STORAGE_BACKEND", "supabase")
    monkeypatch.setattr(settings, "SUPABASE_URL", "https://project-ref.supabase.co")
    monkeypatch.setattr(settings, "SUPABASE_SERVICE_ROLE_KEY", "server-only-test-key")
    monkeypatch.setattr(settings, "SUPABASE_BUCKET", "private-evidence")

    original_client = httpx.Client
    transport = httpx.MockTransport(lambda request: httpx.Response(404, request=request))
    monkeypatch.setattr(artifact_storage.httpx, "Client", lambda **kwargs: original_client(transport=transport, **kwargs))
    with pytest.raises(FileNotFoundError):
        artifact_storage.get_bytes("missing.eml")

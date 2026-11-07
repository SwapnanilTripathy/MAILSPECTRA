"""Restricted original evidence storage; never serves raw bytes as web content."""
import hashlib
import os
import uuid
from pathlib import Path
from datetime import datetime, timezone
from backend.app.core.config import settings
from backend.app.schemas.analysis import ArtifactMetadata, EvidenceObservation


def preserve(raw: bytes, filename: str, actor: str):
    root = Path(settings.UPLOAD_DIR).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    artifact_id = "ART-" + uuid.uuid4().hex
    storage_name = artifact_id + ".eml"
    path = root / storage_name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    metadata = ArtifactMetadata(artifact_id=artifact_id, sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw), filename=Path(filename.replace("\\", "/")).name[:255], actor=actor, ingested_at=datetime.now(timezone.utc).isoformat())
    return metadata, path


def observations(analysis):
    artifact = analysis.artifact
    if not artifact:
        return
    items = []
    for kind, values, field in [("URL", analysis.urls, "url"), ("IP", analysis.ips, "ip"), ("ATTACHMENT_SHA256", analysis.attachments, "sha256")]:
        for index, value in enumerate(values):
            text = getattr(value, field)
            oid = hashlib.sha256(f"{artifact.artifact_id}:{kind}:{index}:{text}".encode()).hexdigest()[:24]
            items.append(EvidenceObservation(observation_id="OBS-"+oid, observation_type=kind, value=text, source_artifact_id=artifact.artifact_id, source_location={"kind":getattr(value,"source","ATTACHMENT"), "index":index}, observed_at=artifact.ingested_at))
    analysis.observations = items
    analysis.evidence_manifest = {"schema_version":"1.0", "artifact":artifact.model_dump(), "analysis_version":analysis.schema_version, "observation_ids":[i.observation_id for i in items], "limitations":["Hashes detect changes relative to stored digests; they do not establish an external chain of custody.", "Legacy cases may lack original artifacts."]}

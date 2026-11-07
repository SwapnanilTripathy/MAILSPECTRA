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
    def add(kind, value, pointer, status="OBSERVED_UNVERIFIED", **location):
        oid = hashlib.sha256(f"{artifact.artifact_id}:{kind}:{pointer}:{value}".encode()).hexdigest()[:24]
        items.append(EvidenceObservation(observation_id="OBS-"+oid, observation_type=kind, value=str(value), source_artifact_id=artifact.artifact_id, source_location={"snapshot_pointer":pointer, "character_offsets":None, "offset_limitation":"Exact character offsets unavailable", **location}, observed_at=artifact.ingested_at, verification_status=status, parser_version=artifact.parser_version))
    counts = {}
    for index, header in enumerate(analysis.metadata.raw_headers):
        name = header['name'].lower()
        occurrence = counts.get(name, 0); counts[name] = occurrence + 1
        add('HEADER', header['value'], f'/metadata/raw_headers/{index}', header_name=name, occurrence_index=occurrence, extraction_area='header')
    for index, hop in enumerate(analysis.relay_chain.hops):
        add('RELAY', hop.raw_header, f'/relay_chain/hops/{index}', extraction_area='Received header', header_name='received', occurrence_index=len(analysis.relay_chain.hops)-1-index)
    for kind, values, field, collection in [("URL", analysis.urls, "url", "urls"), ("IP", analysis.ips, "ip", "ips"), ("ATTACHMENT_SHA256", analysis.attachments, "sha256", "attachments")]:
        for index, value in enumerate(values):
            location = {"extraction_area":getattr(value,"source","MIME_ATTACHMENT"), "locations":getattr(value,"source_locations",[])}
            if kind == 'ATTACHMENT_SHA256':
                location.update(mime_part_index=value.mime_part_index, filename=value.filename)
            add(kind, getattr(value,field), f'/{collection}/{index}', **location)
    intel = analysis.infrastructure_intelligence
    if intel:
        for collection in ('ip_intelligence','domain_intelligence','reputation_intelligence'):
            for key, value in getattr(intel,collection).items():
                escaped = key.replace('~','~0').replace('/','~1')
                add('ENRICHMENT', key, f'/infrastructure_intelligence/{collection}/{escaped}', 'PROVIDER_REPORTED' if intel.mode=='live' else 'NOT_APPLICABLE', origin='external_provider' if intel.mode=='live' else 'offline_fixture', provider_metadata=value.model_dump())
    analysis.observations = items
    analysis.evidence_manifest = {"schema_version":"1.1", "artifact":artifact.model_dump(), "hash_algorithm":"SHA-256", "parser_version":artifact.parser_version, "analysis_version":analysis.schema_version, "observation_ids":[i.observation_id for i in items], "observations":[i.model_dump() for i in items], "verification_status":"PRESENT_UNVERIFIED", "verification_method":"No independently stored manifest digest", "privacy_redaction_applied":False, "limitations":["Hashes detect changes relative to stored digests; they do not establish authenticity or an external chain of custody.", "Parsed observations remain unverified regardless of artifact digest integrity.", "Legacy cases may lack original artifacts."]}

"""Inspect evidence storage without modifying files or database records.

Run with the application's DATABASE_URL, UPLOAD_DIR and REPORTS_DIR configuration:
python -m backend.app.evidence_audit
Exit 0: referenced files match; exit 2: missing/changed/unsafe references or orphan files.
"""
import asyncio
import hashlib
import json
from pathlib import Path
from sqlalchemy import select
from backend.app.core.config import settings
from backend.app.database.session import AsyncSessionLocal
from backend.app.models.entities import ArtifactRecord, CaseRecord


def inspect_file(root, path, expected):
    root = Path(root).resolve()
    path = Path(path)
    # Do not follow symlinks, even if their destination is inside the evidence root.
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        return 'UNSAFE_PATH'
    try:
        relative = path.absolute().relative_to(root)
        ancestor = root
        for part in relative.parts:
            ancestor = ancestor / part
            if ancestor.is_symlink(): return 'UNSAFE_PATH'
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024*1024),b''): digest.update(block)
        return 'MATCH' if digest.hexdigest()==expected else 'MISMATCH'
    except FileNotFoundError: return 'MISSING'
    except (OSError,ValueError): return 'UNREADABLE'


async def audit_storage(db, upload_root, report_root):
    upload_root,report_root=Path(upload_root).resolve(),Path(report_root).resolve()
    records=[]; expected_uploads=set();expected_reports=set()
    for artifact in (await db.scalars(select(ArtifactRecord))).all():
        path=upload_root/artifact.storage_name
        expected_uploads.add(path.absolute())
        records.append({'kind':'ORIGINAL','case_id':artifact.case_id,'status':inspect_file(upload_root,path,artifact.sha256)})
    for case in (await db.scalars(select(CaseRecord).where(CaseRecord.report_path.is_not(None)))).all():
        path=Path(case.report_path).absolute();expected_reports.add(path)
        records.append({'kind':'REPORT','case_id':case.case_id,'status':inspect_file(report_root,path,case.report_sha256)})
        manifest=Path(str(path)+'.manifest.json');expected_reports.add(manifest)
        # Manifests have no independent recorded digest; inspect existence only.
        records.append({'kind':'MANIFEST','case_id':case.case_id,'status':'PRESENT_UNVERIFIED' if manifest.is_file() and not manifest.is_symlink() and manifest.resolve().is_relative_to(report_root) else 'MISSING_OR_UNSAFE'})
    unreferenced=[]
    for kind,root,expected in [('ORIGINAL',upload_root,expected_uploads),('REPORT',report_root,expected_reports)]:
        if not root.is_dir(): continue
        for path in root.iterdir():
            if path.name.startswith('.'): continue
            if path.absolute() not in expected:
                unreferenced.append({'kind':kind,'name':path.name,'status':'REVIEW_REQUIRED'})
    return {'generated_by':'MAILSPECTRA','read_only':True,'records':records,'unreferenced':unreferenced,
        'limitations':['Unreferenced reports can be previous report versions, not disposable files.',
        'Quiesce writes for a stable inventory; concurrent writes can change this result.',
        'No deletion occurs. Apply an approved retention and legal-hold policy before cleanup.',
        'Manifest presence is not independent integrity verification.']}


async def main():
    async with AsyncSessionLocal() as db:
        report=await audit_storage(db,settings.UPLOAD_DIR,settings.REPORTS_DIR)
    print(json.dumps(report,indent=2))
    return 2 if report['unreferenced'] or any(r['status'] not in {'MATCH','PRESENT_UNVERIFIED'} for r in report['records']) else 0

if __name__=='__main__':
    raise SystemExit(asyncio.run(main()))

import hashlib
from backend.app.evidence_audit import inspect_file


def test_file_audit_detects_change_without_altering_bytes(tmp_path):
    p=tmp_path/'original.eml';p.write_bytes(b'original evidence')
    expected=hashlib.sha256(p.read_bytes()).hexdigest()
    assert inspect_file(tmp_path,p,expected)=='MATCH'
    p.write_bytes(b'changed evidence')
    assert inspect_file(tmp_path,p,expected)=='MISMATCH'
    assert p.read_bytes()==b'changed evidence'
    assert inspect_file(tmp_path,tmp_path/'missing',expected)=='MISSING'


def test_file_audit_never_follows_symlinks_or_external_paths(tmp_path):
    root=tmp_path/'uploads';root.mkdir()
    outside=tmp_path/'private';outside.write_bytes(b'outside')
    link=root/'link';link.symlink_to(outside)
    assert inspect_file(root,link,'')=='UNSAFE_PATH'
    assert inspect_file(root,outside,'')=='UNSAFE_PATH'
    directory=root/'linked-dir';directory.symlink_to(tmp_path,target_is_directory=True)
    assert inspect_file(root,directory/'private','')=='UNSAFE_PATH'

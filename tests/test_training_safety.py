from pathlib import Path

import pytest

from backend.app.ml.model_loader import ModelBundle, ModelLoader
from backend.app.ml.train_model import train_and_evaluate


def test_training_rejects_deployed_artifact_before_reading_dataset(tmp_path, monkeypatch):
    deployed = tmp_path / 'deployed' / 'threat_classifier.joblib'
    deployed.parent.mkdir()
    deployed.write_bytes(b'original artifact')
    monkeypatch.setattr(ModelLoader, 'get_model_path', classmethod(lambda cls: deployed))
    candidate_dir = tmp_path / 'candidate'
    candidate_dir.mkdir()
    (candidate_dir / deployed.name).symlink_to(deployed)
    for output in (deployed.parent, candidate_dir):
        with pytest.raises(ValueError, match='cannot overwrite'):
            train_and_evaluate(Path('nonexistent-dataset.json'), output)
    assert deployed.read_bytes() == b'original artifact'


def test_saving_candidate_preserves_active_model_cache(tmp_path, monkeypatch):
    active = ModelBundle(None, None, None, [], [], {'version': 'active'})
    candidate = ModelBundle(None, None, None, [], [], {'version': 'candidate'})
    monkeypatch.setattr(ModelLoader, '_cached_bundle', active)
    monkeypatch.setattr(ModelLoader, 'get_model_path', classmethod(lambda cls: tmp_path / 'active.joblib'))
    output = ModelLoader.save_model(candidate, tmp_path / 'candidate.joblib')
    assert output.exists()
    assert ModelLoader.load_model() is active

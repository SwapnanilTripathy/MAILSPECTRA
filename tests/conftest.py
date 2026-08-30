from pathlib import Path
import pytest
from backend.app.database.session import init_db


SAMPLES_DIR = Path(__file__).parent.parent / "data" / "samples"


@pytest.fixture(autouse=True)
async def setup_test_db():
    await init_db()



@pytest.fixture
def benign_eml_path() -> Path:
    return SAMPLES_DIR / "benign_standard.eml"


@pytest.fixture
def benign_eml_bytes(benign_eml_path) -> bytes:
    return benign_eml_path.read_bytes()


@pytest.fixture
def phishing_eml_path() -> Path:
    return SAMPLES_DIR / "phishing_credential_harvest.eml"


@pytest.fixture
def phishing_eml_bytes(phishing_eml_path) -> bytes:
    return phishing_eml_path.read_bytes()


@pytest.fixture
def spoofed_eml_path() -> Path:
    return SAMPLES_DIR / "spoofed_spf_fail.eml"


@pytest.fixture
def spoofed_eml_bytes(spoofed_eml_path) -> bytes:
    return spoofed_eml_path.read_bytes()

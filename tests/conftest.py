from pathlib import Path
import pytest
from backend.app.database.session import init_db


SAMPLES_DIR = Path(__file__).parent.parent / "data" / "samples"


@pytest.fixture(autouse=True)
async def setup_test_db():
    await init_db()
    yield
    # Async PostgreSQL connections belong to the event loop that created them.
    from backend.app.database.session import engine
    await engine.dispose()



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


@pytest.fixture
async def auth_headers():
    from sqlalchemy import select, delete
    from backend.app.database.session import AsyncSessionLocal
    from backend.app.models.entities import UserRecord, LoginAttemptRecord
    from backend.app.core.security import hash_password
    from backend.app.main import app
    from httpx import AsyncClient, ASGITransport
    async with AsyncSessionLocal() as db:
        if not await db.scalar(select(UserRecord).where(UserRecord.username == "test-admin")):
            db.add(UserRecord(username="test-admin", role="admin", hashed_password=hash_password("test-only-long-password")))
        await db.execute(delete(LoginAttemptRecord))
        await db.commit()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/auth/login", json={"username": "test-admin", "password": "test-only-long-password"})
        assert response.status_code == 200
        return {"Authorization": "Bearer " + response.json()["access_token"]}

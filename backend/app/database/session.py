from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from backend.app.core.config import settings
from backend.app.database.base import Base
import backend.app.models.entities  # Ensure all ORM models are registered


# Create async database engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG and settings.APP_ENV == "development",
    future=True,
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def init_db() -> None:
    """Migrate development databases; production requires explicit operator migration."""
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import text
    from pathlib import Path
    async with engine.begin() as conn:
        if settings.APP_ENV == "production":
            revision = (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar()
            if revision != "0002":
                raise RuntimeError("Database migration required: run alembic upgrade head")
        else:
            def migrate(connection):
                config = Config(str(Path(__file__).resolve().parents[3] / "alembic.ini"))
                config.attributes["connection"] = connection
                command.upgrade(config, "head")
            await conn.run_sync(migrate)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for obtaining async database sessions."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

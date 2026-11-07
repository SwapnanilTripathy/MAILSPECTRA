import asyncio
from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine
from backend.app.core.config import settings
from backend.app.database.base import Base
import backend.app.models.entities

config = context.config

def run(connection):
    context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()

async def online():
    engine = create_async_engine(settings.DATABASE_URL)
    async with engine.connect() as connection:
        await connection.run_sync(run)
    await engine.dispose()

if config.attributes.get('connection') is not None:
    run(config.attributes['connection'])
else:
    asyncio.run(online())

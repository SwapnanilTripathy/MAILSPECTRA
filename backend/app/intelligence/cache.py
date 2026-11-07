import json
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from backend.app.database.session import AsyncSessionLocal
from backend.app.models.entities import IntelligenceCacheRecord
from backend.app.core.config import settings

async def cached_lookup(key, provider, operation):
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        cached = await db.get(IntelligenceCacheRecord, key)
        if cached and cached.expires_at.replace(tzinfo=timezone.utc) > now:
            payload = json.loads(cached.response_json)
            payload['cache_hit'] = True
            return payload
        payload = await operation()
        # Do not cache errors/rate limits or claim fresh results after expiration.
        if payload.get('status') in {'AVAILABLE','SUCCESS','FIXTURE'}:
            record = cached or IntelligenceCacheRecord(cache_key=key)
            record.provider=provider; record.response_json=json.dumps(payload)
            record.status=payload['status']; record.expires_at=now+timedelta(hours=settings.CACHE_TTL_HOURS)
            db.add(record)
            try: await db.commit()
            except Exception: await db.rollback()  # Concurrent cache writes cannot invalidate a lookup.
        return payload

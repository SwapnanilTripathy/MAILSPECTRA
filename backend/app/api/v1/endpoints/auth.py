from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from jose import jwt
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool
from backend.app.core.config import settings
from backend.app.core.security import current_user, hash_password, verify_password
from backend.app.database.session import get_db
from backend.app.models.entities import AuditLogRecord, UserRecord, SessionRecord, LoginAttemptRecord

router = APIRouter()
# Equal-cost password work for unknown accounts. No usable default account exists.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(32))

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=256)

class UserProfile(BaseModel):
    username: str
    full_name: str
    role: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserProfile


def profile(user):
    return UserProfile(username=user.username, full_name=user.full_name, role=user.role)


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=settings.LOGIN_WINDOW_SECONDS)
    # Ignore forwarded headers: the deployment proxy must enforce its own global limit.
    bucket = hashlib.sha256((request.client.host if request.client else "unknown").encode()).hexdigest()
    await db.execute(delete(LoginAttemptRecord).where(LoginAttemptRecord.attempted_at < cutoff))
    count = await db.scalar(select(func.count()).select_from(LoginAttemptRecord).where(LoginAttemptRecord.bucket == bucket))
    if count >= settings.LOGIN_ATTEMPT_LIMIT:
        raise HTTPException(429, "Too many login attempts; try again later", headers={"Retry-After": str(settings.LOGIN_WINDOW_SECONDS)})
    db.add(LoginAttemptRecord(bucket=bucket, attempted_at=now))
    await db.commit()
    user = await db.scalar(select(UserRecord).where(UserRecord.username == payload.username.lower()))
    valid = await run_in_threadpool(verify_password, payload.password, user.hashed_password if user else _DUMMY_HASH)
    if not user or not valid or not user.is_active or user.role not in {"admin", "analyst", "viewer"}:
        raise HTTPException(401, "Invalid credentials")
    expires = now + timedelta(minutes=settings.ACCESS_TOKEN_MINUTES)
    session_id = secrets.token_hex(32)
    db.add(SessionRecord(session_id=session_id, user_id=user.id, expires_at=expires))
    db.add(AuditLogRecord(action="USER_LOGIN", actor=user.username, details="Session created"))
    await db.commit()
    token = jwt.encode({"sub": str(user.id), "jti": session_id, "exp": expires, "iat": now, "iss": settings.TOKEN_ISSUER, "aud": "mailspectra-api", "type": "access"}, settings.SECRET_KEY, algorithm="HS256")
    return LoginResponse(access_token=token, expires_in=settings.ACCESS_TOKEN_MINUTES*60, user=profile(user))


@router.get("/me", response_model=UserProfile)
async def me(user: UserRecord = Depends(current_user)):
    return profile(user)


@router.post("/logout")
async def logout(request: Request, user: UserRecord = Depends(current_user), db: AsyncSession = Depends(get_db)):
    session = await db.get(SessionRecord, request.state.session_id)
    session.revoked = True
    db.add(AuditLogRecord(action="USER_LOGOUT", actor=user.username, details="Session revoked"))
    await db.commit()
    return {"status": "SUCCESS"}

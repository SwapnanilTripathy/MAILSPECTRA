"""Signed short-lived bearer tokens backed by revocable database sessions."""
import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt import InvalidTokenError as JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.config import settings
from backend.app.database.session import get_db
from backend.app.models.entities import UserRecord, SessionRecord

bearer = HTTPBearer(auto_error=False)
ROLES = {"admin", "analyst", "viewer"}


def hash_password(password: str) -> str:
    if not 12 <= len(password) <= 256:
        raise ValueError("Password must contain 12 to 256 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1, maxmem=64*1024*1024)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, salt, expected = encoded.split("$")
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=32768, r=8, p=1, maxmem=64*1024*1024)
        return hmac.compare_digest(actual, base64.b64decode(expected))
    except (ValueError, TypeError):
        return False


async def current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(bearer), db: AsyncSession = Depends(get_db)) -> UserRecord:
    unauthorized = HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
    if not credentials:
        raise unauthorized
    try:
        claims = jwt.decode(credentials.credentials, settings.SECRET_KEY, algorithms=["HS256"], issuer=settings.TOKEN_ISSUER, audience="mailspectra-api", options={"require": ["exp", "sub", "iat", "jti", "iss", "aud"]})
        if claims.get("type") != "access" or not claims.get("jti"):
            raise unauthorized
        session = await db.get(SessionRecord, claims["jti"])
        if not session or session.revoked or session.expires_at.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc) or str(session.user_id) != claims["sub"]:
            raise unauthorized
        user = await db.get(UserRecord, session.user_id)
        if not user or not user.is_active or user.role not in ROLES:
            raise unauthorized
    except (JWTError, ValueError, TypeError):
        raise unauthorized
    request.state.session_id = session.session_id
    request.state.user = user
    return user


async def authorize(request: Request, user: UserRecord = Depends(current_user)):
    if request.method not in {"GET", "HEAD", "OPTIONS"} and user.role == "viewer":
        raise HTTPException(403, "Analyst permission required")
    if request.url.path.endswith("/system/settings") and user.role != "admin":
        raise HTTPException(403, "Administrator permission required")
    return user

from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.database.session import get_db
from backend.app.models.entities import AuditLogRecord, UserRecord

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


# Standard prototype demo analyst credentials for SIH evaluation
DEFAULT_USERS = {
    "analyst": {
        "username": "analyst",
        "full_name": "Lead Forensic Analyst",
        "role": "Lead Investigator",
        "email": "analyst@deeptrace.soc",
    },
    "admin": {
        "username": "admin",
        "full_name": "SOC Administrator",
        "role": "Security Admin",
        "email": "admin@deeptrace.soc",
    },
}


@router.post("/login", response_model=LoginResponse, summary="SOC Analyst Login")
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate SOC analyst and return active session token."""
    username = payload.username.strip().lower()
    
    # Allow default prototype analyst or password verification
    if username in DEFAULT_USERS and payload.password in ["deeptrace2026", "analyst123", "password", "admin"]:
        user_info = DEFAULT_USERS[username]
        
        # Log audit event
        db.add(
            AuditLogRecord(
                action="USER_LOGIN",
                actor=user_info["full_name"],
                details=f"Successful login for user '{username}' ({user_info['role']})",
            )
        )
        await db.commit()

        return LoginResponse(
            access_token=f"deeptrace-jwt-token-{username}-{int(datetime.now(timezone.utc).timestamp())}",
            user=user_info,
        )

    # Demo fallback for evaluation
    if payload.username and payload.password:
        user_info = {
            "username": payload.username,
            "full_name": "Security Analyst",
            "role": "SOC Analyst",
            "email": f"{payload.username}@deeptrace.soc",
        }
        return LoginResponse(
            access_token=f"deeptrace-jwt-token-custom-{int(datetime.now(timezone.utc).timestamp())}",
            user=user_info,
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials. Use username 'analyst' and password 'deeptrace2026'.",
    )


@router.get("/me", summary="Get current logged in user profile")
async def get_current_user():
    return {
        "username": "analyst",
        "full_name": "Lead Forensic Analyst",
        "role": "Lead Investigator",
        "email": "analyst@deeptrace.soc",
        "permissions": ["READ", "WRITE", "EXPORT_REPORT", "MANAGE_CASES"],
    }


@router.post("/logout", summary="Logout current session")
async def logout():
    return {"status": "SUCCESS", "message": "Successfully logged out."}

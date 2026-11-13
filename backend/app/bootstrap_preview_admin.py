"""Create an explicitly configured preview-only admin after database migrations.

Set PREVIEW_ADMIN_USERNAME and PREVIEW_ADMIN_PASSWORD on the preview service
to provision an admin account. With neither variable set, this module is a no-op.
Existing accounts are never modified.
"""
import asyncio
import os
import re

from sqlalchemy import select

from backend.app.core.security import hash_password
from backend.app.database.session import AsyncSessionLocal
from backend.app.models.entities import UserRecord


async def bootstrap_preview_admin() -> None:
    username = os.getenv("PREVIEW_ADMIN_USERNAME", "").strip().lower()
    password = os.getenv("PREVIEW_ADMIN_PASSWORD", "")

    if not username and not password:
        return
    if not username or not password:
        raise RuntimeError(
            "Set both PREVIEW_ADMIN_USERNAME and PREVIEW_ADMIN_PASSWORD, or neither."
        )
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", username):
        raise RuntimeError("PREVIEW_ADMIN_USERNAME contains unsupported characters.")
    if not 12 <= len(password) <= 256:
        raise RuntimeError("PREVIEW_ADMIN_PASSWORD must be 12–256 characters.")

    async with AsyncSessionLocal() as db:
        existing = await db.scalar(
            select(UserRecord).where(UserRecord.username == username)
        )
        if existing:
            if existing.role != "admin":
                raise RuntimeError(
                    "Preview bootstrap account exists but is not an admin; "
                    "refusing to change an existing account."
                )
            print("Preview admin already exists; no changes made.")
            return

        db.add(
            UserRecord(
                username=username,
                full_name="Preview Administrator",
                role="admin",
                hashed_password=hash_password(password),
            )
        )
        await db.commit()

    print("Preview admin account created.")


if __name__ == "__main__":
    asyncio.run(bootstrap_preview_admin())

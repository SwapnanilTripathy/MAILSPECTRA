"""Run after migrations: python -m backend.app.manage_users USERNAME --role admin."""
import argparse
import asyncio
import getpass
from sqlalchemy import select
from backend.app.database.session import AsyncSessionLocal
from backend.app.models.entities import UserRecord
from backend.app.core.security import hash_password

async def create_user(username, role):
    import re
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", username):
        raise SystemExit("Invalid username")
    password = getpass.getpass("Password (12–256 characters): ")
    if password != getpass.getpass("Confirm password: "):
        raise SystemExit("Passwords do not match")
    async with AsyncSessionLocal() as db:
        if await db.scalar(select(UserRecord).where(UserRecord.username == username.lower())):
            raise SystemExit("Account already exists; no changes made")
        db.add(UserRecord(username=username.lower(), full_name=username, role=role, hashed_password=hash_password(password)))
        await db.commit()
    print("Account created")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username")
    parser.add_argument("--role", choices=["admin", "analyst", "viewer"], default="analyst")
    args = parser.parse_args()
    asyncio.run(create_user(args.username, args.role))

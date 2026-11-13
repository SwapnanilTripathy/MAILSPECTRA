#!/bin/sh
set -eu

python -m alembic upgrade head
python -m backend.app.bootstrap_preview_admin
exec python backend/run.py

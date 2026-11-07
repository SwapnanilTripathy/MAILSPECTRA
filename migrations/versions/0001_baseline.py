"""Adopt the existing schema without dropping or overwriting records."""
from alembic import op
from migrations.baseline_schema import Base
revision = '0001'
down_revision = None

def upgrade():
    Base.metadata.create_all(op.get_bind(), checkfirst=True)

def downgrade():
    raise RuntimeError('Restore a backup to remove the baseline; automatic data deletion is prohibited')

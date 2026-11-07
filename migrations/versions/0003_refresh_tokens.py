"""Hash-only rotating refresh tokens, retaining consumed identifiers for reuse detection."""
from alembic import op
import sqlalchemy as sa
revision = '0003'
down_revision = '0002'
def upgrade():
    op.create_table('refresh_tokens',sa.Column('token_hash',sa.String(64),primary_key=True),sa.Column('session_id',sa.String(64),sa.ForeignKey('auth_sessions.session_id'),nullable=False),sa.Column('consumed',sa.Boolean,nullable=False))
    op.create_index('ix_refresh_tokens_session_id','refresh_tokens',['session_id'])
def downgrade():
    raise RuntimeError('Restore a coordinated backup instead of deleting session history')

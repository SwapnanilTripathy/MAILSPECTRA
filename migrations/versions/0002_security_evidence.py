"""Add sessions, throttling, original evidence and durable alerts."""
from alembic import op
import sqlalchemy as sa
revision = '0002'
down_revision = '0001'

def upgrade():
    # checkfirst supports adopting a development database that already contains auth tables.
    metadata = sa.MetaData()
    sa.Table('users', metadata, sa.Column('id', sa.Integer, primary_key=True))
    sa.Table('cases', metadata, sa.Column('case_id', sa.String(64), primary_key=True))
    tables = [
        sa.Table('auth_sessions', metadata, sa.Column('session_id', sa.String(64), primary_key=True), sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=False, index=True), sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False), sa.Column('revoked', sa.Boolean, nullable=False)),
        sa.Table('login_attempts', metadata, sa.Column('id', sa.Integer, primary_key=True), sa.Column('bucket', sa.String(64), nullable=False, index=True), sa.Column('attempted_at', sa.DateTime(timezone=True), nullable=False, index=True)),
        sa.Table('artifacts', metadata, sa.Column('artifact_id', sa.String(64), primary_key=True), sa.Column('case_id', sa.String(64), sa.ForeignKey('cases.case_id'), nullable=False, unique=True), sa.Column('sha256', sa.String(64), nullable=False, unique=True), sa.Column('storage_name', sa.String(128), nullable=False, unique=True), sa.Column('size_bytes', sa.Integer, nullable=False), sa.Column('original_filename', sa.String(255), nullable=False), sa.Column('ingested_at', sa.DateTime(timezone=True), nullable=False), sa.Column('actor', sa.String(128), nullable=False)),
        sa.Table('alerts', metadata, sa.Column('alert_id', sa.String(64), primary_key=True), sa.Column('case_id', sa.String(64), sa.ForeignKey('cases.case_id'), nullable=False, index=True), sa.Column('payload_json', sa.Text, nullable=False), sa.Column('status', sa.String(32), nullable=False), sa.Column('assigned_to', sa.String(128)), sa.Column('created_at', sa.DateTime(timezone=True), nullable=False)),
    ]
    for table in tables:
        table.create(op.get_bind(), checkfirst=True)

def downgrade():
    raise RuntimeError('Evidence/session downgrade requires coordinated restore from backup; no destructive downgrade is provided')

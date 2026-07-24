"""Insert Vertex Coders LLC API Key

Revision ID: d7e8f9g0h1i2
Revises: C2d3e4f5a6b7
Create Date: 2026-07-24 09:35:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'd7e8f9g0h1i2'
down_revision = 'C2d3e4f5a6b7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Insert Vertex Coders LLC API Key
    op.execute(
        sa.text("""
            INSERT INTO api_keys (tenant_id, name, prefix, key_hash, scopes, is_active, created_at, expires_at)
            VALUES (1, 'Vertex Coders LLC API Key', 'vtx_fff6f93b', '2vTelUJ2QghySKcDrumycG6VTiApOHmeKrllU6h2gRg', '["read", "write", "admin"]'::jsonb, true, NOW(), NULL)
            ON CONFLICT DO NOTHING;
        """)
    )


def downgrade() -> None:
    # Remove the inserted API Key
    op.execute(
        sa.text("""
            DELETE FROM api_keys 
            WHERE prefix = 'vtx_fff6f93b' AND name = 'Vertex Coders LLC API Key';
        """)
    )

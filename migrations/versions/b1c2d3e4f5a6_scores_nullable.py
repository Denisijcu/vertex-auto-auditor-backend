"""scores nullable + indice compuesto en audit_reports

Revision ID: b1c2d3e4f5a6
Revises: af3ccb6abf9f
"""
from alembic import op
import sqlalchemy as sa

revision = "b1c2d3e4f5a6"
down_revision = "af3ccb6abf9f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # NULL = no evaluable. Distinto de 0 (todo mal) y de 100 (todo bien).
    op.alter_column("audit_reports", "security_score",
                    existing_type=sa.Integer(), nullable=True, server_default=None)
    op.alter_column("audit_reports", "optimization_score",
                    existing_type=sa.Integer(), nullable=True, server_default=None)

    # Trazabilidad de fallos en el pipeline - idempotent using raw SQL
    op.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'audit_tasks' AND column_name = 'error'
        ) THEN
            ALTER TABLE audit_tasks ADD COLUMN error TEXT NULL;
        END IF;
        
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'audit_tasks' AND column_name = 'attempts'
        ) THEN
            ALTER TABLE audit_tasks ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
        END IF;
    END $$;
    """)


def downgrade() -> None:
    op.execute("""
    DO $$
    BEGIN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'audit_tasks' AND column_name = 'attempts'
        ) THEN
            ALTER TABLE audit_tasks DROP COLUMN attempts;
        END IF;
        
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'audit_tasks' AND column_name = 'error'
        ) THEN
            ALTER TABLE audit_tasks DROP COLUMN error;
        END IF;
    END $$;
    """)
    
    op.alter_column("audit_reports", "optimization_score",
                    existing_type=sa.Integer(), nullable=False, server_default="100")
    op.alter_column("audit_reports", "security_score",
                    existing_type=sa.Integer(), nullable=False, server_default="100")

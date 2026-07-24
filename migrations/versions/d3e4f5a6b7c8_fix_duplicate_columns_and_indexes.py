"""Fix duplicate columns and indexes - make all DDL operations idempotent

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
"""
from alembic import op
import sqlalchemy as sa


revision = "d3e4f5a6b7c8"
down_revision = "c2d3e4f5a6b7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Ensure error and attempts columns exist in audit_tasks (idempotent)
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
    
    # Ensure the composite index exists on audit_reports (idempotent)
    op.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_indexes
            WHERE schemaname = 'public'
              AND tablename = 'audit_reports'
              AND indexname = 'ix_audit_reports_company_created'
        ) THEN
            CREATE INDEX ix_audit_reports_company_created ON audit_reports (company_id, created_at DESC);
        END IF;
    END $$;
    """)


def downgrade() -> None:
    # Drop columns and indexes if they exist
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
    
    op.execute("""
    DROP INDEX IF EXISTS ix_audit_reports_company_created;
    """)


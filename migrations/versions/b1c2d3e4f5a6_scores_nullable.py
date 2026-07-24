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

    # Trazabilidad de fallos en el pipeline
    op.add_column("audit_tasks", sa.Column("error", sa.Text(), nullable=True))
    op.add_column("audit_tasks",
                  sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    op.drop_column("audit_tasks", "attempts")
    op.drop_column("audit_tasks", "error")
    op.alter_column("audit_reports", "optimization_score",
                    existing_type=sa.Integer(), nullable=False, server_default="100")
    op.alter_column("audit_reports", "security_score",
                    existing_type=sa.Integer(), nullable=False, server_default="100")
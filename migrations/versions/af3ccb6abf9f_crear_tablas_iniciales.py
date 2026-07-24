"""crear_tablas_iniciales

Crea companies, audit_tasks y audit_reports.

Esta migracion se genero con --autogenerate cuando las tablas YA existian,
creadas por Base.metadata.create_all. Alembic no encontro diferencias y
produjo un archivo vacio. En una base limpia la cadena arrancaba alterando
una tabla que nunca se creo.

Revision ID: af3ccb6abf9f
Revises:
Create Date: 2026-07-20 07:30:49.043727
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "af3ccb6abf9f"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    op.create_table(
        "companies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("industry", sa.String(100), nullable=True),
        sa.Column("location", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_companies_domain", "companies", ["domain"], unique=True)

    op.create_table(
        "audit_tasks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("company_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("companies.id", ondelete="CASCADE"), nullable=False),
        sa.Column("agent_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, server_default="PENDING"),
        sa.Column("raw_output", postgresql.JSONB, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_audit_tasks_company", "audit_tasks", ["company_id"])

    op.create_table(
        "audit_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("company_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("companies.id", ondelete="CASCADE"), nullable=False),
        sa.Column("security_score", sa.Integer, nullable=False),
        sa.Column("optimization_score", sa.Integer, nullable=False),
        sa.Column("findings", postgresql.JSONB, nullable=False),
        sa.Column("pdf_url", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()")),
    )


def downgrade() -> None:
    op.drop_table("audit_reports")
    op.drop_index("ix_audit_tasks_company", table_name="audit_tasks")
    op.drop_table("audit_tasks")
    op.drop_index("ix_companies_domain", table_name="companies")
    op.drop_table("companies")
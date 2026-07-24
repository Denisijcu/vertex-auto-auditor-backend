"""crear_tablas_iniciales

Crea companies, audit_tasks y audit_reports.

MOTIVO: esta migracion se genero con --autogenerate cuando las tablas YA
existian, creadas por `Base.metadata.create_all` en el lifespan. Alembic
comparo modelos contra base, no encontro diferencias, y produjo un archivo
con el nombre correcto y el cuerpo vacio.

En las bases donde create_all habia corrido no se noto. En una base limpia
la cadena arrancaba alterando una tabla que nunca se creo:

    relation "audit_reports" does not exist
    [SQL: ALTER TABLE audit_reports ALTER COLUMN security_score DROP NOT NULL]

El esquema aqui es el ANTERIOR a las dos migraciones siguientes:
  - b1c2d3e4f5a6 hace nullable las puntuaciones
  - c2d3e4f5a6b7 anade tenants, api_keys y tenant_id

Por eso security_score sale NOT NULL y no hay tenant_id: reproduce el estado
original para que las migraciones posteriores tengan algo que alterar.

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
    # Indice UNICO, no constraint: es lo que generaba
    # Column(..., unique=True, index=True) con create_all, y la migracion
    # c2d3e4f5a6b7 espera encontrarse esto para sustituirlo por la unicidad
    # compuesta (tenant_id, domain).
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
        # NOT NULL a proposito: b1c2d3e4f5a6 es la que lo relaja y necesita
        # encontrarlo asi.
        sa.Column("security_score", sa.Integer, nullable=False),
        sa.Column("optimization_score", sa.Integer, nullable=False),
        sa.Column("findings", postgresql.JSONB, nullable=False),
        sa.Column("pdf_url", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()")),
    )
    op.create_index(
        "ix_audit_reports_company_created",
        "audit_reports",
        ["company_id", sa.text("created_at DESC")],
    )


def downgrade() -> None:
    op.drop_index("ix_audit_reports_company_created", table_name="audit_reports")
    op.drop_table("audit_reports")
    op.drop_index("ix_audit_tasks_company", table_name="audit_tasks")
    op.drop_table("audit_tasks")
    op.drop_index("ix_companies_domain", table_name="companies")
    op.drop_table("companies")
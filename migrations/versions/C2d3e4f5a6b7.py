"""tenants, api_keys y tenant_id en las tablas de datos

Revision ID: c2d3e4f5a6b7
Revises: b1c2d3e4f5a6
"""
import uuid

import sqlalchemy as sa
from alembic import op

revision = "c2d3e4f5a6b7"
down_revision = "b1c2d3e4f5a6"
branch_labels = None
depends_on = None

DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False, unique=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_tenants_slug ON tenants (slug)")

    op.execute(
        f"INSERT INTO tenants (id, name, slug, is_active, created_at) "
        f"VALUES ('{DEFAULT_TENANT_ID}', 'Vertex Coders LLC', 'vertex-coders', true, now()) "
        f"ON CONFLICT (id) DO NOTHING"
    )

    op.create_table(
        "api_keys",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.dialects.postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("prefix", sa.String(16), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("scopes", sa.dialects.postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_api_keys_prefix_active ON api_keys (prefix, is_active)")

    # tenant_id en las tablas de datos. Backfill al tenant por defecto y luego
    # NOT NULL: si se deja nullable, tarde o temprano entra una fila huerfana.
    for table in ("companies", "audit_reports", "audit_tasks"):
        op.add_column(table, sa.Column(
            "tenant_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=True))
        op.execute(f"UPDATE {table} SET tenant_id = '{DEFAULT_TENANT_ID}'")
        op.alter_column(table, "tenant_id", nullable=False)
        op.create_foreign_key(
            f"fk_{table}_tenant", table, "tenants", ["tenant_id"], ["id"], ondelete="CASCADE")
        op.execute(f"CREATE INDEX IF NOT EXISTS ix_{table}_tenant ON {table} (tenant_id)")

    # El dominio pasa a ser unico POR TENANT, no globalmente: dos clientes
    # pueden auditar el mismo dominio de forma independiente.
    #
    # OJO: las tablas originales las creo Base.metadata.create_all, no Alembic.
    # Con Column(..., unique=True, index=True) SQLAlchemy no genera un
    # CONSTRAINT sino un INDICE UNICO (ix_companies_domain), asi que
    # drop_constraint("companies_domain_key") falla con UndefinedObject.
    # Se eliminan ambas formas consultando el catalogo, sin asumir el nombre.
    op.execute("""
    DO $$
    DECLARE r record;
    BEGIN
        FOR r IN
            SELECT conname FROM pg_constraint
            WHERE conrelid = 'companies'::regclass
              AND contype = 'u'
              AND pg_get_constraintdef(oid) ILIKE 'UNIQUE (domain)'
        LOOP
            EXECUTE format('ALTER TABLE companies DROP CONSTRAINT %I', r.conname);
        END LOOP;

        FOR r IN
            SELECT indexname FROM pg_indexes
            WHERE tablename = 'companies'
              AND indexdef ILIKE 'CREATE UNIQUE INDEX%(domain)'
        LOOP
            EXECUTE format('DROP INDEX %I', r.indexname);
        END LOOP;
    END $$;
    """)

    # Indice no unico para las busquedas por dominio dentro de un tenant.
    op.execute("CREATE INDEX IF NOT EXISTS ix_companies_domain ON companies (domain)")
    op.create_unique_constraint(
        "uq_companies_tenant_domain", "companies", ["tenant_id", "domain"])


def downgrade() -> None:
    op.drop_constraint("uq_companies_tenant_domain", "companies", type_="unique")
    op.execute("DROP INDEX IF EXISTS ix_companies_domain")
    op.create_unique_constraint("companies_domain_key", "companies", ["domain"])
    for table in ("audit_tasks", "audit_reports", "companies"):
        op.drop_index(f"ix_{table}_tenant", table_name=table)
        op.drop_constraint(f"fk_{table}_tenant", table, type_="foreignkey")
        op.drop_column(table, "tenant_id")
    op.drop_index("ix_api_keys_prefix_active", table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_index("ix_tenants_slug", table_name="tenants")
    op.drop_table("tenants")
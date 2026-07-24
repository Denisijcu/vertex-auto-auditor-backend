"""guardar el pdf en la base, no en disco

El PDF lo genera el worker y lo sirve el servicio web. En Railway son dos
contenedores con discos separados: el worker escribia el archivo en su
/app/reports y web lo buscaba en el suyo, que es otro. Resultado: 404 al
descargar. Guardarlo en Postgres —que si tiene volumen persistente— elimina
el problema de raiz y sobrevive a cualquier deploy.

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
Create Date: 2026-07-24
"""
from alembic import op
import sqlalchemy as sa

revision = "d3e4f5a6b7c8"
down_revision = "c2d3e4f5a6b7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_reports", sa.Column("pdf_bytes", sa.LargeBinary, nullable=True))


def downgrade() -> None:
    op.drop_column("audit_reports", "pdf_bytes")
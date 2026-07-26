"""target_type en companies

Distingue un sitio web (HTML, se renderiza en navegador) de una API (JSON,
la consume un cliente). El tipo se DECLARA al registrar el dominio, no se
infiere del content-type: inferir es adivinar, y un sitio roto tambien puede
devolver JSON. Declararlo es coherente con el principio del motor.

Con target_type='api', los checks que asumen un navegador renderizando HTML
(http.reachable sobre la raiz, content.not_error_page, csp_self_block,
X-Frame-Options) salen como not_assessed "no aplica a objetivo API" en vez de
disparar un critico falso. Los que si aplican a un endpoint (TLS, DNS, HSTS,
X-Content-Type-Options, tiempo de respuesta) corren igual.

El server_default 'website' deja las companies existentes intactas: todas son
sitios, que es lo correcto.

Revision ID: e4f5a6b7c8d9
Revises: d3e4f5a6b7c8
Create Date: 2026-07-25
"""
from alembic import op
import sqlalchemy as sa

revision = "e4f5a6b7c8d9"
down_revision = "d3e4f5a6b7c8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("companies", sa.Column(
        "target_type", sa.String(20), nullable=False, server_default="website"))


def downgrade() -> None:
    op.drop_column("companies", "target_type")

"""
Deteccion de hosting compartido.

MOTIVO: un dominio como `vertex-kontia.netlify.app` no controla la zona DNS de
`netlify.app`. Reportarle "politica SPF no publicada" es tecnicamente cierto e
INACCIONABLE: el titular no puede publicar ese registro aunque quiera.

Un hallazgo que el cliente no puede corregir es peor que no reportarlo. Ocupa
espacio en el informe, baja el score sin motivo y erosiona la confianza en el
resto de hallazgos, que si son accionables.

Aplica el principio central del motor: no se puede medir != esta mal. Estos
checks pasan a NOT_ASSESSED con un motivo explicito, no a FAIL.

NOTA: esto no es la Public Suffix List completa. Es una lista curada de los
proveedores donde la herramienta se usa en la practica. Si el objetivo esta en
un proveedor no listado, el comportamiento es el anterior (se evalua), que es
el lado seguro del error: preferimos un falso positivo revisable a un falso
negativo silencioso.
"""
from __future__ import annotations

# Sufijos bajo los cuales el titular de un subdominio NO controla la zona DNS.
SHARED_HOSTING_SUFFIXES: frozenset[str] = frozenset({
    # Hosting estatico / JAMstack
    "netlify.app",
    "vercel.app",
    "pages.dev",
    "github.io",
    "gitlab.io",
    "surge.sh",
    "onrender.com",
    "fly.dev",
    "up.railway.app",
    "koyeb.app",
    # Plataformas de aplicacion
    "herokuapp.com",
    "appspot.com",
    "azurewebsites.net",
    "web.app",
    "firebaseapp.com",
    "workers.dev",
    "glitch.me",
    "replit.app",
    "repl.co",
    "cyclic.app",
    # ML / demos
    "hf.space",
    "streamlit.app",
    "gradio.live",
    # CDN / almacenamiento
    "cloudfront.net",
    "amazonaws.com",
    "blob.core.windows.net",
})

# Checks cuyo resultado depende de controlar la zona DNS del dominio. En
# hosting compartido no son evaluables para el titular del subdominio.
ZONE_DEPENDENT_CHECKS: frozenset[str] = frozenset({
    "dns.spf",
    "dns.dmarc",
    "dns.dnssec",
    "dns.caa",
})


def shared_hosting_suffix(host: str) -> str | None:
    """Devuelve el sufijo de hosting compartido, o None.

    Solo coincide para SUBDOMINIOS del sufijo. El proveedor si controla su
    propio dominio: `netlify.app` a secas no es hosting compartido para quien
    lo audita, `algo.netlify.app` si lo es.
    """
    host = host.lower().strip().rstrip(".")
    if host.startswith("www."):
        host = host[4:]

    for suffix in SHARED_HOSTING_SUFFIXES:
        if host.endswith("." + suffix) and host != suffix:
            return suffix
    return None


def zone_not_controllable_reason(suffix: str) -> str:
    return (
        f"el dominio es un subdominio de {suffix}; la zona DNS pertenece al "
        f"proveedor de hosting y no es modificable por el titular"
    )
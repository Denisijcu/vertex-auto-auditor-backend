"""
Generador de reportes PDF.

Sustituye al mock que devolvia una URL fija a un archivo inexistente.

Principios del entregable:
  - La cobertura se declara en la PRIMERA pagina, no en un anexo. Un reporte
    que no pudo medir la mitad de los checks tiene que decirlo antes que el
    score, o el numero engana.
  - Cada hallazgo lleva su evidencia. Sin ella el cliente no puede verificar
    nada y el informe no vale lo que se cobra por el.
  - La formula de scoring va impresa. Si preguntan por que 71 y no 80, la
    respuesta esta en el documento.
  - Huella SHA-256 del payload en el pie: permite detectar si el PDF fue
    alterado despues de emitirlo.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
    TableStyle,
)

logger = logging.getLogger("vertex.pdf")

# Paleta legible en impresion: fondo blanco, acentos oscuros.
INK = colors.HexColor("#101018")
MUTED = colors.HexColor("#6B6B80")
LINE = colors.HexColor("#D8D8E2")
ACCENT = colors.HexColor("#0A6C74")

SEVERITY_COLORS = {
    "critical": colors.HexColor("#9B1C1C"),
    "high": colors.HexColor("#C2410C"),
    "medium": colors.HexColor("#A16207"),
    "low": colors.HexColor("#3F6212"),
    "info": MUTED,
}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_WEIGHTS = {"critical": 40, "high": 20, "medium": 10, "low": 3, "info": 0}


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    s = {
        "title": ParagraphStyle("t", parent=base["Title"], fontName="Helvetica-Bold",
                                fontSize=24, leading=28, textColor=INK, spaceAfter=2),
        "subtitle": ParagraphStyle("st", parent=base["Normal"], fontSize=10.5,
                                   textColor=MUTED, spaceAfter=14),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold",
                             fontSize=13, textColor=INK, spaceBefore=16, spaceAfter=6),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontName="Helvetica-Bold",
                             fontSize=10.5, textColor=INK, spaceBefore=10, spaceAfter=3),
        "body": ParagraphStyle("b", parent=base["Normal"], fontSize=9.5, leading=13.5,
                               textColor=INK, spaceAfter=5),
        "small": ParagraphStyle("s", parent=base["Normal"], fontSize=8,
                                leading=11, textColor=MUTED),
        "mono": ParagraphStyle("m", parent=base["Normal"], fontName="Courier",
                               fontSize=7.5, leading=10, textColor=INK),
        "score": ParagraphStyle("sc", parent=base["Normal"], fontName="Helvetica-Bold",
                                fontSize=34, leading=36, alignment=TA_CENTER),
        "scorelbl": ParagraphStyle("scl", parent=base["Normal"], fontSize=7.5,
                                   alignment=TA_CENTER, textColor=MUTED),
    }
    return s


def _esc(v: Any, limit: int = 220) -> str:
    text = str(v)
    if len(text) > limit:
        text = text[:limit] + "…"
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _score_cell(value: int | None, label: str, st: dict) -> list:
    if value is None:
        color, shown = MUTED, "N/D"
    elif value >= 90:
        color, shown = colors.HexColor("#166534"), str(value)
    elif value >= 70:
        color, shown = colors.HexColor("#A16207"), str(value)
    else:
        color, shown = colors.HexColor("#9B1C1C"), str(value)
    style = ParagraphStyle("x", parent=st["score"], textColor=color)
    return [Paragraph(shown, style), Paragraph(label, st["scorelbl"])]


class PDFGenerator:
    """Genera el PDF y devuelve la ruta relativa para servirlo."""

    @staticmethod
    def _fingerprint(payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                               separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @classmethod
    def build(cls, payload: dict[str, Any], out_path: Path) -> str:
        st = _styles()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        target = payload.get("target", "desconocido")
        coverage = payload.get("coverage", {}) or {}
        findings = payload.get("findings", []) or []
        reliable = bool(coverage.get("reliable", False))
        fingerprint = cls._fingerprint(payload)
        issued = datetime.now(timezone.utc)

        doc = SimpleDocTemplate(
            str(out_path), pagesize=A4,
            leftMargin=20 * mm, rightMargin=20 * mm,
            topMargin=18 * mm, bottomMargin=20 * mm,
            title=f"Auditoria OSINT - {target}",
            author="Vertex Coders LLC", subject="Auditoria de superficie publica",
        )

        story: list = []

        # ------------------------------------------------------------ cabecera
        story.append(Paragraph("Auditoría de superficie pública", st["title"]))
        story.append(Paragraph(
            f"{_esc(target)} &nbsp;·&nbsp; emitido {issued.strftime('%d/%m/%Y %H:%M')} UTC "
            f"&nbsp;·&nbsp; Vertex Coders LLC", st["subtitle"]))
        story.append(HRFlowable(width="100%", color=LINE, spaceAfter=14))

        # -------------------------------------------------------------- scores
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1

        score_tbl = Table(
            [
                _score_cell(payload.get("security_score"), "SEGURIDAD", st)[:1]
                + _score_cell(payload.get("optimization_score"), "OPTIMIZACIÓN", st)[:1]
                + [Paragraph(str(len(findings)), ParagraphStyle(
                    "n", parent=st["score"], textColor=INK))],
                [Paragraph("SEGURIDAD", st["scorelbl"]),
                 Paragraph("OPTIMIZACIÓN", st["scorelbl"]),
                 Paragraph("HALLAZGOS", st["scorelbl"])],
            ],
            colWidths=[56 * mm] * 3,
        )
        score_tbl.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOX", (0, 0), (-1, -1), 0.6, LINE),
            ("INNERGRID", (0, 0), (-1, -1), 0.6, LINE),
            ("TOPPADDING", (0, 0), (-1, 0), 12),
            ("BOTTOMPADDING", (0, 1), (-1, 1), 10),
        ]))
        story.append(score_tbl)
        story.append(Spacer(1, 6))

        verdict = payload.get("verdict", "—")
        story.append(Paragraph(f"<b>Veredicto:</b> {_esc(verdict)}", st["body"]))

        # ---------------------------------------------- cobertura (antes que todo)
        # Va aqui a proposito: si el escaneo no pudo medir lo suficiente, el
        # lector tiene que saberlo ANTES de mirar los numeros de arriba.
        story.append(Paragraph("Cobertura del escaneo", st["h2"]))
        assessed = coverage.get("assessed", 0)
        total = coverage.get("total_checks", 0)
        ratio = coverage.get("ratio", 0)

        cov_text = (
            f"Se ejecutaron <b>{assessed} de {total}</b> comprobaciones "
            f"({ratio * 100:.0f}% de cobertura)."
        )
        story.append(Paragraph(cov_text, st["body"]))

        if not reliable:
            warn = Table([[Paragraph(
                "<b>Cobertura insuficiente.</b> Menos del 70% de las comprobaciones "
                "pudieron ejecutarse, por lo que las puntuaciones se reportan como "
                "N/D. Este documento no constituye una auditoría concluyente y no "
                "debe usarse como evidencia de conformidad.", st["body"])]],
                colWidths=[168 * mm])
            warn.setStyle(TableStyle([
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#9B1C1C")),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF2F2")),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(warn)
            story.append(Spacer(1, 6))

        na = coverage.get("not_assessed_detail", []) or []
        if na:
            story.append(Paragraph("Comprobaciones no evaluadas", st["h3"]))
            rows = [[Paragraph("<b>Check</b>", st["small"]),
                     Paragraph("<b>Motivo</b>", st["small"])]]
            rows += [[Paragraph(_esc(x.get("id", "")), st["mono"]),
                      Paragraph(_esc(x.get("reason", ""), 110), st["small"])] for x in na]
            t = Table(rows, colWidths=[58 * mm, 110 * mm])
            t.setStyle(TableStyle([
                ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t)
            story.append(Paragraph(
                "Una comprobación no evaluada no implica ausencia de riesgo: "
                "significa que no se pudo determinar.", st["small"]))

        # ------------------------------------------------------------- resumen
        story.append(Paragraph("Resumen por severidad", st["h2"]))
        rows = [[Paragraph("<b>Severidad</b>", st["small"]),
                 Paragraph("<b>Nº</b>", st["small"]),
                 Paragraph("<b>Peso unitario</b>", st["small"]),
                 Paragraph("<b>Penalización</b>", st["small"])]]
        total_pen = 0
        for sev in SEVERITY_ORDER:
            n = counts.get(sev, 0)
            pen = n * SEVERITY_WEIGHTS[sev]
            total_pen += pen
            rows.append([
                Paragraph(f"<font color='#{SEVERITY_COLORS[sev].hexval()[2:]}'>"
                          f"<b>{sev.upper()}</b></font>", st["small"]),
                Paragraph(str(n), st["small"]),
                Paragraph(str(SEVERITY_WEIGHTS[sev]), st["small"]),
                Paragraph(f"−{pen}" if pen else "0", st["small"]),
            ])
        rows.append([Paragraph("<b>Total</b>", st["small"]), "", "",
                     Paragraph(f"<b>{'−' + str(total_pen) if total_pen else '0'}</b>",
                               st["small"])])
        t = Table(rows, colWidths=[46 * mm, 24 * mm, 44 * mm, 54 * mm])
        t.setStyle(TableStyle([
            ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE),
            ("LINEABOVE", (0, -1), (-1, -1), 0.8, INK),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(t)

        # ------------------------------------------------------------ hallazgos
        if findings:
            story.append(PageBreak())
            story.append(Paragraph("Hallazgos detallados", st["h2"]))
            ordered = sorted(
                findings,
                key=lambda f: SEVERITY_ORDER.index(f.get("severity", "info")),
            )
            for i, f in enumerate(ordered, 1):
                story.extend(cls._finding_block(i, f, st))
        else:
            story.append(Paragraph("Hallazgos", st["h2"]))
            story.append(Paragraph(
                "No se detectaron hallazgos en las comprobaciones ejecutadas.",
                st["body"]))

        # ---------------------------------------------------------- metodologia
        story.append(PageBreak())
        story.append(Paragraph("Metodología", st["h2"]))
        story.append(Paragraph(
            "El escaneo es <b>pasivo sobre superficie pública</b>: resolución DNS, "
            "handshake TLS para inspeccionar el certificado y peticiones HTTP "
            "equivalentes a las de un visitante. No se ejecuta escaneo de puertos, "
            "fuzzing ni explotación de vulnerabilidades.", st["body"]))

        story.append(Paragraph("Cálculo de la puntuación", st["h3"]))
        story.append(Paragraph(
            f"Método <font face='Courier'>{_esc(payload.get('scoring_method', 'n/d'))}</font>. "
            "La penalización es la suma de los pesos de cada hallazgo, derivados de "
            "los rangos CVSS v3.1. La puntuación es 100 menos esa penalización, con "
            "suelo en 0.", st["body"]))
        story.append(Paragraph(
            "Si menos del 70% de las comprobaciones de una categoría se pudieron "
            "ejecutar, su puntuación se reporta como N/D en lugar de calcularse "
            "sobre datos incompletos.", st["body"]))

        story.append(Paragraph("Limitaciones", st["h3"]))
        for lim in (
            "El tiempo de respuesta se mide desde un único punto de observación; "
            "no es una medición sintética multi-región.",
            "La ausencia de hallazgos indica que las comprobaciones ejecutadas no "
            "detectaron problemas, no que el sistema sea seguro.",
            "El alcance cubre la superficie expuesta a internet. No incluye revisión "
            "de código, configuración interna ni controles organizativos.",
            "El análisis de la política de seguridad de contenidos es estático: "
            "contrasta el documento servido contra la política declarada. No "
            "detecta violaciones que solo se manifiestan al ejecutar la aplicación "
            "en un navegador."
        ):
            story.append(Paragraph(f"• {lim}", st["body"]))

        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", color=LINE, spaceAfter=6))
        story.append(Paragraph(
            f"Huella SHA-256 del contenido auditado:<br/>"
            f"<font face='Courier'>{fingerprint}</font>", st["small"]))
        story.append(Paragraph(
            "Esta huella permite verificar que el contenido no fue alterado tras "
            "la emisión.", st["small"]))

        def _footer(canvas, doc_):
            canvas.saveState()
            canvas.setFont("Helvetica", 7)
            canvas.setFillColor(MUTED)
            canvas.drawString(20 * mm, 12 * mm,
                              f"Vertex Coders LLC · {target} · {fingerprint[:16]}")
            canvas.drawRightString(A4[0] - 20 * mm, 12 * mm, f"Página {doc_.page}")
            canvas.setStrokeColor(LINE)
            canvas.line(20 * mm, 15 * mm, A4[0] - 20 * mm, 15 * mm)
            canvas.restoreState()

        doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
        return fingerprint

    @staticmethod
    def _finding_block(index: int, f: dict[str, Any], st: dict) -> list:
        sev = f.get("severity", "info")
        color = SEVERITY_COLORS.get(sev, MUTED)

        head = Table(
            [[Paragraph(f"<b>{sev.upper()}</b>", ParagraphStyle(
                "sv", parent=st["small"], textColor=colors.white, alignment=TA_CENTER)),
              Paragraph(f"<b>{index}. {_esc(f.get('title', ''))}</b>", st["h3"]),
              Paragraph(_esc(f.get("id", "")), ParagraphStyle(
                  "fid", parent=st["mono"], textColor=MUTED))]],
            colWidths=[22 * mm, 116 * mm, 30 * mm],
        )
        head.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), color),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (0, 0), 2),
            ("RIGHTPADDING", (0, 0), (0, 0), 2),
        ]))

        block = [Spacer(1, 8), head, Spacer(1, 4)]

        meta = " · ".join(x for x in (
            f"Activo: {_esc(f.get('asset', ''))}",
            f"CWE: {_esc(f['cwe'])}" if f.get("cwe") else "",
            f"OWASP: {_esc(f['owasp'])}" if f.get("owasp") else "",
            f"Confianza: {_esc(f.get('confidence', ''))}",
        ) if x)
        block.append(Paragraph(meta, st["small"]))
        block.append(Spacer(1, 4))
        block.append(Paragraph(_esc(f.get("description", ""), 900), st["body"]))

        block.append(Paragraph("Remediación", ParagraphStyle(
            "rem", parent=st["small"], textColor=ACCENT, fontName="Helvetica-Bold",
            spaceBefore=4)))
        block.append(Paragraph(_esc(f.get("remediation", ""), 900), st["body"]))

        evidence = f.get("evidence") or {}
        if evidence:
            block.append(Paragraph("Evidencia observada", ParagraphStyle(
                "ev", parent=st["small"], textColor=ACCENT,
                fontName="Helvetica-Bold", spaceBefore=4)))
            rows = [[Paragraph(_esc(k), st["mono"]),
                     Paragraph(_esc(json.dumps(v, ensure_ascii=False)
                                    if isinstance(v, (dict, list)) else v, 160), st["mono"])]
                    for k, v in list(evidence.items())[:8]]
            t = Table(rows, colWidths=[42 * mm, 126 * mm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7F7FA")),
                ("BOX", (0, 0), (-1, -1), 0.4, LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            block.append(t)

        return [KeepTogether(block)]

    # ------------------------------------------------------------------ API

    @classmethod
    async def render_audit_pdf(
        cls, payload: dict[str, Any], *, reports_dir: str = "/app/reports",
        company_id: str | None = None,
    ) -> str | None:
        """Genera el PDF y devuelve la ruta relativa servible.

        Devuelve None si falla: el reporte debe persistirse igual, con pdf_url
        en NULL. Un PDF roto no puede tumbar la auditoria.
        """
        try:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            safe = "".join(c if c.isalnum() or c in "-." else "_"
                           for c in payload.get("target", "target"))
            name = f"{safe}-{stamp}.pdf"
            path = Path(reports_dir) / (company_id or "shared") / name
            cls.build(payload, path)
            # Ruta RELATIVA a REPORTS_DIR. Se guarda asi para que mover el
            # directorio no invalide las filas ya escritas en la base.
            rel = f"{company_id or 'shared'}/{name}"
            logger.info("pdf_generated path=%s", path)
            return rel
        except Exception:
            logger.exception("pdf_generation_failed target=%s", payload.get("target"))
            return None
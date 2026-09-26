"""
ReportLab PDF Report Generator
================================
Generates a one-page PDF evidence report for any alert.

Output contains:
  - Header with project name + timestamp
  - Alert summary table (ID, prediction, confidence, status)
  - SHAP top-features bar chart (embedded as inline image)
  - Class probability table
  - Footer noting Verification Agent phase
"""

import io
import json
import sys
from pathlib import Path
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable, Image,
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics import renderPDF


# ── Brand colours (light theme) ───────────────────────────────────
NAVY   = colors.HexColor("#0D47A1")
BLUE   = colors.HexColor("#1565C0")
LBLUE  = colors.HexColor("#E3F2FD")
RED    = colors.HexColor("#C62828")
GREEN  = colors.HexColor("#2E7D32")
GREY   = colors.HexColor("#616161")
WHITE  = colors.white
BLACK  = colors.black

CLASS_COLOURS = {
    "Benign":      GREEN,
    "DoS/DDoS":    RED,
    "Port Scan":   colors.HexColor("#F57F17"),
    "Brute Force": colors.HexColor("#6A1B9A"),
    "Web Attack":  colors.HexColor("#E65100"),
    "Botnet":      colors.HexColor("#880E4F"),
}


def _severity(prob: float, prediction: str) -> tuple[str, object]:
    if prediction == "Benign":
        return "LOW", GREEN
    if prob >= 0.85:
        return "HIGH", RED
    if prob >= 0.60:
        return "MEDIUM", colors.HexColor("#F57F17")
    return "LOW", GREEN


def _shap_bar_drawing(top_features: list, width=400, height=180) -> Drawing:
    """Render SHAP top-features as a ReportLab bar chart drawing."""
    if not top_features:
        d = Drawing(width, 30)
        d.add(String(10, 10, "No SHAP features available.", fontSize=9, fillColor=GREY))
        return d

    features = [f["feature"][:28] for f in top_features[:8]]
    values   = [abs(f.get("shap_value", f.get("importance", 0))) for f in top_features[:8]]
    n = len(features)
    bar_h = max(height, n * 22 + 40)

    d   = Drawing(width, bar_h)
    bc  = HorizontalBarChart()
    bc.x           = 160
    bc.y           = 10
    bc.width       = width - 180
    bc.height      = bar_h - 20
    bc.data        = [values]
    bc.bars[0].fillColor = BLUE
    bc.valueAxis.valueMin  = 0
    bc.valueAxis.valueMax  = max(values) * 1.15 if values else 1
    bc.valueAxis.labels.fontSize = 7
    bc.categoryAxis.categoryNames  = features
    bc.categoryAxis.labels.fontSize = 7
    bc.categoryAxis.labels.dx      = -4
    d.add(bc)
    return d


def generate_pdf(alert: dict) -> bytes:
    """
    Generate a PDF report for one alert.

    Parameters
    ----------
    alert : dict
        Alert object from the SQLite store or detection pipeline.

    Returns
    -------
    bytes — raw PDF content (send as response body).
    """
    buf    = io.BytesIO()
    doc    = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )
    styles = getSampleStyleSheet()
    story  = []

    # ── Title ──────────────────────────────────────────────────────
    title_style = ParagraphStyle(
        "title", parent=styles["Title"],
        fontSize=18, textColor=NAVY, spaceAfter=4,
    )
    sub_style = ParagraphStyle(
        "sub", parent=styles["Normal"],
        fontSize=9, textColor=GREY, spaceAfter=12,
    )
    story.append(Paragraph("🛡️ TRUST-SOC", title_style))
    story.append(Paragraph(
        "Trust-Aware, Verification-Driven Detection Pipeline · Alert Report",
        sub_style,
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=NAVY))
    story.append(Spacer(1, 0.4*cm))

    # ── Alert summary table ────────────────────────────────────────
    pred      = alert.get("prediction", "—")
    prob      = alert.get("probability", 0.0)
    severity, sev_colour = _severity(prob, pred)
    pred_colour = CLASS_COLOURS.get(pred, BLUE)

    summary_data = [
        ["Field", "Value"],
        ["Alert ID",    alert.get("alert_id", "—")],
        ["Timestamp",   alert.get("timestamp", "—")],
        ["Prediction",  pred],
        ["Confidence",  f"{prob:.1%}"],
        ["Severity",    severity],
        ["Status",      alert.get("status", "DETECTED")],
        ["True Label",  alert.get("true_label") or "—"],
        ["Verification", alert.get("verification_result", "NOT_IMPLEMENTED")],
    ]

    tbl = Table(summary_data, colWidths=[5*cm, 11*cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  NAVY),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  WHITE),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("BACKGROUND",   (0, 1), (-1, -1), LBLUE),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LBLUE]),
        ("GRID",         (0, 0), (-1, -1), 0.4, colors.HexColor("#BBDEFB")),
        ("TEXTCOLOR",    (1, 3), (1, 3),   pred_colour),
        ("FONTNAME",     (1, 3), (1, 3),   "Helvetica-Bold"),
        ("TEXTCOLOR",    (1, 5), (1, 5),   sev_colour),
        ("FONTNAME",     (1, 5), (1, 5),   "Helvetica-Bold"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 0.5*cm))

    # ── Class probabilities ────────────────────────────────────────
    class_probs = alert.get("class_probabilities", {})
    if isinstance(class_probs, str):
        try:
            class_probs = json.loads(class_probs)
        except Exception:
            class_probs = {}

    if class_probs:
        story.append(Paragraph(
            "Class Probabilities",
            ParagraphStyle("h2", parent=styles["Heading2"],
                           fontSize=11, textColor=NAVY, spaceAfter=4),
        ))
        cp_data = [["Class", "Probability"]] + [
            [k, f"{v:.2%}"] for k, v in
            sorted(class_probs.items(), key=lambda x: -x[1])
        ]
        cp_tbl = Table(cp_data, colWidths=[8*cm, 8*cm])
        cp_tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), BLUE),
            ("TEXTCOLOR",    (0, 0), (-1, 0), WHITE),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LBLUE]),
            ("GRID",         (0, 0), (-1, -1), 0.4, colors.HexColor("#BBDEFB")),
            ("ALIGN",        (1, 0), (1, -1), "RIGHT"),
        ]))
        story.append(cp_tbl)
        story.append(Spacer(1, 0.5*cm))

    # ── SHAP top features ──────────────────────────────────────────
    top_features = alert.get("top_features", [])
    if isinstance(top_features, str):
        try:
            top_features = json.loads(top_features)
        except Exception:
            top_features = []

    story.append(Paragraph(
        "SHAP Feature Attributions (Top Features)",
        ParagraphStyle("h2", parent=styles["Heading2"],
                       fontSize=11, textColor=NAVY, spaceAfter=4),
    ))
    if top_features:
        drawing = _shap_bar_drawing(top_features)
        story.append(drawing)
    else:
        story.append(Paragraph(
            "SHAP explanations not available for this alert.",
            ParagraphStyle("note", parent=styles["Normal"],
                           fontSize=9, textColor=GREY),
        ))
    story.append(Spacer(1, 0.5*cm))

    # ── Footer ─────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=GREY))
    story.append(Spacer(1, 0.2*cm))
    footer_style = ParagraphStyle(
        "footer", parent=styles["Normal"],
        fontSize=7.5, textColor=GREY,
    )
    story.append(Paragraph(
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC  |  "
        "TRUST-SOC Prototype v0.1  |  BTech CSE Micro-Project",
        footer_style,
    ))
    story.append(Paragraph(
        "⚠ Verification Agent: NOT IMPLEMENTED — planned Phase 2 component. "
        "Detection results shown stand-alone.",
        ParagraphStyle("warn", parent=styles["Normal"],
                       fontSize=7.5, textColor=colors.HexColor("#E65100")),
    ))

    doc.build(story)
    return buf.getvalue()

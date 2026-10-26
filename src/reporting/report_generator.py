"""
Evidence-Linked Report Generator (Milestone 3 — Stage 3.4)
==========================================================
Generates evidence-linked triage reports for any alert in both JSON and ReportLab PDF.

Strictly adheres to:
  - ReportLab exclusively (WeasyPrint is NOT used)
  - Section 3 Light Theme tokens everywhere
  - 5-Tuple network flow metadata
  - Detection probabilities & SHAP feature attributions
  - Verification signals (r, s, b, e), agreement score p_v, and deterministic rationale
  - Composite confidence score C, band badge, and MITRE ATT&CK mapping
  - Full cryptographic audit trail
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)

from src.config.config import (
    REPORTS_JSON_DIR,
    REPORTS_PDF_DIR,
    RULES_PATH,
)
from src.config.theme import THEME
from src.database.alert_store import insert_report

log = logging.getLogger("TRUST-SOC.reporting")

# Theme Colors for ReportLab
NAVY_PRIMARY  = colors.HexColor(THEME["primary"])       # #1F3864
NAVY_SOFT     = colors.HexColor(THEME["primary_soft"])  # #E8EEF8
BORDER_COLOR  = colors.HexColor(THEME["border"])        # #D9E0EA
TEXT_COLOR    = colors.HexColor(THEME["text"])          # #1F2937
TEXT_MUTED    = colors.HexColor(THEME["text_muted"])    # #5B6676
WHITE         = colors.HexColor("#FFFFFF")
SURFACE_BG    = colors.HexColor("#FAFCFE")

# Band colors
COLOR_HIGH    = colors.HexColor(THEME["high"])          # #B42318
COLOR_MEDIUM  = colors.HexColor(THEME["medium"])        # #B54708
COLOR_LOW     = colors.HexColor(THEME["low"])           # #2E7D5B

# Verification decision colors
COLOR_CONFIRM = colors.HexColor(THEME["confirm"])       # #1F6F43
COLOR_REDUCE  = colors.HexColor(THEME["reduce"])        # #B54708
COLOR_REJECT  = colors.HexColor(THEME["reject"])        # #5B6676


class ReportGenerator:
    """Produces JSON and ReportLab PDF evidence reports for alerts."""

    def __init__(
        self,
        json_dir: Path = REPORTS_JSON_DIR,
        pdf_dir: Path = REPORTS_PDF_DIR,
        rules_path: Path = RULES_PATH,
    ):
        self.json_dir = Path(json_dir)
        self.pdf_dir = Path(pdf_dir)
        self.json_dir.mkdir(parents=True, exist_ok=True)
        self.pdf_dir.mkdir(parents=True, exist_ok=True)

        with open(rules_path, "r", encoding="utf-8") as f:
            self.rules_config = json.load(f)
        self.classes_rules = self.rules_config.get("classes", {})

    def generate_json_report(self, alert: Dict[str, Any]) -> Path:
        """Saves canonical JSON evidence report."""
        alert_id = alert["alert_id"]
        safe_id = alert_id.replace(":", "_").replace("/", "_")
        out_path = self.json_dir / f"{safe_id}.json"

        # Attach MITRE ATT&CK context if not already present
        det_class = alert.get("detection", {}).get("predicted_class", "Benign")
        mitre_info = self.classes_rules.get(det_class, {}).get("mitre", {})

        report_payload = {
            "report_id": f"REP-{safe_id}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mitre_attack": mitre_info,
            "alert": alert,
        }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report_payload, f, indent=2, ensure_ascii=False)

        log.info(f"Generated JSON evidence report -> {out_path}")
        return out_path

    def generate_pdf_report(self, alert: Dict[str, Any]) -> Path:
        """Generates a structured, professional light-theme PDF report using ReportLab."""
        alert_id = alert["alert_id"]
        safe_id = alert_id.replace(":", "_").replace("/", "_")
        out_path = self.pdf_dir / f"{safe_id}.pdf"

        flow = alert.get("flow", {})
        fields = flow.get("fields_available", {})
        raw_feats = flow.get("features", {})
        det = alert.get("detection", {})
        ver = alert.get("verification", {})
        sc = alert.get("scoring", {})
        audit = alert.get("audit_trail", [])

        pred_class = det.get("predicted_class", "Benign")
        p_d = float(det.get("probability", 0.0))
        ver_dec = ver.get("decision", "NOT_IMPLEMENTED")
        p_v = float(ver.get("p_v", 0.0))
        comp_c = float(sc.get("composite", 0.0))
        band = sc.get("band", "LOW")
        rationale = ver.get("rationale", "No verification rationale available.")

        mitre_info = self.classes_rules.get(pred_class, {}).get("mitre", {
            "technique_id": "T1000",
            "technique_name": "Unknown",
            "tactic": "Security Event",
        })

        # Set up ReportLab Document
        doc = SimpleDocTemplate(
            str(out_path),
            pagesize=letter,
            rightMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            topMargin=0.4 * inch,
            bottomMargin=0.4 * inch,
        )

        styles = getSampleStyleSheet()

        # Custom Paragraph Styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=15,
            textColor=WHITE,
            leading=18,
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            textColor=NAVY_SOFT,
            leading=11,
        )
        section_heading = ParagraphStyle(
            "SectionHeading",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=NAVY_PRIMARY,
            leading=13,
            spaceAfter=4,
        )
        body_text = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=TEXT_COLOR,
            leading=10,
        )
        bold_text = ParagraphStyle(
            "BoldBody",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            textColor=TEXT_COLOR,
            leading=10,
        )
        badge_style = ParagraphStyle(
            "Badge",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            textColor=WHITE,
            alignment=1,
            leading=11,
        )

        story = []

        # 1. Header Banner
        header_data = [
            [
                Paragraph("<b>TRUST-SOC SECURITY INCIDENT EVIDENCE REPORT</b>", title_style),
                Paragraph(f"<b>ALERT ID:</b> {alert_id}<br/><b>INGESTED:</b> {alert.get('ingested_at', '')[:19]} UTC", subtitle_style),
            ]
        ]
        header_table = Table(header_data, colWidths=[4.8 * inch, 2.7 * inch])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), NAVY_PRIMARY),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 0.1 * inch))

        # 2. Executive Triage Summary Card
        band_col = COLOR_HIGH if band == "HIGH" else (COLOR_MEDIUM if band == "MEDIUM" else COLOR_LOW)
        ver_col = COLOR_CONFIRM if ver_dec == "CONFIRM" else (COLOR_REDUCE if ver_dec == "REDUCE" else COLOR_REJECT)

        summary_data = [
            [
                Paragraph("<b>Predicted Class:</b>", bold_text),
                Paragraph(f"<b>{pred_class}</b>", bold_text),
                Paragraph("<b>Confidence Band:</b>", bold_text),
                Paragraph(f"<b>{band} (C = {comp_c:.3f})</b>", badge_style),
            ],
            [
                Paragraph("<b>MITRE ATT&CK:</b>", bold_text),
                Paragraph(f"{mitre_info.get('technique_id')}: {mitre_info.get('technique_name')}", body_text),
                Paragraph("<b>Verification Verdict:</b>", bold_text),
                Paragraph(f"<b>{ver_dec} (p_v = {p_v:.3f})</b>", badge_style),
            ],
            [
                Paragraph("<b>ATT&CK Tactic:</b>", bold_text),
                Paragraph(f"{mitre_info.get('tactic')}", body_text),
                Paragraph("<b>Triage Action:</b>", bold_text),
                Paragraph(f"{sc.get('action', 'ANALYST_QUEUE')}", body_text),
            ],
        ]
        summary_table = Table(summary_data, colWidths=[1.3 * inch, 2.3 * inch, 1.5 * inch, 2.4 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), SURFACE_BG),
            ("BACKGROUND", (3, 0), (3, 0), band_col),
            ("BACKGROUND", (3, 1), (3, 1), ver_col),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.1 * inch))

        # 3. 5-Tuple Network Traffic Metadata
        story.append(Paragraph("1. Network Flow Context (5-Tuple)", section_heading))
        flow_data = [
            ["Source IP", "Destination IP", "Source Port", "Dest Port", "Protocol", "Duration (us)", "Packets/s", "Bytes/s"],
            [
                str(fields.get("Source IP", "—")),
                str(fields.get("Destination IP", "—")),
                str(fields.get("Source Port", "—")),
                str(fields.get("Destination Port", "—")),
                str(fields.get("Protocol", "—")),
                f"{float(raw_feats.get('Flow Duration', 0)):,.0f}",
                f"{float(raw_feats.get('Flow Packets/s', 0)):,.1f}",
                f"{float(raw_feats.get('Flow Bytes/s', 0)):,.1f}",
            ],
        ]
        flow_table = Table(flow_data, colWidths=[1.1 * inch, 1.1 * inch, 0.7 * inch, 0.7 * inch, 0.6 * inch, 1.1 * inch, 1.1 * inch, 1.1 * inch])
        flow_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY_SOFT),
            ("TEXTCOLOR", (0, 0), (-1, 0), NAVY_PRIMARY),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(flow_table)
        story.append(Spacer(1, 0.1 * inch))

        # 4. Detection Agent Analysis & Class Probabilities
        story.append(Paragraph("2. Detection Agent Findings (Model: Random Forest Baseline)", section_heading))
        class_probs = det.get("class_probabilities", {})
        prob_headers = list(class_probs.keys())
        prob_values = [f"{float(class_probs[c]):.3f}" for c in prob_headers]

        prob_table_data = [
            prob_headers,
            prob_values,
        ]
        prob_table = Table(prob_table_data, colWidths=[1.25 * inch] * len(prob_headers))
        prob_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY_SOFT),
            ("TEXTCOLOR", (0, 0), (-1, 0), NAVY_PRIMARY),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(prob_table)
        story.append(Spacer(1, 0.1 * inch))

        # 5. Verification Agent Findings (The 4 Signals)
        story.append(Paragraph("3. Verification Agent Corroboration (The Trust Mechanism)", section_heading))
        sigs = ver.get("signals", {})
        r_sig = sigs.get("rule", {})
        s_sig = sigs.get("statistical", {})
        b_sig = sigs.get("behavioural", {})
        e_sig = sigs.get("explanation", {})

        sig_table_data = [
            ["Verification Signal", "Score [0,1]", "Status", "Inspection Mechanism"],
            [
                "(a) Rule / Context Corroboration",
                f"{float(r_sig.get('score', 0)):.3f}",
                "CONTRADICTION" if r_sig.get("strongly_contradictory") else "Corroborated",
                "Deterministic port rules, ATT&CK signature matching, asset criticality",
            ],
            [
                "(b) Statistical Corroboration",
                f"{float(s_sig.get('score', 0)):.3f}",
                "CONTRADICTION" if s_sig.get("strongly_contradictory") else "Corroborated",
                "Independently trained Isolation Forest (Benign-only manifold check)",
            ],
            [
                "(c) Behavioural Baseline",
                f"{float(b_sig.get('score', 0)):.3f}",
                "CONTRADICTION" if b_sig.get("strongly_contradictory") else "Corroborated",
                "Host-level Z-deviation and causal sliding window traffic surge",
            ],
            [
                "(d) Explanation Consistency",
                f"{float(e_sig.get('score', 0)):.3f}",
                "CONTRADICTION" if e_sig.get("strongly_contradictory") else "Corroborated",
                "SHAP attribution mass semantic alignment with attack physics",
            ],
        ]
        sig_table = Table(sig_table_data, colWidths=[2.2 * inch, 0.8 * inch, 1.2 * inch, 3.3 * inch])
        sig_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY_SOFT),
            ("TEXTCOLOR", (0, 0), (-1, 0), NAVY_PRIMARY),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(sig_table)
        story.append(Spacer(1, 0.05 * inch))

        # Rationale Callout Box
        rationale_para = Paragraph(f"<b>Verification Rationale:</b> {rationale}", body_text)
        rationale_table = Table([[rationale_para]], colWidths=[7.5 * inch])
        rationale_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), SURFACE_BG),
            ("BOX", (0, 0), (-1, -1), 1.0, BORDER_COLOR),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(rationale_table)
        story.append(Spacer(1, 0.1 * inch))

        # 6. SHAP Top-5 Feature Explanations
        story.append(Paragraph("4. Explainability (SHAP Top Feature Attributions)", section_heading))
        top_feats = det.get("top_features", [])[:5]
        if top_feats:
            shap_data = [["Rank", "Feature Name", "Observed Value", "SHAP Attribution", "Direction"]]
            for f_item in top_feats:
                val = f_item.get("feature_value", raw_feats.get(f_item.get("feature", ""), "—"))
                val_str = f"{val:,.2f}" if isinstance(val, (int, float)) else str(val)
                shap_val = float(f_item.get("shap_value", 0.0))
                direction = "Supports Attack (+)" if shap_val >= 0 else "Supports Benign (-)"
                shap_data.append([
                    str(f_item.get("rank", "—")),
                    str(f_item.get("feature", "")),
                    val_str,
                    f"{shap_val:+.4f}",
                    direction,
                ])
        else:
            shap_data = [["Rank", "Feature Name", "Observed Value", "SHAP Attribution", "Direction"], ["—", "No individual SHAP attributions extracted", "—", "—", "—"]]

        shap_table = Table(shap_data, colWidths=[0.5 * inch, 2.7 * inch, 1.4 * inch, 1.4 * inch, 1.5 * inch])
        shap_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY_SOFT),
            ("TEXTCOLOR", (0, 0), (-1, 0), NAVY_PRIMARY),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("ALIGN", (3, 0), (3, -1), "RIGHT"),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(shap_table)
        story.append(Spacer(1, 0.1 * inch))

        # 7. Audit Trail Timeline
        story.append(Paragraph("5. Forensic Audit Trail", section_heading))
        audit_rows = [["Step", "Timestamp (UTC)", "Stage", "Event Description"]]
        for idx, ev in enumerate(audit[:6], 1):
            audit_rows.append([
                str(idx),
                str(ev.get("ts", ""))[:19],
                str(ev.get("stage", "")).capitalize(),
                str(ev.get("event", "")),
            ])
        audit_table = Table(audit_rows, colWidths=[0.5 * inch, 1.5 * inch, 1.3 * inch, 4.2 * inch])
        audit_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY_SOFT),
            ("TEXTCOLOR", (0, 0), (-1, 0), NAVY_PRIMARY),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.2),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("PADDING", (0, 0), (-1, -1), 2.5),
        ]))
        story.append(audit_table)
        story.append(Spacer(1, 0.1 * inch))

        # Footer Notice
        footer_text = Paragraph(
            "TRUST-SOC: A Trust-Aware Verification-Driven Detection Pipeline | BTech CSE Micro-Project | BVCOE Delhi",
            subtitle_style,
        )
        story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER_COLOR, spaceAfter=3))
        story.append(footer_text)

        # Build PDF
        doc.build(story)
        log.info(f"Generated ReportLab PDF evidence report -> {out_path}")
        return out_path

    def generate_both_reports(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Generates both JSON and PDF reports and logs in SQLite database."""
        json_path = self.generate_json_report(alert)
        pdf_path = self.generate_pdf_report(alert)

        report_id = f"REP-{alert['alert_id'].replace(':', '_')}"
        summary = (
            f"Alert {alert['alert_id']} ({alert.get('detection', {}).get('predicted_class')}) "
            f"scored C={alert.get('scoring', {}).get('composite', 0.0):.3f} "
            f"({alert.get('scoring', {}).get('band')}). Decision: {alert.get('verification', {}).get('decision')}."
        )

        insert_report(
            report_id=report_id,
            alert_id=alert["alert_id"],
            json_path=str(json_path),
            pdf_path=str(pdf_path),
            summary=summary,
        )

        return {
            "report_id": report_id,
            "json_path": str(json_path),
            "pdf_path": str(pdf_path),
            "summary": summary,
        }

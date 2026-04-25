"""
PDF Reporter - Auditor Enterprise Suite.
Generates a professional executive summary PDF for:
  - SOC 2 / ISO 27001 readiness engagements
  - Cyber insurance underwriting packages (Marsh, Aon, WTW)

Output: 4-page structured document
  Page 1 — Cover & Executive Summary
  Page 2 — Risk Dashboard (SPI, severity breakdown, compliance coverage)
  Page 3 — Top Findings with Compliance Mapping
  Page 4 — Remediation Roadmap & Attestation block
  Page 5+ — Evidence Appendix (code context for SUPPORTED + uncovered CRITICAL/HIGH)
"""

import logging
import os
import traceback
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    PageBreak,
    KeepTogether,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from .base_reporter import BaseReporter
from .framework_mapper import FrameworkMapper
from auditor.core.engine import Finding
from auditor.core.policy import Decision

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Colour palette (professional / conservative for enterprise audience)
# ---------------------------------------------------------------------------
NAVY = colors.HexColor("#0D1B2A")
STEEL = colors.HexColor("#1B3A5C")
ACCENT = colors.HexColor("#1A6FA8")
LIGHT_BLUE = colors.HexColor("#EAF4FB")
C_CRITICAL = colors.HexColor("#C0392B")
C_HIGH = colors.HexColor("#E67E22")
C_MEDIUM = colors.HexColor("#F1C40F")
C_LOW = colors.HexColor("#27AE60")
C_INFO = colors.HexColor("#2980B9")
WHITE = colors.white
LIGHT_GREY = colors.HexColor("#F5F6FA")
MID_GREY = colors.HexColor("#BDC3C7")
TEXT_DARK = colors.HexColor("#1A1A2E")

SEV_COLOR = {
    "CRITICAL": C_CRITICAL,
    "HIGH": C_HIGH,
    "MEDIUM": C_MEDIUM,
    "LOW": C_LOW,
    "INFO": C_INFO,
}


def _sev_color(sev: str):
    return SEV_COLOR.get(sev.upper(), MID_GREY)


# ---------------------------------------------------------------------------
# Style helpers
# ---------------------------------------------------------------------------
def _styles():
    base = getSampleStyleSheet()
    custom = {
        "cover_title": ParagraphStyle(
            "cover_title",
            fontSize=26,
            textColor=WHITE,
            fontName="Helvetica-Bold",
            spaceAfter=6,
            leading=32,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub",
            fontSize=12,
            textColor=colors.HexColor("#A8C8E8"),
            fontName="Helvetica",
            spaceAfter=4,
        ),
        "section_header": ParagraphStyle(
            "section_header",
            fontSize=13,
            textColor=NAVY,
            fontName="Helvetica-Bold",
            spaceBefore=14,
            spaceAfter=6,
            borderPad=4,
        ),
        "body": ParagraphStyle(
            "body",
            fontSize=9,
            textColor=TEXT_DARK,
            fontName="Helvetica",
            leading=14,
            spaceAfter=4,
        ),
        "small": ParagraphStyle(
            "small",
            fontSize=8,
            textColor=colors.HexColor("#555555"),
            fontName="Helvetica",
            leading=12,
        ),
        "label": ParagraphStyle(
            "label",
            fontSize=8,
            textColor=colors.HexColor("#777777"),
            fontName="Helvetica-Bold",
            spaceAfter=2,
        ),
        "metric_big": ParagraphStyle(
            "metric_big",
            fontSize=28,
            textColor=NAVY,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
            leading=32,
        ),
        "metric_label": ParagraphStyle(
            "metric_label",
            fontSize=8,
            textColor=colors.HexColor("#777777"),
            fontName="Helvetica",
            alignment=TA_CENTER,
        ),
        "finding_title": ParagraphStyle(
            "finding_title",
            fontSize=9,
            textColor=NAVY,
            fontName="Helvetica-Bold",
            spaceAfter=2,
        ),
        "tag": ParagraphStyle(
            "tag",
            fontSize=7,
            textColor=WHITE,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
        ),
        "footer": ParagraphStyle(
            "footer",
            fontSize=7,
            textColor=MID_GREY,
            fontName="Helvetica",
            alignment=TA_CENTER,
        ),
        "toc_item": ParagraphStyle(
            "toc_item",
            fontSize=9,
            textColor=ACCENT,
            fontName="Helvetica",
            leading=16,
        ),
    }
    return base, custom


# ---------------------------------------------------------------------------
# Page template (header + footer on every page)
# ---------------------------------------------------------------------------
class _PageTemplate:
    def __init__(self, project_name: str, timestamp: str):
        self.project_name = project_name
        self.timestamp = timestamp

    def __call__(self, canvas, doc):
        canvas.saveState()
        w, h = letter

        # Header bar
        canvas.setFillColor(NAVY)
        canvas.rect(0, h - 40, w, 40, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.setFillColor(WHITE)
        canvas.drawString(
            0.4 * inch, h - 26, "CONFIDENTIAL — Security Assessment Report"
        )
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(w - 0.4 * inch, h - 26, self.project_name)

        # Footer bar
        canvas.setFillColor(LIGHT_GREY)
        canvas.rect(0, 0, w, 28, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MID_GREY)
        canvas.drawString(
            0.4 * inch,
            10,
            f"Generated: {self.timestamp} | Auditor Core Enterprise | "
            f"Confidential — for named recipient only. Not for public distribution.",
        )
        canvas.drawRightString(w - 0.4 * inch, 10, f"Page {doc.page}")

        canvas.restoreState()


# ---------------------------------------------------------------------------
# Main reporter class
# ---------------------------------------------------------------------------
class PDFReporter(BaseReporter):
    """
    Executive-grade PDF reporter targeting SOC 2 readiness and
    cyber insurance underwriting workflows.
    """

    def generate(
        self,
        findings: List[Finding],
        decision: Decision,
        output_path: str,
        project_name: str = "Security Assessment",
        ai_recommendations: Optional[List[Dict]] = None,
    ) -> Optional[Path]:

        def _clean_number(x, default=0):
            try:
                if x is None:
                    return default
                return float(x)
            except:
                return default

        if not self._validate_inputs(findings, decision):
            return None

        for f in findings:
            if f.line is None:
                f.line = 0

        full_path = self._get_safe_path(output_path, project_name, "pdf")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
        _, S = _styles()
        mapper = FrameworkMapper()

        # Build ai_map
        ai_map: Dict[str, Dict] = {}
        if isinstance(ai_recommendations, list):
            for r in ai_recommendations or []:
                if isinstance(r, dict):
                    fid = str(r.get("finding_id") or r.get("id", ""))
                    if fid:
                        ai_map[fid] = r
        elif isinstance(ai_recommendations, dict):
            ai_map = {str(k): v for k, v in ai_recommendations.items()}

        # Enrich findings with compliance mapping
        enriched: List[Dict] = []
        for f in findings:
            cwe = str(getattr(f, "cwe", "") or "")
            cm = mapper.map(
                rule_id=str(f.rule_id),
                cwe=cwe,
                severity=str(f.severity),
                description=str(f.description),
            )
            enriched.append(
                {
                    "finding": f,
                    "compliance": cm,
                    "ai": ai_map.get(str(f.id), {}),
                }
            )

        fw_summary = mapper.build_framework_summary(
            [{"compliance_mapping": e["compliance"]} for e in enriched]
        )

        chains_map = {}
        for item in enriched:
            f = item["finding"]
            c_id = f.meta.get("chain_id")
            if c_id:
                if c_id not in chains_map:
                    chains_map[c_id] = {
                        "rule": f.meta.get("chain_rule"),
                        "findings": [],
                    }
                chains_map[c_id]["findings"].append(f)

        # Stats
        stats = {k: _clean_number(v) for k, v in (decision.summary or {}).items()}
        spi = _clean_number(getattr(decision, "posture_index", 0.0))
        grade = getattr(decision, "posture_grade", "N/A")
        meta = getattr(decision, "meta", {}) or {}
        rca_raw = meta.get("rca", {}) or {}
        rca = {k: _clean_number(v) for k, v in rca_raw.items()}

        doc = SimpleDocTemplate(
            str(full_path),
            pagesize=letter,
            leftMargin=0.6 * inch,
            rightMargin=0.6 * inch,
            topMargin=0.7 * inch,
            bottomMargin=0.55 * inch,
        )

        pt = _PageTemplate(project_name, timestamp)
        story = []

        # ── PAGE 1: COVER ────────────────────────────────────────────────────
        story += self._cover_page(
            S, project_name, timestamp, decision, spi, grade, stats
        )
        story.append(PageBreak())

        # ── PAGE 2: RISK DASHBOARD ───────────────────────────────────────────
        story += self._dashboard_page(S, stats, spi, grade, rca, fw_summary)
        story.append(PageBreak())

        # ── PAGE 3: TOP FINDINGS ─────────────────────────────────────────────
        story += self._findings_page(S, enriched)
        story.append(PageBreak())

        # ── ATTACK PATH ANALYSIS ──────────────────────────────────
        if chains_map:
            style_h2 = S.get("Heading2", S.get("h2", S.get("Normal")))
            story.append(Paragraph("Attack Path Analysis (Critical Chains)", style_h2))
            story.append(Spacer(1, 0.1 * inch))

            for c_id, data in chains_map.items():
                chain_text = f"<b>Chain ID:</b> {c_id}<br/><b>Logic:</b> {data['rule']}"
                story.append(Paragraph(chain_text, S["body"]))
                story.append(Spacer(1, 0.1 * inch))

                step_row = []
                for idx, cf in enumerate(data["findings"]):
                    step_row.append(
                        Paragraph(
                            f"<font color='#ff4d6d'><b>{cf.rule_id}</b></font><br/><font size='8'>{cf.file_path}:{cf.line}</font>",
                            S["small"],
                        )
                    )
                    if idx < len(data["findings"]) - 1:
                        style_h3 = S.get("Heading3", S.get("h3", S.get("Normal")))
                        step_row.append(Paragraph("<b>&rarr;</b>", style_h3))

                from reportlab.platypus import (
                    Table,
                    TableStyle,
                )
                from reportlab.lib import colors

                # Distribute available page width evenly across cells.
                # Without explicit colWidths ReportLab may compute None widths
                # and crash with a TypeError inside _calc_height.
                _page_w = 7.3 * inch  # matches doc left/right margins
                _n_cells = len(step_row)
                _col_w = [_page_w / _n_cells] * _n_cells if _n_cells else [_page_w]
                steps_table = Table([step_row], colWidths=_col_w, hAlign="LEFT")
                steps_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
                            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                            ("LEFTPADDING", (0, 0), (-1, -1), 8),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ]
                    )
                )
                story.append(steps_table)
                story.append(Spacer(1, 0.25 * inch))

            story.append(PageBreak())

        # ── PAGE 4: ROADMAP & ATTESTATION ───────────────────────────────────
        story += self._roadmap_page(S, enriched, fw_summary, project_name, timestamp)

        # ── PAGE 5+: EVIDENCE APPENDIX ───────────────────────────────────────
        # Use the actual project root (stored in decision.meta by orchestrator) so
        # _get_code_snippet can re-read source files. Fallback to output_path if missing.
        _project_root = (meta.get("rca") or {}).get("project_root", "") or output_path
        appendix = self._evidence_appendix_page(S, enriched, project_path=_project_root)
        if appendix:
            story.append(PageBreak())
            story += appendix

        try:
            doc.build(story, onFirstPage=pt, onLaterPages=pt)
            logger.info(f"PDF Reporter: Report saved at {full_path}")
            return full_path
        

        except Exception as e:
            logger.error("PDF Reporter: Build failed with traceback:")
            traceback.print_exc()
            raise

    # ── COVER PAGE ───────────────────────────────────────────────────────────
    def _cover_page(self, S, project_name, timestamp, decision, spi, grade, stats):
        w = 7.3 * inch
        story = []

        # Dark hero banner
        banner_data = [
            [
                Paragraph(
                    f'<font color="white"><b>SECURITY ASSESSMENT REPORT</b></font>',
                    ParagraphStyle(
                        "bh",
                        fontSize=20,
                        fontName="Helvetica-Bold",
                        textColor=WHITE,
                        alignment=TA_CENTER,
                        leading=28,
                    ),
                )
            ]
        ]
        banner = Table(banner_data, colWidths=[w])
        banner.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), NAVY),
                    ("TOPPADDING", (0, 0), (-1, -1), 28),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 28),
                    ("LEFTPADDING", (0, 0), (-1, -1), 20),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 20),
                    ("ROUNDEDCORNERS", (0, 0), (-1, -1), [6, 6, 6, 6]),
                ]
            )
        )
        story.append(Spacer(1, 0.2 * inch))
        story.append(banner)
        story.append(Spacer(1, 0.25 * inch))

        story.append(Paragraph(f"<b>Project:</b> {project_name}", S["body"]))
        story.append(Paragraph(f"<b>Date:</b> {timestamp}", S["body"]))
        story.append(
            Paragraph(
                f"<b>Classification:</b> CONFIDENTIAL — For Named Recipient Only",
                S["body"],
            )
        )
        story.append(Spacer(1, 0.2 * inch))
        story.append(HRFlowable(width="100%", thickness=1, color=MID_GREY))
        story.append(Spacer(1, 0.15 * inch))

        # Executive verdict box
        action = getattr(decision, "action", None)
        action_val = action.value.upper() if action else "UNKNOWN"
        rationale = getattr(decision, "rationale", "")
        _VERDICT_LABEL = {
            "PASS": "ASSESSMENT RESULT: PASS — No critical exposures identified",
            "WARN": "ASSESSMENT RESULT: REQUIRES REMEDIATION",
            "BLOCK": "ASSESSMENT RESULT: CRITICAL — Immediate action required",
            "FAIL": "ASSESSMENT RESULT: REQUIRES REMEDIATION",
        }
        verdict_label = _VERDICT_LABEL.get(
            action_val, f"ASSESSMENT RESULT: {action_val}"
        )
        verdict_color = (
            C_CRITICAL
            if action_val in ("BLOCK", "FAIL")
            else (C_HIGH if action_val == "WARN" else C_LOW)
        )

        verdict_data = [
            [
                Paragraph(
                    f"<b>{verdict_label}</b>",
                    ParagraphStyle(
                        "vt",
                        fontSize=12,
                        fontName="Helvetica-Bold",
                        textColor=WHITE,
                        alignment=TA_CENTER,
                    ),
                ),
            ],
            [
                Paragraph(
                    rationale or "No rationale provided.",
                    ParagraphStyle(
                        "vr",
                        fontSize=9,
                        fontName="Helvetica",
                        textColor=WHITE,
                        alignment=TA_CENTER,
                        leading=14,
                    ),
                ),
            ],
        ]
        verdict_tbl = Table(verdict_data, colWidths=[w])
        verdict_tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), verdict_color),
                    ("TOPPADDING", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                    ("LEFTPADDING", (0, 0), (-1, -1), 16),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 16),
                ]
            )
        )
        story.append(verdict_tbl)
        story.append(Spacer(1, 0.2 * inch))

        # SPI + severity tiles
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        tile_data = [
            [
                Paragraph(
                    f"<b>{spi}</b>",
                    ParagraphStyle(
                        "spi",
                        fontSize=30,
                        fontName="Helvetica-Bold",
                        textColor=NAVY,
                        alignment=TA_CENTER,
                    ),
                ),
                *[
                    Paragraph(
                        f"<b>{stats.get(s, 0)}</b>",
                        ParagraphStyle(
                            f"sv{s}",
                            fontSize=22,
                            fontName="Helvetica-Bold",
                            textColor=_sev_color(s),
                            alignment=TA_CENTER,
                        ),
                    )
                    for s in sev_order
                ],
            ],
            [
                Paragraph("Security Posture Index", S["metric_label"]),
                *[Paragraph(s, S["metric_label"]) for s in sev_order],
            ],
        ]
        col_w = [1.35 * inch] * 6
        tile_tbl = Table(tile_data, colWidths=col_w)
        tile_tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GREY),
                    ("BOX", (0, 0), (-1, -1), 0.5, MID_GREY),
                    ("INNERGRID", (0, 0), (-1, -1), 0.3, MID_GREY),
                    ("TOPPADDING", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ]
            )
        )
        story.append(tile_tbl)
        story.append(Spacer(1, 0.2 * inch))

        # Scope declaration
        story.append(Paragraph("Scope & Methodology", S["section_header"]))
        story.append(
            Paragraph(
                "This report presents the findings of an automated security assessment "
                "conducted using Auditor Core Enterprise. The assessment combined Static "
                "Application Security Testing (SAST), Software Composition Analysis (SCA), "
                "Infrastructure-as-Code (IaC) scanning, secret detection, and CI/CD pipeline "
                "analysis. AI-assisted validation was applied to reduce false positives. "
                "Findings are mapped to SOC 2 Trust Services Criteria, CIS Controls v8, "
                "and ISO/IEC 27001:2022 Annex A.",
                S["body"],
            )
        )
        story.append(Spacer(1, 0.06 * inch))
        story.append(
            Paragraph(
                "<b>Security Posture Index (SPI):</b> Calculated using Weighted Security "
                "Posture Model v2.2 (WSPM). Only production and infrastructure findings are "
                "included — test files and documentation are excluded from the score. "
                "Each rule category is exposure-capped to prevent score distortion from a "
                "single noisy detector. A high SPI alongside critical findings indicates "
                "that critical issues are isolated in scope — they require immediate "
                "remediation regardless of the overall index.",
                S["small"],
            )
        )
        story.append(Spacer(1, 0.1 * inch))

        # Intended use statement
        story.append(HRFlowable(width="100%", thickness=0.5, color=MID_GREY))
        story.append(Spacer(1, 0.1 * inch))
        story.append(
            Paragraph(
                "<b>Intended Use:</b> This report may be used as supporting evidence for "
                "SOC 2 readiness preparation, ISO 27001 gap analysis, and cyber insurance "
                "underwriting pre-assessment. It does not constitute a formal audit opinion "
                "and should be reviewed by a qualified security professional.",
                S["small"],
            )
        )

        return story

    # ── DASHBOARD PAGE ───────────────────────────────────────────────────────
    def _dashboard_page(self, S, stats, spi, grade, rca, fw_summary):
        story = []
        story.append(Paragraph("Risk Dashboard", S["section_header"]))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Spacer(1, 0.15 * inch))
        w = 7.3 * inch

        # SPI gauge row
        gauge_data = [
            [
                Paragraph(
                    f"<b>{spi}</b>",
                    ParagraphStyle(
                        "g1",
                        fontSize=36,
                        fontName="Helvetica-Bold",
                        textColor=NAVY,
                        alignment=TA_CENTER,
                    ),
                ),
                Paragraph(
                    f"<b>{grade}</b>",
                    ParagraphStyle(
                        "g2",
                        fontSize=36,
                        fontName="Helvetica-Bold",
                        textColor=ACCENT,
                        alignment=TA_CENTER,
                    ),
                ),
                Paragraph(
                    f"<b>Exposure:</b> {rca.get('exposure_capped', 'N/A')}<br/>"
                    f"<b>K-Factor:</b> {rca.get('dynamic_k', 'N/A')}<br/>"
                    f"<b>Core/Prod:</b> {rca.get('core_contribution', 0)}%<br/>"
                    f"<b>Test/Noise:</b> {rca.get('test_contribution', 0)}%<br/>"
                    f"<b>AI Excluded:</b> {rca.get('ai_excluded', 0)} findings",
                    ParagraphStyle(
                        "g3",
                        fontSize=9,
                        fontName="Helvetica",
                        textColor=TEXT_DARK,
                        leading=16,
                    ),
                ),
            ],
            [
                Paragraph("Security Posture Index", S["metric_label"]),
                Paragraph("Grade", S["metric_label"]),
                Paragraph("Calculation Parameters", S["metric_label"]),
            ],
        ]
        gauge_tbl = Table(gauge_data, colWidths=[2 * inch, 1.5 * inch, 3.8 * inch])
        gauge_tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (1, -1), LIGHT_BLUE),
                    ("BACKGROUND", (2, 0), (2, -1), LIGHT_GREY),
                    ("BOX", (0, 0), (-1, -1), 0.5, MID_GREY),
                    ("INNERGRID", (0, 0), (-1, -1), 0.3, MID_GREY),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING", (2, 0), (2, -1), 14),
                ]
            )
        )
        story.append(gauge_tbl)
        story.append(Spacer(1, 0.2 * inch))

        # Severity breakdown table
        story.append(Paragraph("Severity Distribution", S["section_header"]))
        sev_rows = [
            [
                Paragraph("<b>Severity</b>", S["label"]),
                Paragraph("<b>Count</b>", S["label"]),
                Paragraph("<b>Indicator</b>", S["label"]),
            ],
        ]
        def _safe_float(x, default=0.0):
            try:
                return float(x)
            except (TypeError, ValueError):
                return default

        def _safe_int(x, default=0):
            try:
                return int(float(x))
            except (TypeError, ValueError):
                return default


        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = _safe_float(stats.get(sev, 0))
            total_stats = sum(_safe_float(v) for v in stats.values()) or 1.0

            raw_width = (count / total_stats) * 180.0 if total_stats else 0.0

            bar_width = min(_safe_int(raw_width), 180) if count > 0 else 0

            safe_width = max(_safe_int(bar_width), 2)

            sev_rows.append(
                [
                    Paragraph(sev, S["body"]),
                    Paragraph(str(int(count)), S["body"]),
                    (
                        Table(
                            [[" "]],
                            colWidths=[safe_width],
                            rowHeights=[12],
                            style=TableStyle([
                                ("BACKGROUND", (0, 0), (-1, -1), _sev_color(sev)),
                            ]),
                        )
                        if count > 0 else Paragraph("—", S["small"])
                    ),
                ]
            )
        sev_tbl = Table(sev_rows, colWidths=[1.5 * inch, 1 * inch, 4.8 * inch])
        sev_tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                    ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
                    ("BOX", (0, 0), (-1, -1), 0.5, MID_GREY),
                    ("INNERGRID", (0, 0), (-1, -1), 0.3, MID_GREY),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(sev_tbl)
        story.append(Spacer(1, 0.2 * inch))

        # Compliance coverage summary
        story.append(Paragraph("Compliance Framework Coverage", S["section_header"]))
        fw_rows = [
            [
                Paragraph("<b>Framework</b>", S["label"]),
                Paragraph("<b>Controls Triggered</b>", S["label"]),
                Paragraph("<b>Top Affected Control</b>", S["label"]),
                Paragraph("<b>Findings</b>", S["label"]),
            ]
        ]
        frameworks = [
            (
                "SOC 2 TSC",
                fw_summary.get("soc2_controls", []),
                "total_soc2_criteria_triggered",
            ),
            (
                "CIS Controls v8",
                fw_summary.get("cis_controls", []),
                "total_cis_safeguards_triggered",
            ),
            (
                "ISO 27001:2022",
                fw_summary.get("iso27001_controls", []),
                "total_iso_controls_triggered",
            ),
        ]
        for fw_name, controls, total_key in frameworks:
            top = controls[0] if controls else {}
            fw_rows.append(
                [
                    Paragraph(fw_name, S["body"]),
                    Paragraph(str(fw_summary.get(total_key, 0)), S["body"]),
                    Paragraph(
                        f"{top.get('id','')} — {top.get('title','')[:45]}", S["small"]
                    ),
                    Paragraph(str(top.get("count", 0)), S["body"]),
                ]
            )
        fw_tbl = Table(
            fw_rows, colWidths=[1.4 * inch, 1.2 * inch, 3.4 * inch, 1.3 * inch]
        )
        fw_tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), STEEL),
                    ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
                    ("BOX", (0, 0), (-1, -1), 0.5, MID_GREY),
                    ("INNERGRID", (0, 0), (-1, -1), 0.3, MID_GREY),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(fw_tbl)
        return story

    # ── TOP FINDINGS PAGE ────────────────────────────────────────────────────
    def _findings_page(self, S, enriched):
        story = []
        story.append(Paragraph("Key Findings", S["section_header"]))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Spacer(1, 0.1 * inch))
        story.append(
            Paragraph(
                "The following findings represent the highest-risk items identified "
                "during the assessment, sorted by severity. Each finding includes its "
                "compliance framework mapping for remediation prioritisation.",
                S["body"],
            )
        )
        story.append(Spacer(1, 0.15 * inch))

        # Group findings by (severity, rule_id, file_path) to avoid
        # showing 13 identical rows for consecutive lines in one file.
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_enriched = sorted(
            enriched, key=lambda x: sev_order.get(x["finding"].severity.upper(), 9)
        )
        # Collapse same rule_id + file_path into one row, collect line numbers
        seen: dict = {}
        grouped: list = []
        for item in sorted_enriched:
            f_obj = item["finding"]
            key = (f_obj.severity.upper(), f_obj.rule_id, f_obj.file_path)
            if key not in seen:
                seen[key] = len(grouped)
                grouped.append({**item, "_lines": [f_obj.line]})
            else:
                grouped[seen[key]]["_lines"].append(f_obj.line)
        top = grouped[:20]
        
        top = [item for item in top if item["finding"].line is not None]

        for idx, item in enumerate(top, start=1):
            f = item["finding"]
            cm = item["compliance"]
            ai = item["ai"]
            sev = f.severity.upper()
            sc = _sev_color(sev)
            raw_lines = item.get("_lines", [f.line])
            lines_list = [l if (l is not None) else 0 for l in raw_lines]
            
            if len(lines_list) <= 1:
                line_val = lines_list[0] if lines_list else 0
                loc_label = f"{str(f.file_path)[-52:]}:{line_val}"
            else:
                sorted_lines = sorted(list(set(lines_list)))
                lines_str = ", ".join(str(l) for l in sorted_lines[:6])
                suffix = " ..." if len(lines_list) > 6 else ""
                loc_label = (
                    f"{str(f.file_path)[-40:]} "
                    f"— {len(lines_list)} instances · lines {lines_str}{suffix}"
                )

            # Severity pill + rule ID header
            header_data = [
                [
                    Paragraph(
                        f"<b>#{idx} &nbsp; {sev}</b>",
                        ParagraphStyle(
                            "eidx",
                            fontSize=8,
                            fontName="Helvetica-Bold",
                            textColor=WHITE,
                            alignment=TA_CENTER,
                        ),
                    ),
                    Paragraph(
                        f"<b>{f.rule_id}</b>",
                        ParagraphStyle(
                            "erid",
                            fontSize=9,
                            fontName="Helvetica-Bold",
                            textColor=NAVY,
                        ),
                    ),
                    Paragraph(
                        loc_label,
                        ParagraphStyle(
                            "loc",
                            fontSize=7,
                            fontName="Helvetica",
                            textColor=colors.HexColor("#777777"),
                            alignment=TA_RIGHT,
                        ),
                    ),
                ]
            ]
            header_tbl = Table(
                header_data, colWidths=[0.8 * inch, 3.5 * inch, 3.0 * inch]
            )
            header_tbl.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, 0), sc),
                        ("BACKGROUND", (1, 0), (-1, 0), LIGHT_GREY),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ]
                )
            )

            # Description + AI verdict
            ai_verdict = ai.get("verdict", "")
            ai_reasoning = ai.get("reasoning", "")[:200] if ai else ""
            desc_text = str(f.description)[:220]

            detail_rows = [
                [
                    Paragraph(
                        f"<b>Description:</b> {desc_text}"
                        + (
                            f"<br/><b>AI Verdict:</b> {ai_verdict} — {ai_reasoning}"
                            if ai_verdict
                            else ""
                        ),
                        S["small"],
                    )
                ]
            ]

            # Compliance tags row
            soc2_ids = " · ".join(x["id"] for x in cm.get("soc2", []))
            cis_ids = " · ".join(x["id"] for x in cm.get("cis", []))
            iso_ids = " · ".join(x["id"] for x in cm.get("iso27001", []))
            tags_text = (
                f'<b><font color="#1A6FA8">SOC2:</font></b> {soc2_ids}    '
                f'<b><font color="#27AE60">CIS:</font></b> {cis_ids}    '
                f'<b><font color="#8E44AD">ISO:</font></b> {iso_ids}'
            )
            detail_rows.append([Paragraph(tags_text, S["small"])])

            detail_tbl = Table(detail_rows, colWidths=[7.3 * inch])
            detail_tbl.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), WHITE),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("BOX", (0, 0), (-1, -1), 0.5, MID_GREY),
                    ]
                )
            )

            story.append(KeepTogether([header_tbl, detail_tbl, Spacer(1, 0.08 * inch)]))

        return story

    # ── EVIDENCE APPENDIX ────────────────────────────────────────────────────
    def _evidence_appendix_page(
        self,
        S: dict,
        enriched: list,
        project_path: str = "",
    ) -> list:
        """
        Builds evidence blocks for:
          - AI SUPPORTED findings (confirmed by AI analysis)
          - CRITICAL / HIGH findings without AI coverage (blind-spot protection)

        Each block contains: finding ID, location, severity, compliance tags,
        AI reasoning (if available), and a fenced code snippet with line numbers.
        """
        CODE_BG = colors.HexColor("#0D1117")
        CODE_FG = colors.HexColor("#C9D1D9")
        LINE_NUM = colors.HexColor("#484F58")
        BORDER = colors.HexColor("#30363D")
        ORANGE = colors.HexColor("#E67E22")
        PURPLE = colors.HexColor("#8E44AD")

        code_style = ParagraphStyle(
            "code",
            fontSize=7,
            fontName="Courier",
            textColor=CODE_FG,
            leading=11,
            backColor=CODE_BG,
            leftIndent=6,
            rightIndent=6,
        )
        linenum_style = ParagraphStyle(
            "linenum",
            fontSize=7,
            fontName="Courier",
            textColor=LINE_NUM,
            leading=11,
            alignment=TA_RIGHT,
        )
        verdict_supported = ParagraphStyle(
            "vs",
            fontSize=8,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#C0392B"),
        )
        verdict_uncovered = ParagraphStyle(
            "vu",
            fontSize=8,
            fontName="Helvetica-Bold",
            textColor=ORANGE,
        )

        def _get_code_snippet(
            finding, project_path: str
        ) -> tuple[list[tuple[int, str]], int]:
            """
            Returns ([(line_no, line_text), ...], target_line_index_in_list).
            Priority: meta._source_code_snippet → re-read file → empty.
            Window: 5 lines before + 10 lines after target line.
            """
            raw_target = getattr(finding, "line", 1)
            target = raw_target if raw_target is not None else 1
            BEFORE, AFTER = 5, 10

            # Priority 1: pre-collected snippet in meta
            snippet = (getattr(finding, "meta", {}) or {}).get(
                "_source_code_snippet", ""
            )
            if snippet:
                raw_lines = snippet.splitlines()
                # snippet is centred around target ±50 (engine.py collects ±50)
                snippet_start = max(1, target - 50)
                # Narrow to our window
                offset = max(0, (target - snippet_start) - BEFORE)
                window = raw_lines[offset : offset + BEFORE + AFTER + 1]
                start_line = snippet_start + offset
                return [(start_line + i, l) for i, l in enumerate(window)], min(
                    BEFORE, target - snippet_start - offset
                )

            # Priority 2: re-read file
            fpath = str(getattr(finding, "file_path", ""))
            if not fpath:
                return [], 0

            # Try relative to project_path first, then absolute
            candidates = [fpath, os.path.join(project_path, fpath)]
            for candidate in candidates:
                if os.path.isfile(candidate):
                    try:
                        with open(
                            candidate, "r", encoding="utf-8", errors="replace"
                        ) as fh:
                            all_lines = fh.readlines()
                        start = max(0, target - 1 - BEFORE)
                        end = min(len(all_lines), target + AFTER)
                        window = all_lines[start:end]
                        return [
                            (start + 1 + i, l.rstrip()) for i, l in enumerate(window)
                        ], target - 1 - start
                    except OSError:
                        pass

            return [], 0

        def _build_code_block(lines_with_nos: list, target_idx: int) -> list:
            """Renders a two-column code table: line numbers | code."""
            if not lines_with_nos:
                return [
                    Paragraph(
                        "<i>Source not available at report generation time.</i>",
                        ParagraphStyle(
                            "na",
                            fontSize=7,
                            fontName="Helvetica",
                            textColor=MID_GREY,
                            leftIndent=8,
                        ),
                    )
                ]
            rows = []
            for i, (lno, text) in enumerate(lines_with_nos):
                is_target = i == target_idx
                bg = colors.HexColor("#2D1B1B") if is_target else CODE_BG
                # Escape XML special chars for ReportLab
                safe = (
                    text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                )
                safe = safe[:160]  # hard cap to prevent layout overflow
                row = [
                    Paragraph(str(lno), linenum_style),
                    Paragraph(f"<b>{safe}</b>" if is_target else safe, code_style),
                ]
                rows.append(row)

            tbl = Table(rows, colWidths=[0.38 * inch, 6.9 * inch])
            style_cmds = [
                ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
                ("TOPPADDING", (0, 0), (-1, -1), 1),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
            if 0 <= target_idx < len(rows):
                style_cmds.append(
                    (
                        "BACKGROUND",
                        (0, target_idx),
                        (-1, target_idx),
                        colors.HexColor("#2D1B1B"),
                    )
                )
            tbl.setStyle(TableStyle(style_cmds))
            return [tbl]

        # ── Select findings for appendix ──────────────────────────────────────
        evidence_items = []
        for item in enriched:
            f = item["finding"]
            ai = item.get("ai", {})
            sev = f.severity.upper()
            verdict = ai.get("verdict", "") if ai else ""

            include = False
            label = ""
            if verdict == "SUPPORTED":
                include = True
                label = "AI CONFIRMED"
            elif sev in ("CRITICAL", "HIGH") and not verdict:
                include = True
                label = "REQUIRES REVIEW (no AI coverage)"
            elif sev in ("CRITICAL", "HIGH") and verdict == "NOT_SUPPORTED":
                # AI dismissed it but it's CRITICAL/HIGH — flag it
                include = True
                label = "AI DISMISSED — MANUAL REVIEW ADVISED"

            if include:
                evidence_items.append((item, label))

        if not evidence_items:
            return []

        story = []
        story.append(Paragraph("Evidence Appendix", S["section_header"]))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Spacer(1, 0.08 * inch))
        story.append(
            Paragraph(
                f"This appendix provides source-level evidence for {len(evidence_items)} finding(s): "
                f"all AI-confirmed (SUPPORTED) findings and any CRITICAL/HIGH findings "
                f"not covered by AI analysis. Code is presented with ±5/10 line context; "
                f"the flagged line is highlighted.",
                S["body"],
            )
        )
        story.append(Spacer(1, 0.12 * inch))

        for idx, (item, label) in enumerate(evidence_items, 1):
            f = item["finding"]
            cm = item["compliance"]
            ai = item.get("ai", {})
            sev = f.severity.upper()
            sc = _sev_color(sev)

            is_supported = ai.get("verdict") == "SUPPORTED"
            vstyle = verdict_supported if is_supported else verdict_uncovered

            line_display = f.line if f.line is not None else 0

            # Header row: index + severity + rule + location
            header_data = [
                [
                    Paragraph(
                        f"<b>#{idx} &nbsp; {sev}</b>",
                        ParagraphStyle(
                            "eidx",
                            fontSize=8,
                            fontName="Helvetica-Bold",
                            textColor=WHITE,
                            alignment=TA_CENTER,
                        ),
                    ),
                    Paragraph(
                        f"<b>{f.rule_id}</b>",
                        ParagraphStyle(
                            "erid",
                            fontSize=9,
                            fontName="Helvetica-Bold",
                            textColor=NAVY,
                        ),
                    ),
                    Paragraph(
                        f"{str(f.file_path)[-62:]}:{line_display}",
                        ParagraphStyle(
                            "eloc",
                            fontSize=7,
                            fontName="Courier",
                            textColor=colors.HexColor("#555555"),
                            alignment=TA_RIGHT,
                        ),
                    ),
                ]
            ]
            header_tbl = Table(
                header_data, colWidths=[1.0 * inch, 2.5 * inch, 3.8 * inch]
            )
            header_tbl.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, 0), sc),
                        ("BACKGROUND", (1, 0), (-1, 0), LIGHT_GREY),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ]
                )
            )

            # Status + compliance tags
            soc2_ids = " · ".join(x["id"] for x in cm.get("soc2", []))
            cis_ids = " · ".join(x["id"] for x in cm.get("cis", []))
            iso_ids = " · ".join(x["id"] for x in cm.get("iso27001", []))
            tags_text = (
                f'<b><font color="#1A6FA8">SOC2:</font></b> {soc2_ids} &nbsp;&nbsp;'
                f'<b><font color="#27AE60">CIS:</font></b> {cis_ids} &nbsp;&nbsp;'
                f'<b><font color="#8E44AD">ISO:</font></b> {iso_ids}'
            )

            meta_rows = [
                [
                    Paragraph(
                        f'<b>Status:</b> <font color="{"#C0392B" if is_supported else "#E67E22"}">{label}</font>',
                        S["small"],
                    )
                ],
                [Paragraph(tags_text, S["small"])],
            ]

            # AI reasoning if available
            reasoning = (
                (ai.get("reasoning") or ai.get("advice", ""))[:350] if ai else ""
            )
            if reasoning:
                meta_rows.append(
                    [
                        Paragraph(
                            f"<b>AI Analysis:</b> {reasoning}{'…' if len(ai.get('reasoning','')) > 350 else ''}",
                            S["small"],
                        )
                    ]
                )

            # Chain info
            if "chain_id" in f.meta:
                chain_html = f'<br/><b>Chain ID:</b> {f.meta["chain_id"]} | <b>Chain Risk:</b> {f.meta.get("chain_risk", "UNKNOWN")} | <b>Rule:</b> {f.meta.get("chain_rule", "")}'
                meta_rows.append([Paragraph(chain_html, S["small"])])

            meta_tbl = Table(meta_rows, colWidths=[7.3 * inch])
            meta_tbl.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), WHITE),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("BOX", (0, 0), (-1, -1), 0.3, MID_GREY),
                    ]
                )
            )

            # Code snippet
            lines_data, target_idx = _get_code_snippet(f, project_path)
            code_elements = _build_code_block(lines_data, target_idx)

            story.append(
                KeepTogether(
                    [
                        header_tbl,
                        meta_tbl,
                        Spacer(1, 0.04 * inch),
                        *code_elements,
                        Spacer(1, 0.14 * inch),
                    ]
                )
            )

        return story

    # ── ROADMAP & ATTESTATION PAGE ───────────────────────────────────────────
    def _roadmap_page(self, S, enriched, fw_summary, project_name, timestamp):
        story = []
        story.append(Paragraph("Remediation Roadmap", S["section_header"]))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
        story.append(Spacer(1, 0.1 * inch))

        # Priority buckets
        buckets = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for item in enriched:
            sev = item["finding"].severity.upper()
            if sev in buckets:
                buckets[sev].append(item)

        roadmap_data = [
            [
                Paragraph("<b>Priority</b>", S["label"]),
                Paragraph("<b>Findings</b>", S["label"]),
                Paragraph("<b>Recommended Action</b>", S["label"]),
                Paragraph("<b>Timeline</b>", S["label"]),
            ]
        ]
        guidance = {
            "CRITICAL": (
                "Immediate — patch or disable affected component within 24–72 hours. "
                "Notify stakeholders.",
                "0–3 days",
            ),
            "HIGH": (
                "Short-term — remediate within current sprint. Apply input validation, "
                "dependency patches, or configuration hardening.",
                "1–2 weeks",
            ),
            "MEDIUM": (
                "Planned — schedule in next release cycle. Review code patterns "
                "and update secure coding guidelines.",
                "1 month",
            ),
            "LOW": (
                "Backlog — address during regular maintenance. "
                "Consider adding automated checks to CI pipeline.",
                "Next quarter",
            ),
        }
        for sev, items in buckets.items():
            if not items:
                continue
            action, timeline = guidance[sev]
            roadmap_data.append(
                [
                    Paragraph(
                        f"<b>{sev}</b>",
                        ParagraphStyle(
                            f"rm{sev}",
                            fontSize=8,
                            fontName="Helvetica-Bold",
                            textColor=WHITE,
                            alignment=TA_CENTER,
                        ),
                    ),
                    Paragraph(str(len(items)), S["body"]),
                    Paragraph(action, S["small"]),
                    Paragraph(f"<b>{timeline}</b>", S["small"]),
                ]
            )
        roadmap_tbl = Table(
            roadmap_data, colWidths=[0.9 * inch, 0.7 * inch, 4.3 * inch, 1.4 * inch]
        )
        row_colors = []
        sev_list = [s for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] if buckets[s]]
        for idx, sev in enumerate(sev_list, start=1):
            row_colors.append(("BACKGROUND", (0, idx), (0, idx), _sev_color(sev)))
        roadmap_tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                    ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
                    ("BOX", (0, 0), (-1, -1), 0.5, MID_GREY),
                    ("INNERGRID", (0, 0), (-1, -1), 0.3, MID_GREY),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("TEXTCOLOR", (0, 1), (0, -1), WHITE),
                    *row_colors,
                ]
            )
        )
        story.append(roadmap_tbl)
        story.append(Spacer(1, 0.2 * inch))

        # SOC 2 control coverage detail
        story.append(Paragraph("SOC 2 Control Exposure Detail", S["section_header"]))
        soc2_rows = [
            [
                Paragraph("<b>Criteria</b>", S["label"]),
                Paragraph("<b>Title</b>", S["label"]),
                Paragraph("<b>Findings Mapped</b>", S["label"]),
            ]
        ]
        for ctrl in fw_summary.get("soc2_controls", [])[:10]:
            soc2_rows.append(
                [
                    Paragraph(ctrl["id"], S["body"]),
                    Paragraph(ctrl["title"], S["small"]),
                    Paragraph(str(ctrl["count"]), S["body"]),
                ]
            )
        soc2_tbl = Table(soc2_rows, colWidths=[1.0 * inch, 5.3 * inch, 1.0 * inch])
        soc2_tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), STEEL),
                    ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
                    ("BOX", (0, 0), (-1, -1), 0.5, MID_GREY),
                    ("INNERGRID", (0, 0), (-1, -1), 0.3, MID_GREY),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(soc2_tbl)
        story.append(Spacer(1, 0.25 * inch))

        # Attestation block
        story.append(HRFlowable(width="100%", thickness=1, color=MID_GREY))
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph("Assessment Attestation", S["section_header"]))

        attest_text = (
            f"This security assessment of <b>{project_name}</b> was conducted using "
            f"Auditor Core Enterprise on {timestamp}. The assessment was performed using "
            f"automated static analysis, dependency scanning, secret detection, and "
            f"AI-assisted validation. Results reflect the state of the codebase at the "
            f"time of scanning and should be treated as point-in-time findings.<br/><br/>"
            f"This document is intended for use by the named organisation's security "
            f"and compliance teams, and may be shared with authorised third parties "
            f"including external auditors and cyber insurance underwriters under "
            f"appropriate non-disclosure agreements.<br/><br/>"
            f"<b>Auditor Core Enterprise</b> | Automated Security Assessment Platform<br/>"
            f"Report integrity is verified via SHA-256 hash of finding content.<br/>"
            f"Assessment conducted in accordance with WSPM v2.2 methodology. "
            f"This report does not constitute a formal SOC 2 audit opinion. "
            f"For SOC 2 Type I/II certification, engage a licensed CPA firm."
        )
        story.append(Paragraph(attest_text, S["body"]))
        story.append(Spacer(1, 0.3 * inch))

        # Signature lines
        sig_data = [
            [
                Paragraph("_" * 35, S["body"]),
                Paragraph("_" * 35, S["body"]),
            ],
            [
                Paragraph("Prepared by / Assessment Lead", S["small"]),
                Paragraph("Reviewed by / Security Officer", S["small"]),
            ],
            [
                Paragraph("Date: ___________________", S["small"]),
                Paragraph("Date: ___________________", S["small"]),
            ],
        ]
        sig_tbl = Table(sig_data, colWidths=[3.65 * inch, 3.65 * inch])
        sig_tbl.setStyle(
            TableStyle(
                [
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        story.append(sig_tbl)
        return story

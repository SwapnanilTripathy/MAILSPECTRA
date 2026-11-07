from datetime import datetime, timezone
import hashlib
import json
import os
import uuid
from html import escape
from backend.app.core.assessment import severity_for_score
from typing import Any, Dict, List, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import HRFlowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.utils.crypto import calculate_hashes


class ForensicReportGenerator:
    """Generates professional, evidence-preserving PDF forensic investigation reports with cryptographic integrity validation."""


    @classmethod
    def generate_case_pdf(
        cls,
        case_data: Dict[str, Any],
        output_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate PDF report for a case, calculate its SHA-256 hash, and return file metadata."""
        # Escape all untrusted strings before interpolating ReportLab paragraph markup.
        def safe(value):
            if isinstance(value,str): return escape(value)
            if isinstance(value,list): return [safe(item) for item in value]
            if isinstance(value,dict): return {key:safe(item) for key,item in value.items()}
            return value
        raw_case_data = case_data
        case_data = safe(case_data)
        reports_dir = output_dir or settings.REPORTS_DIR
        os.makedirs(reports_dir, exist_ok=True)

        case_id = case_data.get("case_id", f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
        clean_case_id = case_id.replace(":", "_").replace("/", "_")
        filename = f"MAILSPECTRA_REPORT_{uuid.uuid4().hex}.pdf"
        filepath = os.path.join(reports_dir, filename)

        doc = SimpleDocTemplate(
            filepath,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
            spaceAfter=4,
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#475569"),
            fontName="Helvetica",
            spaceAfter=12,
        )
        section_heading = ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            fontSize=12,
            leading=15,
            textColor=colors.HexColor("#1e293b"),
            fontName="Helvetica-Bold",
            spaceBefore=10,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "BodyTextCustom",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#334155"),
            fontName="Helvetica",
        )
        body_bold = ParagraphStyle(
            "BodyBoldCustom",
            parent=body_style,
            fontName="Helvetica-Bold",
        )
        code_style = ParagraphStyle(
            "CodeStyleCustom",
            parent=body_style,
            fontName="Courier",
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#0f172a"),
        )
        disclaimer_style = ParagraphStyle(
            "DisclaimerStyle",
            parent=body_style,
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#64748b"),
            fontName="Helvetica-Oblique",
        )

        elements: List[Any] = []

        # ----------------------------------------------------
        # HEADER & BANNER
        # ----------------------------------------------------
        header_table_data = [
            [
                Paragraph("<b>MAILSPECTRA</b> | Digital Forensics & Threat Intelligence", title_style),
                Paragraph(f"<b>CONFIDENTIAL</b><br/>Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", ParagraphStyle("RightH", parent=body_style, alignment=2)),
            ]
        ]
        t_header = Table(header_table_data, colWidths=[360, 180])
        t_header.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
        elements.append(t_header)
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0ea5e9"), spaceBefore=4, spaceAfter=8))

        # ----------------------------------------------------
        # 1. CASE & THREAT OVERVIEW
        # ----------------------------------------------------
        elements.append(Paragraph("1. Executive Threat Summary & Verdict", section_heading))

        classification = case_data.get("classification") or case_data.get("threat_assessment", {}).get("classification", "UNKNOWN")
        risk_score = case_data.get("risk_score") or case_data.get("threat_assessment", {}).get("risk_score", 0.0)
        confidence = case_data.get("confidence") or case_data.get("threat_assessment", {}).get("confidence", 1.0)
        
        # Color coding for severity
        severity_label = severity_for_score(risk_score)
        if severity_label == "CRITICAL":
            badge_bg = colors.HexColor("#fee2e2")
            badge_txt = colors.HexColor("#991b1b")
            severity_label = "CRITICAL"
        elif severity_label == "HIGH":
            badge_bg = colors.HexColor("#ffedd5")
            badge_txt = colors.HexColor("#9a3412")
            severity_label = "HIGH"
        elif severity_label == "MEDIUM":
            badge_bg = colors.HexColor("#fef9c3")
            badge_txt = colors.HexColor("#854d0e")
            severity_label = "MEDIUM"
        else:
            badge_bg = colors.HexColor("#dcfce7")
            badge_txt = colors.HexColor("#166534")


        overview_data = [
            [
                Paragraph("<b>Case ID:</b>", body_style), Paragraph(str(case_id), code_style),
                Paragraph("<b>Threat Verdict:</b>", body_style), Paragraph(f"<b>{classification}</b>", ParagraphStyle("Verdict", parent=body_style, textColor=badge_txt)),
            ],
            [
                Paragraph("<b>Filename:</b>", body_style), Paragraph(str(case_data.get("filename", "email.eml")), body_style),
                Paragraph("<b>Risk Score:</b>", body_style), Paragraph(f"<b>{risk_score}/100</b> ({severity_label})", body_style),
            ],
            [
                Paragraph("<b>Subject:</b>", body_style), Paragraph(str(case_data.get("subject") or case_data.get("metadata", {}).get("subject", "N/A")), body_style),
                Paragraph("<b>Model Confidence:</b>", body_style), Paragraph(f"{round(confidence * 100, 1)}%", body_style),
            ],
            [
                Paragraph("<b>From Sender:</b>", body_style), Paragraph(str(case_data.get("from_address") or case_data.get("metadata", {}).get("from_sender", {}).get("raw", "N/A")), body_style),
                Paragraph("<b>Investigation Status:</b>", body_style), Paragraph(str(case_data.get("status", "OPEN")), body_style),
            ],
        ]

        t_overview = Table(overview_data, colWidths=[80, 190, 100, 170])
        t_overview.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_overview)
        elements.append(Spacer(1, 8))

        # ----------------------------------------------------
        # 2. EVIDENCE PRESERVATION & HASHES
        # ----------------------------------------------------
        elements.append(Paragraph("2. Evidence Chain of Custody & Cryptographic Hashes", section_heading))
        ev_hashes = case_data.get("evidence_hashes", {})
        hash_sha256 = case_data.get("sha256") or ev_hashes.get("sha256", "N/A")
        hash_md5 = ev_hashes.get("md5", "N/A")
        hash_sha1 = ev_hashes.get("sha1", "N/A")
        file_size = case_data.get("file_size_bytes", "N/A")

        hash_table_data = [
            [Paragraph("<b>Evidence Type</b>", body_bold), Paragraph("RFC 822 / MIME Email Artifact (.EML)", body_style)],
            [Paragraph("<b>File Size</b>", body_bold), Paragraph(f"{file_size} bytes", body_style)],
            [Paragraph("<b>SHA-256 Hash</b>", body_bold), Paragraph(str(hash_sha256), code_style)],
            [Paragraph("<b>SHA-1 Hash</b>", body_bold), Paragraph(str(hash_sha1), code_style)],
            [Paragraph("<b>MD5 Hash</b>", body_bold), Paragraph(str(hash_md5), code_style)],
            [Paragraph("<b>Integrity Status</b>", body_bold), Paragraph("Digest recorded. Reverification is a separate operation.", ParagraphStyle("G", parent=body_style, textColor=colors.HexColor("#166534")))],
        ]
        t_hashes = Table(hash_table_data, colWidths=[130, 410])
        t_hashes.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(t_hashes)
        elements.append(Spacer(1, 8))

        # ----------------------------------------------------
        # 3. AUTHENTICATION & HEADER FORENSICS
        # ----------------------------------------------------
        elements.append(Paragraph("3. Email Header & Authentication Forensics", section_heading))
        auth = case_data.get("authentication", {})
        meta = case_data.get("metadata", {})

        auth_table_data = [
            [Paragraph("<b>Protocol</b>", body_bold), Paragraph("<b>Status</b>", body_bold), Paragraph("<b>Observed Alignment & Details</b>", body_bold)],
            [Paragraph("<b>SPF</b>", body_style), Paragraph(str(auth.get("spf_result", "none")).upper(), body_bold), Paragraph(str(auth.get("spf_details") or "Reported SPF claim (untrusted)"), body_style)],
            [Paragraph("<b>DKIM</b>", body_style), Paragraph(str(auth.get("dkim_result", "none")).upper(), body_bold), Paragraph(str(auth.get("dkim_details") or "Reported DKIM claim (untrusted)"), body_style)],
            [Paragraph("<b>DMARC</b>", body_style), Paragraph(str(auth.get("dmarc_result", "none")).upper(), body_bold), Paragraph(str(auth.get("dmarc_details") or "Reported DMARC claim (untrusted)"), body_style)],
        ]
        t_auth = Table(auth_table_data, colWidths=[70, 70, 400])
        t_auth.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(t_auth)
        elements.append(Spacer(1, 8))

        # ----------------------------------------------------
        # 4. EXPLAINABLE AI & SHAP ATTRIBUTION
        # ----------------------------------------------------
        elements.append(Paragraph("4. AI Threat Detection & SHAP Feature Explanations", section_heading))
        shap_exp = (case_data.get("shap_explanation") or {})
        top_feats = shap_exp.get("top_features", [])

        if top_feats:
            shap_table_data = [
                [Paragraph("<b>Observed Signal / Feature</b>", body_bold), Paragraph("<b>Impact</b>", body_bold), Paragraph("<b>SHAP Value</b>", body_bold), Paragraph("<b>Analyst Explanation</b>", body_bold)]
            ]
            for f in top_feats[:6]:
                direct = f.get("direction", "increases_risk")
                dir_txt = "INCREASES RISK" if direct == "increases_risk" else "DECREASES RISK"
                dir_color = colors.HexColor("#dc2626") if direct == "increases_risk" else colors.HexColor("#16a34a")
                
                shap_table_data.append([
                    Paragraph(str(f.get("feature_name", f.get("feature", "N/A"))), body_style),
                    Paragraph(f"<b>{dir_txt}</b>", ParagraphStyle("Dir", parent=body_style, textColor=dir_color)),
                    Paragraph(str(f.get("contribution", 0.0)), code_style),
                    Paragraph(str(f.get("description", "")), body_style),
                ])

            t_shap = Table(shap_table_data, colWidths=[130, 95, 65, 250])
            t_shap.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            elements.append(t_shap)
        else:
            elements.append(Paragraph("No anomalous AI risk features observed.", body_style))

        elements.append(Spacer(1, 8))

        # ----------------------------------------------------
        # 5. ORIGIN & INFRASTRUCTURE INTELLIGENCE
        # ----------------------------------------------------
        elements.append(Paragraph("5. Origin Assessment & Infrastructure Telemetry", section_heading))
        origin = (case_data.get("origin_assessment") or {})
        infra = case_data.get("infrastructure_intelligence", {})
        earliest_ip = origin.get("earliest_reliable_ip") or case_data.get("origin_ip", "N/A")
        
        geo_info = {}
        if infra and infra.get("ip_intelligence") and earliest_ip in infra["ip_intelligence"]:
            geo_info = infra["ip_intelligence"][earliest_ip]

        origin_table_data = [
            [
                Paragraph("<b>Earliest Observable Source IP:</b>", body_style),
                Paragraph(str(earliest_ip), code_style),
                Paragraph("<b>Assessment Confidence:</b>", body_style),
                Paragraph(f"{round(origin.get('confidence', 0) * 100, 1)}%", body_style),
            ],
            [
                Paragraph("<b>Probable GeoLocation:</b>", body_style),
                Paragraph(f"{geo_info.get('city') or ''}, {geo_info.get('country') or 'Unknown'}", body_style),
                Paragraph("<b>Autonomous System (ASN):</b>", body_style),
                Paragraph(str(geo_info.get("asn") or "N/A"), body_style),
            ],
            [
                Paragraph("<b>Internet Service Provider (ISP):</b>", body_style),
                Paragraph(str(geo_info.get("isp") or geo_info.get("organization") or "N/A"), body_style),
                Paragraph("<b>Anonymization / Proxy Flag:</b>", body_style),
                Paragraph(str(geo_info.get("proxy_or_vpn", "False")), body_style),
            ],
        ]
        t_origin = Table(origin_table_data, colWidths=[140, 160, 120, 120])
        t_origin.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(t_origin)
        elements.append(Spacer(1, 8))

        # ----------------------------------------------------
        # 6. THREAT GRAPH & CAMPAIGN CORRELATION
        # ----------------------------------------------------
        elements.append(Paragraph("6. Threat Graph Infrastructure & Campaign Clustering", section_heading))
        graph = (case_data.get("threat_graph") or {})
        camp = (case_data.get("active_campaign") or {})
        attr = (case_data.get("attribution_support") or {})

        graph_summary_data = [
            [
                Paragraph("<b>Graph Node Count:</b>", body_style), Paragraph(str(graph.get("total_nodes", 0)), body_style),
                Paragraph("<b>Graph Edge Count:</b>", body_style), Paragraph(str(graph.get("total_edges", 0)), body_style),
            ],
            [
                Paragraph("<b>Active Threat Campaign:</b>", body_style), Paragraph(str(camp.get("campaign_id") or "No active campaign"), body_style),
                Paragraph("<b>Attribution Category:</b>", body_style), Paragraph(str(attr.get("assessment", "INSUFFICIENT_EVIDENCE")), body_style),
            ],
        ]
        t_graph = Table(graph_summary_data, colWidths=[120, 150, 120, 150])
        t_graph.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(t_graph)
        elements.append(Spacer(1, 10))

        # ----------------------------------------------------
        # 7. FORENSIC DISCLAIMERS & REPORT INTEGRITY
        # ----------------------------------------------------
        elements.append(Paragraph("7. Investigation Limitations & Legal Disclaimers", section_heading))
        disclaimer_text = (
            "<b>NOTICE:</b> Attribution support, IP geolocation, and threat graph relationships reflect technical infrastructure "
            "telemetry and algorithmic pattern matching. They indicate network routing associations and do not constitute definitive "
            "identification of a physical human individual or legal entity. Static analysis was performed without dynamic payload execution."
        )
        elements.append(Paragraph(disclaimer_text, disclaimer_style))
        elements.append(Spacer(1, 10))

        elements.append(Paragraph("8. Evidence manifest, verification and analysis details", section_heading))
        elements.append(Paragraph("MAILSPECTRA derives from DEEPTRACE / SIH26106; upstream attribution and license are retained. The PDF digest is supplied in the accompanying manifest because a file cannot contain its own final digest. Original artifact and PDF hashes serve different purposes.", body_style))
        for key in ("artifact", "evidence_manifest", "risk_assessment", "authentication", "ai_inference", "relay_chain", "urls", "ips", "attachments", "content_intelligence", "infrastructure_intelligence", "campaign_correlations", "timeline", "limitations"):
            value = raw_case_data.get(key)
            if value is None: continue
            elements.append(Paragraph(key.replace("_", " ").title(), body_bold))
            rendered = json.dumps(value,ensure_ascii=True,indent=2)
            # Bound the PDF; the complete snapshot remains available through the case API.
            if len(rendered) > 16000: rendered = rendered[:16000] + "\n[Section truncated; consult persisted case evidence]"
            for line in rendered.splitlines():
                for start in range(0,max(1,len(line)),100):
                    elements.append(Paragraph(escape(line[start:start+100]) or " ",code_style))
        elements.append(Paragraph("Model probabilities are uncalibrated demonstration results. Masking is best-effort presentation redaction, not guaranteed anonymization. Supplied authentication and relay headers may be forged.", disclaimer_style))

        # Build Document
        doc.build(elements)
        os.chmod(filepath, 0o600)

        # Compute SHA-256 hash of the generated PDF report
        with open(filepath, "rb") as f:
            pdf_bytes = f.read()
        report_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
        report_size = len(pdf_bytes)

        logger.info(f"Generated Forensic PDF Report: {filename} ({report_size} bytes, SHA-256: {report_sha256})")

        return {
            "filename": filename,
            "filepath": filepath,
            "filesize_bytes": report_size,
            "sha256": report_sha256,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "case_id": case_id,
        }

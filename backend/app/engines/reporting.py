from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from io import BytesIO
from datetime import datetime

def generate_board_brief_pdf(assets, rating, scan_date=None):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    display_date = scan_date if scan_date else datetime.now().strftime('%Y-%m-%d')

    # Header
    elements.append(Paragraph("Q-GUARDIAN | QUANTUM TRANSITION INTELLIGENCE", styles['Title']))
    elements.append(Paragraph(f"BOARD BRIEF - {display_date}", styles['Heading2']))
    elements.append(Spacer(1, 12))

    # Calculate Risk Statistics
    critical_assets = [a for a in assets if a.get('mosca', {}).get('risk_state') == 'CRITICAL']
    warning_assets = [a for a in assets if a.get('mosca', {}).get('risk_state') == 'WARNING']
    all_days = [a.get('mosca', {}).get('days_remaining_worst', 9999) for a in assets]
    min_days = min(all_days) if all_days else 0

    # Executive Summary
    elements.append(Paragraph("EXECUTIVE SUMMARY", styles['Heading3']))
    
    if critical_assets:
        narrative = f"CRITICAL: {len(critical_assets)} asset(s) have breached the Mosca safety threshold. Immediate migration planning is required for core infrastructure."
    elif warning_assets:
        narrative = f"WARNING: The enterprise risk window opens in as little as {min_days} days. Staged migration for sensitive tiers should commence within this quarter."
    else:
        narrative = f"All discovered assets are currently within the Mosca safe zone. Continued monitoring of nation-state CRQC progress is recommended."
        
    summary_text = f"The enterprise cyber rating is currently <b>{rating['score']} ({rating['status']})</b> based on {rating['asset_count']} discovered assets. {narrative}"
    elements.append(Paragraph(summary_text, styles['Normal']))
    elements.append(Spacer(1, 12))

    # Top Risks Table
    elements.append(Paragraph("TOP 5 CRYPTOGRAPHIC RISKS", styles['Heading3']))
    data = [["Asset Hostname", "Algorithm", "QTRI Score", "Mosca Countdown"]]
    
    # Sort assets by QTRI score (lowest first)
    sorted_assets = sorted(assets, key=lambda x: x['qtri_score'])[:5]
    for asset in sorted_assets:
        data.append([
            asset['hostname'],
            asset['algorithm'],
            str(asset['qtri_score']),
            f"{asset['mosca']['days_remaining_worst']} Days"
        ])

    t = Table(data)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.maroon),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(t)
    elements.append(Spacer(1, 24))

    # Regulatory Alignment
    elements.append(Paragraph("REGULATORY ALIGNMENT", styles['Heading3']))
    elements.append(Paragraph("This report maps to RBI Cybersecurity Framework (CSF) 2.0 and NIST IR 8547 PQC Migration Guidelines.", styles['Normal']))

    # HNDL Grounding Disclaimer
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("HNDL SIMULATION ADVISORY", styles['Heading3']))
    elements.append(Paragraph(
        "<b>Weakly Grounded Notice:</b> Harvest-Now-Decrypt-Later (HNDL) exposure volumes reported in this brief are calculated using "
        "RBI-tiered conservative traffic baselines (NSA HNDL Advisory 2023). Without real-time packet capture (PCAP) data or network "
        "telemetry integration, these figures represent a <b>theoretical risk ceiling</b>, not a verified exfiltration measurement. "
        "Security analysts should use these metrics for risk prioritization only.",
        styles['Normal']
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf_report(
    filename,
    headers,
    score,
    attack_type,
    reasons,
    recommendations,
    auth,
    domain_info,
    domain_age,
    ip_info,
    iocs,
    attachments
):

    doc = SimpleDocTemplate(
        filename,
        pagesize=letter
    )

    styles = getSampleStyleSheet()

    content = []

    # Title

    content.append(
        Paragraph(
            "EmailShield Enterprise Incident Report",
            styles["Title"]
        )
    )

    content.append(
        Spacer(1, 12)
    )

    # Summary

    content.append(
        Paragraph(
            "Incident Summary",
            styles["Heading1"]
        )
    )

    content.append(
        Paragraph(
            f"<b>Attack Type:</b> {attack_type}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"<b>Risk Score:</b> {score}/100",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"<b>Sender:</b> {headers['from']}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"<b>Subject:</b> {headers['subject']}",
            styles["BodyText"]
        )
    )

    content.append(
        Spacer(1, 10)
    )

    # Authentication

    content.append(
        Paragraph(
            "Authentication Results",
            styles["Heading1"]
        )
    )

    content.append(
        Paragraph(
            f"SPF: {auth['spf']}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"DKIM: {auth['dkim']}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"DMARC: {auth['dmarc']}",
            styles["BodyText"]
        )
    )

    # Domain Intelligence

    content.append(
        Spacer(1, 10)
    )

    content.append(
        Paragraph(
            "Domain Intelligence",
            styles["Heading1"]
        )
    )

    if domain_info:

        content.append(
            Paragraph(
                f"Registrar: {domain_info['registrar']}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"Domain Age: {domain_age}",
                styles["BodyText"]
            )
        )

    # IP Intelligence

    content.append(
        Spacer(1, 10)
    )

    content.append(
        Paragraph(
            "IP Intelligence",
            styles["Heading1"]
        )
    )

    if ip_info:

        content.append(
            Paragraph(
                f"Country: {ip_info['country']}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"ISP: {ip_info['isp']}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"Abuse Score: {ip_info['abuse_score']}",
                styles["BodyText"]
            )
        )

    # RCA

    content.append(
        Spacer(1, 10)
    )

    content.append(
        Paragraph(
            "RCA Findings",
            styles["Heading1"]
        )
    )

    for reason in reasons:

        content.append(
            Paragraph(
                f"• {reason}",
                styles["BodyText"]
            )
        )

    # Recommendations

    content.append(
        Spacer(1, 10)
    )

    content.append(
        Paragraph(
            "Recommendations",
            styles["Heading1"]
        )
    )

    for rec in recommendations:

        content.append(
            Paragraph(
                f"• {rec}",
                styles["BodyText"]
            )
        )

    # Attachments

    content.append(
        Spacer(1, 10)
    )

    content.append(
        Paragraph(
            "Attachments",
            styles["Heading1"]
        )
    )

    for attachment in attachments:

        content.append(
            Paragraph(
                attachment["filename"],
                styles["BodyText"]
            )
        )

    # IOCs

    content.append(
        Spacer(1, 10)
    )

    content.append(
        Paragraph(
            "IOCs",
            styles["Heading1"]
        )
    )

    content.append(
        Paragraph(
            f"Domains: {', '.join(iocs['domains'])}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"IPs: {', '.join(iocs['ips'])}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"URLs: {', '.join(iocs['urls'])}",
            styles["BodyText"]
        )
    )

    doc.build(content)
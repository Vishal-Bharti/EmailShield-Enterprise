from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet


def safe(value):
    """Escape a value for safe insertion into a reportlab Paragraph.

    reportlab's Paragraph parses a small XML/HTML-like markup language.
    Since this app processes untrusted, attacker-controlled email
    content (subject lines, sender addresses, attachment filenames),
    inserting that text directly into Paragraph() without escaping can
    either crash report generation (malformed markup) or let a crafted
    email inject its own formatting into the PDF. Every value that
    originates from the analyzed email must go through this first.
    """

    if value is None:
        return "N/A"

    return escape(str(value))


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
    attachments,
    domain_rep=None,
    spam_result=None
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
            f"<b>Attack Type:</b> {safe(attack_type)}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"<b>Risk Score:</b> {safe(score)}/100",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"<b>Sender:</b> {safe(headers.get('from'))}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"<b>Subject:</b> {safe(headers.get('subject'))}",
            styles["BodyText"]
        )
    )

    if spam_result:

        content.append(
            Paragraph(
                f"<b>Spam Verdict:</b> {safe(spam_result.get('verdict'))} "
                f"({safe(spam_result.get('spam_score'))}/100)",
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
            f"SPF: {safe(auth['spf'])}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"DKIM: {safe(auth['dkim'])}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"DMARC: {safe(auth['dmarc'])}",
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
                f"Registrar: {safe(domain_info.get('registrar'))}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"Domain Age: {safe(domain_age)}",
                styles["BodyText"]
            )
        )

    if domain_rep:

        if domain_rep.get("malicious") == -1:

            content.append(
                Paragraph(
                    "VirusTotal Reputation: Unavailable",
                    styles["BodyText"]
                )
            )

        else:

            content.append(
                Paragraph(
                    f"VirusTotal - Malicious: {safe(domain_rep.get('malicious'))}, "
                    f"Suspicious: {safe(domain_rep.get('suspicious'))}, "
                    f"Harmless: {safe(domain_rep.get('harmless'))}",
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
                f"Country: {safe(ip_info['country'])}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"ISP: {safe(ip_info['isp'])}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"Abuse Score: {safe(ip_info['abuse_score'])}",
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
                f"• {safe(reason)}",
                styles["BodyText"]
            )
        )

    # Spam Indicators

    if spam_result and spam_result.get("reasons"):

        content.append(
            Spacer(1, 10)
        )

        content.append(
            Paragraph(
                "Spam Indicators",
                styles["Heading1"]
            )
        )

        for reason in spam_result["reasons"]:

            content.append(
                Paragraph(
                    f"• {safe(reason)}",
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
                f"• {safe(rec)}",
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

    if attachments:

        for attachment in attachments:

            content.append(
                Paragraph(
                    f"<b>{safe(attachment.get('filename'))}</b> "
                    f"({safe(attachment.get('size'))} bytes, "
                    f"declared: {safe(attachment.get('content_type'))}, "
                    f"detected: {safe(attachment.get('detected_file_type', 'UNKNOWN'))})",
                    styles["BodyText"]
                )
            )

            flags = []

            if attachment.get("extension_spoofed"):
                flags.append("Extension spoofing detected")

            if attachment.get("double_extension"):
                flags.append("Double extension trick detected")

            if attachment.get("bidi_override"):
                flags.append("Unicode filename spoofing detected")

            if attachment.get("script_indicators"):
                flags.append(
                    "Suspicious script content: "
                    + ", ".join(attachment["script_indicators"])
                )

            for flag in flags:

                content.append(
                    Paragraph(
                        f"⚠ {safe(flag)}",
                        styles["BodyText"]
                    )
                )

    else:

        content.append(
            Paragraph(
                "No attachments found.",
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
            f"Domains: {safe(', '.join(iocs['domains']) if iocs['domains'] else 'None')}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"IPs: {safe(', '.join(iocs['ips']) if iocs['ips'] else 'None')}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"URLs: {safe(', '.join(iocs['urls']) if iocs['urls'] else 'None')}",
            styles["BodyText"]
        )
    )

    doc.build(content)

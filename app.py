import os
import re
import html
from pathlib import Path

import streamlit as st

from config import get_secret, mask_secret

VIRUSTOTAL_API_KEY = get_secret("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = get_secret("ABUSEIPDB_API_KEY")

if VIRUSTOTAL_API_KEY:
    os.environ["VIRUSTOTAL_API_KEY"] = VIRUSTOTAL_API_KEY

if ABUSEIPDB_API_KEY:
    os.environ["ABUSEIPDB_API_KEY"] = ABUSEIPDB_API_KEY

from analyzers.header_parser import parse_eml
from analyzers.auth_analyzer import analyze_authentication
from analyzers.ip_extractor import extract_ips
from analyzers.domain_extractor import extract_domain
from analyzers.ioc_extractor import extract_iocs

from intelligence.whois_lookup import (
    get_domain_info,
    calculate_domain_age
)

from intelligence.ip_reputation import (
    check_ip_reputation
)

from intelligence.domain_reputation import (
    check_domain_reputation
)

from database.db import (
    create_database,
    save_email
)

from analyzers.threat_score import (
    calculate_risk_score
)

from analyzers.attack_classifier import (
    classify_attack
)
from analyzers.recommendation_engine import (
    get_recommendations
)

from analyzers.attachment_analyzer import (
    analyze_attachments
)
from analyzers.ip_filter import (
    get_public_ips
)
from analyzers.spam_detector import (
    analyze_spam
)

from reports.pdf_report import (
    generate_pdf_report
)


from analyzers.routing_analyzer import (
    analyze_routing,
    get_originating_ip
)

create_database()

st.title("EmailShield Enterprise")
st.caption(
    f"API key status: VirusTotal={mask_secret(VIRUSTOTAL_API_KEY)}, "
    f"AbuseIPDB={mask_secret(ABUSEIPDB_API_KEY)}"
)

if not VIRUSTOTAL_API_KEY and not ABUSEIPDB_API_KEY:
    st.info("No API keys configured. Add them in Streamlit Secrets or environment variables.")

uploaded_file = st.file_uploader(
    "Upload EML File",
    type=["eml"]
)

if uploaded_file:
    status = st.status(
    "🚀 Starting Analysis...",
    expanded=True
    )

    progress = st.progress(0)

    status.write(
    "📧 Parsing Email..."
    )

    headers, msg = parse_eml(
        uploaded_file
    )

    sender = headers.get("from", "Unknown")
    subject = headers.get("subject", "Unknown")
    to_addr = headers.get("to", "Unknown")
    reply_to = headers.get("reply_to", "Unknown")
    return_path = headers.get("return_path", "Unknown")
    date_value = headers.get("date", "Unknown")

    progress.progress(10)
    routing_data = analyze_routing(
    msg
    )
    origin_ip = get_originating_ip(
    routing_data
    )

    status.write(
    "🛣 Analyzing Email Routing..."
    )

    progress.progress(20)

    attachments = analyze_attachments(
    msg
    )
    status.write(
    "📎 Analyzing Attachments..."
    )

    progress.progress(30)


    # -------------------------
    # Extract Email Body
    # -------------------------

    def html_to_text(html_content):
        """Strip tags and decode entities so IOC/spam analysis has
        something to work with even when there's no text/plain part."""

        # Drop script/style blocks entirely
        text = re.sub(r"(?is)<(script|style).*?>.*?(</\1>)", " ", html_content)
        # Turn common block/line-break tags into newlines
        text = re.sub(r"(?i)<(br|/p|/div|/tr|/li)\s*/?>", "\n", text)
        # Strip remaining tags
        text = re.sub(r"(?s)<[^>]+>", " ", text)
        text = html.unescape(text)
        # Collapse excess whitespace
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n\s*\n+", "\n", text)
        return text.strip()

    def extract_html_links(html_content):
        """Pull raw href URLs out of anchor tags - the displayed link text
        can differ from the real destination, a classic phishing trick."""

        return re.findall(r'href=["\']([^"\']+)["\']', html_content, re.IGNORECASE)

    plain_text_body = ""
    html_body = ""

    if msg.is_multipart():

        for part in msg.walk():

            content_type = part.get_content_type()

            if content_type == "text/plain":

                try:

                    plain_text_body += (
                        part.get_payload(
                            decode=True
                        ).decode(
                            errors="ignore"
                        )
                    )

                except:
                    pass

            elif content_type == "text/html":

                try:

                    html_body += (
                        part.get_payload(
                            decode=True
                        ).decode(
                            errors="ignore"
                        )
                    )

                except:
                    pass

    else:

        content_type = msg.get_content_type()

        try:

            payload = msg.get_payload(
                decode=True
            ).decode(
                errors="ignore"
            )

            if content_type == "text/html":
                html_body = payload
            else:
                plain_text_body = payload

        except:
            pass

    # Prefer plain text (cleaner for regex matching); fall back to
    # HTML-stripped text if no plain-text part exists, so email_body is
    # never silently empty for HTML-only phishing emails.
    if plain_text_body.strip():
        email_body = plain_text_body
    elif html_body.strip():
        email_body = html_to_text(html_body)
    else:
        email_body = ""

    # Surface raw href URLs from HTML too, so extract_iocs catches the
    # real destination even when the visible link text looks harmless.
    if html_body:

        html_links = extract_html_links(html_body)

        if html_links:
            email_body += "\n" + "\n".join(html_links)

    # -------------------------
    # IOC Extraction
    # -------------------------

    iocs = extract_iocs(
        email_body
    )
    status.write(
    "🔍 Extracting IOCs..."
    )

    progress.progress(40)

    # -------------------------
    # Authentication
    # -------------------------

    auth = analyze_authentication(
        msg
    )
    status.write(
    "🛡 Analyzing Authentication..."
    )

    progress.progress(50)

    # -------------------------
    # IP Analysis
    # -------------------------

    ips = extract_ips(msg)

    public_ips = get_public_ips(
        ips
    )

    public_ip = public_ips[0] if public_ips else "Unknown"

    ip_info = None

    if public_ip != "Unknown":
        ip_info = check_ip_reputation(
            public_ip
        )
    status.write(
    "🌍 Checking IP Reputation..."
    )

    progress.progress(65)

        

    # -------------------------
    # Domain Analysis
    # -------------------------

    sender_domain = extract_domain(
        sender
    ) if sender and sender != "Unknown" else "Unknown"

    domain_info = None
    domain_rep = None
    domain_age = None

    if sender_domain and sender_domain != "Unknown":
        domain_info = get_domain_info(
            sender_domain
        )
        domain_rep = check_domain_reputation(
            sender_domain
        )
    status.write(
    "🌐 Performing Domain Intelligence..."
    )

    progress.progress(75)

    status.write(
    "🔥 Checking VirusTotal..."
    )

    progress.progress(85)

    if domain_info and domain_info.get("created"):
        domain_age = calculate_domain_age(
            domain_info["created"]
        )

        
    

    # Debug (helps identify why risk score stays 0)
    print("=== Risk Score Inputs ===")
    print("auth:", auth)
    print("domain_age:", domain_age)
    print("ip_info:", ip_info)
    print("domain_rep:", domain_rep)
    print("attachments_count:", len(attachments))
    if attachments:
        print("attachment_filenames:", [a.get("filename") for a in attachments])

    score, reasons = calculate_risk_score(

        auth,
        domain_age,
        ip_info,
        domain_rep,
        attachments,
        routing_data,
        origin_ip
    )
    status.write(
    "🎯 Calculating Threat Score..."
    )

    spam_result = analyze_spam(
        email_body,
        headers=headers,
        auth=auth,
        iocs=iocs,
        attachments=attachments,
    )

    progress.progress(95)

    print("=== Risk Score Output ===")
    print("score:", score)
    print("reasons:", reasons)
    attack_type, attack_evidence = classify_attack(
        auth,
        domain_age,
        iocs,
        score
    )
    recommendations = get_recommendations(
    score
        )
    progress.progress(100)

    status.update(
        label="✅ Analysis Complete",
        state="complete"
    )
    st.subheader(

        "Threat Assessment"
        )

    st.metric(

        "Risk Score",
        f"{score}/100"
    )

    st.metric(
        "Spam Score",
        f"{spam_result['spam_score']}/100"
    )

    if spam_result["is_spam"]:
        st.error("🚨 LIKELY SPAM")
    else:
        st.success("✅ LIKELY NOT SPAM")

    if score >= 70:

        st.error(
        "🚨 HIGH CONFIDENCE PHISHING"
        )

    elif score >= 40:

        st.warning(
        "⚠ SUSPICIOUS EMAIL"
    )

    else:

        st.success(
        "✅ LOW RISK EMAIL"
    )
    
    
    st.subheader(

        "RCA Findings"
    )

    if reasons:

        for reason in reasons:

            st.write(
                f"• {reason}"
            )

    else:

        st.write(
            "No suspicious indicators found."
        )
    
    st.subheader(

        "Attack Classification"
        )

    st.write(
        "Attack Type:",
        attack_type
    )
    st.write(

            "Classification Evidence:"
    )

    for item in attack_evidence:


        st.write(
        f"• {item}"
    )
    st.subheader("Incident Summary")

    st.write(
        f"""
        Attack Type: {attack_type}

        Risk Score: {score}/100

        Verdict:

        {"HIGH CONFIDENCE PHISHING" if score >= 70 else "SUSPICIOUS"}

        Sender:

        {sender}

        Domain:
        {sender_domain}
        """
        )
    st.subheader("Spam Indicators")

    if spam_result["reasons"]:
        for reason in spam_result["reasons"]:
            st.write(f"• {reason}")
    else:
        st.write("No spam indicators found.")

    st.subheader("Recommendations")

    for rec in recommendations:
        st.write(f"• {rec}")


    report_path = Path(__file__).resolve().parent / "incident_report.pdf"

    if st.button(
    "Generate PDF Report"
        ):
        generate_pdf_report(
            str(report_path),
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
        )

        st.success(
            "PDF Report Generated"
        )

        with open(
                report_path,
                "rb"
            ) as pdf_file:

            st.download_button(


            label="Download Report",

            data=pdf_file,

            file_name="EmailShield_Report.pdf",

            mime="application/pdf"
    )    

    # =========================
    # HEADER INFORMATION
    # =========================

    st.subheader(
        "Header Information"
    )

    st.write(
        "From:",
        sender
    )

    st.write(
        "To:",
        to_addr
    )

    st.write(
        "Subject:",
        subject
    )

    st.write(
        "Date:",
        date_value
    )

    st.write(
        "Reply-To:",
        reply_to
    )

    st.write(
        "Return-Path:",
        return_path
    )

    # =========================
    # AUTHENTICATION
    # =========================

    st.subheader(
        "Authentication"
    )

    st.write(
        "SPF:",
        auth["spf"]
    )

    st.write(
        "DKIM:",
        auth["dkim"]
    )

    st.write(
        "DMARC:",
        auth["dmarc"]
    )

    # =========================
    # DOMAIN INFO
    # =========================

    st.subheader(
        "Domain Information"
    )

    st.write(
        "Sender Domain:",
        sender_domain
    )

    if domain_info:

        st.subheader(
            "Domain Intelligence"
        )

        st.write(
            "Registrar:",
            domain_info["registrar"]
        )

        st.write(
            "Domain Age (Days):",
            domain_age
        )

        st.write(
            "Created:",
            domain_info["created"]
        )

        if domain_age is not None and domain_age < 30:

            st.error(
                "⚠ Newly Registered Domain"
            )

    # =========================
    # DOMAIN REPUTATION
    # =========================

    if domain_rep:

        st.subheader(
        "Domain Reputation"
    )

        if domain_rep["malicious"] == -1:

            st.warning(
            "VirusTotal Reputation Unavailable"
        )

        else:

            st.write(
            "Malicious:",
            domain_rep["malicious"]
        )
            

            st.write(
            "Suspicious:",
            domain_rep["suspicious"]
        )

            st.write(
            "Harmless:",
            domain_rep["harmless"]
        )

            if domain_rep["malicious"] > 0:


                st.error(
                "⚠ Domain flagged by VirusTotal"
            )

    # =========================
    # IP INTELLIGENCE
    # =========================

    if ips:

        st.subheader(
    "Sender IPs"
        )

        st.write(
            "All Extracted IPs:",
            ips
        )

        st.write(
            "Public IPs:",
            public_ips
        )

    if ip_info:

        st.subheader(
        "IP Intelligence"
    )

        if (
        ip_info["country"] == "Unknown"
        and
        ip_info["isp"] == "Unknown"
            ):

            

            st.warning(
            "IP Reputation Service Unavailable"
        )

        st.write(
            "IP Address:",
            public_ips[0]
        )

        st.write(
            "Country:",
        ip_info["country"]
        )

        st.write(
            "ISP:",
            ip_info["isp"]
        )

        st.write(
        "Usage Type:",
        ip_info["usage_type"]
        )

        st.write(
            "Abuse Score:",
        ip_info["abuse_score"]
        )

        

        

        if (

            ip_info["country"] == "Unknown"
            and
            ip_info["isp"] == "Unknown"
            ):


                st.warning(
            "IP Reputation Service Unavailable"
                )

        elif ip_info["abuse_score"] > 50:

                    st.error(
            "⚠ High Risk IP"
    )

        elif ip_info["abuse_score"] > 0:

            st.warning(
            "⚠ Suspicious IP"
        )

        else:

            st.success(
            "✅ Clean IP Reputation"
    )
    
    # =========================
# ATTACHMENT INTELLIGENCE
# =========================

    st.subheader(
        "Attachment Intelligence"
    )

    if attachments:

        dangerous_extensions = [
            
        ".exe",
        ".bat",
        ".cmd",
        ".js",
        ".vbs",
        ".scr",
        ".ps1",
        ".dll",
        ".zip",
        ".rar",
        ".7z",
        ".docm",
        ".xlsm",
        ".pptm"

        ]

        for attachment in attachments:


            filename = attachment["filename"].lower()


            st.write(
                "File Name:",
                attachment["filename"]
                    )

            st.write(
                "File Type (Declared):",
                attachment["content_type"]
            )

            st.write(
                "File Type (Detected from content):",
                attachment.get("detected_file_type", "UNKNOWN")
            )

            st.write(
                "File Size:",
                f"{attachment['size']} bytes"
            )

            st.write(
                "SHA256:",
                attachment["sha256"]
            )

            if any(
                filename.endswith(ext)
                for ext in dangerous_extensions
            ):

                st.error(
                    f"⚠ Potentially Dangerous Attachment: {filename}"
                )

            if attachment.get("extension_spoofed"):

                st.error(
                    f"🚨 Extension Spoofing: file claims to be "
                    f"'{filename.rsplit('.', 1)[-1]}' but its content is "
                    f"actually {attachment.get('detected_file_type')}"
                )

            if attachment.get("double_extension"):

                st.error(
                    "🚨 Double Extension Trick Detected "
                    "(e.g. invoice.pdf.exe)"
                )

            if attachment.get("bidi_override"):

                st.error(
                    "🚨 Unicode Filename Spoofing Detected "
                    "(hidden right-to-left override character)"
                )

            if attachment.get("script_indicators"):

                st.error(
                    "🚨 Suspicious Script Content Detected: "
                    + ", ".join(attachment["script_indicators"])
                )

            st.divider()

    else:

        st.write(
            "No Attachments Found"
        )

    # =========================
    # ROUTING ANALYSIS
    # =========================

    st.subheader(
        "🛣 Routing Analysis"
    )

    if origin_ip:

        st.success(
            f"Originating IP: {origin_ip}"
        )

    else:

        st.warning(
            "Unable to determine originating IP."
        )

    if routing_data:

        st.write(
            f"Total Hops: {len(routing_data)}"
        )

        for route in routing_data:

            st.markdown(
                f"### Hop {route['hop']}"
            )

            if route["ips"]:

                st.write(
                    "IPs:",
                    ", ".join(
                        route["ips"]
                    )
                )

            else:

                st.write(
                    "IPs: None Found"
                )

            with st.expander(
                f"View Header - Hop {route['hop']}"
            ):

                st.code(
                    route["header"]
                )

            st.divider()

    else:

        st.warning(
            "No routing information found."
        )
    
    # =========================
    # IOC EXTRACTION
    # =========================

    st.subheader(
        "IOC Extraction"
    )

    st.write(
        "Domains:",
        iocs["domains"]
    )

    st.write(
        "IPs:",
        iocs["ips"]
    )

    st.write(
        "URLs:",
        iocs["urls"]
    )

    st.write(
        "Email Addresses:",
        iocs["emails"]
    )

    # =========================
    # SAVE TO DATABASE
    # =========================

    save_email(
        sender,
        subject,
        auth["spf"],
        auth["dkim"],
        auth["dmarc"],
        public_ip,
        sender_domain,
        domain_age,
        domain_info.get("registrar", "Unknown") if domain_info else "Unknown",
        ip_info.get("country", "Unknown") if ip_info else "Unknown",
        ip_info.get("isp", "Unknown") if ip_info else "Unknown",
        ip_info.get("abuse_score", 0) if ip_info else 0,
        score,
        spam_result["spam_score"],
        1 if spam_result["is_spam"] else 0,
        attack_type,
        "HIGH CONFIDENCE PHISHING"
        if score >= 70
        else "SUSPICIOUS EMAIL"
        if score >= 40
        else "LOW RISK"
    )
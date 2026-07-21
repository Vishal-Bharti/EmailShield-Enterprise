"""
Analysis pipeline for the EmailShield API.

Mirrors the exact sequence of analyzer calls in app.py, so results
match what the Streamlit app shows. This exists as a separate function
so the Outlook add-in (and any other future integration) can reuse the
same detection logic without depending on Streamlit.

NOTE: if you change the analysis flow in app.py, mirror the change
here too - the two aren't automatically kept in sync.
"""

import io
import re
import html
import base64

from analyzers.header_parser import parse_eml
from analyzers.auth_analyzer import analyze_authentication
from analyzers.ip_extractor import extract_ips
from analyzers.domain_extractor import extract_domain
from analyzers.ioc_extractor import extract_iocs
from analyzers.threat_score import calculate_risk_score
from analyzers.attack_classifier import classify_attack
from analyzers.recommendation_engine import get_recommendations
from analyzers.attachment_analyzer import analyze_attachments
from analyzers.ip_filter import get_public_ips
from analyzers.spam_detector import analyze_spam
from analyzers.routing_analyzer import analyze_routing, get_originating_ip

from intelligence.whois_lookup import get_domain_info, calculate_domain_age
from intelligence.ip_reputation import (
    check_ip_reputation,
    check_ip_reputation_virustotal
)
from intelligence.domain_reputation import check_domain_reputation


def _html_to_text(html_content):
    text = re.sub(r"(?is)<(script|style).*?>.*?(</\1>)", " ", html_content)
    text = re.sub(r"(?i)<(br|/p|/div|/tr|/li)\s*/?>", "\n", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text.strip()


def _extract_html_links(html_content):
    return re.findall(r'href=["\']([^"\']+)["\']', html_content, re.IGNORECASE)


def _extract_email_body(msg):

    plain_text_body = ""
    html_body = ""

    if msg.is_multipart():

        for part in msg.walk():

            content_type = part.get_content_type()

            if content_type == "text/plain":
                try:
                    plain_text_body += part.get_payload(decode=True).decode(errors="ignore")
                except Exception:
                    pass

            elif content_type == "text/html":
                try:
                    html_body += part.get_payload(decode=True).decode(errors="ignore")
                except Exception:
                    pass

    else:

        content_type = msg.get_content_type()

        try:
            payload = msg.get_payload(decode=True).decode(errors="ignore")

            if content_type == "text/html":
                html_body = payload
            else:
                plain_text_body = payload

        except Exception:
            pass

    if plain_text_body.strip():
        email_body = plain_text_body
    elif html_body.strip():
        email_body = _html_to_text(html_body)
    else:
        email_body = ""

    if html_body:
        html_links = _extract_html_links(html_body)
        if html_links:
            email_body += "\n" + "\n".join(html_links)

    return email_body


def analyze_eml_bytes(eml_bytes):
    """Run the full EmailShield pipeline against raw .eml bytes.

    Returns a plain, JSON-serializable dict - no email.message objects,
    no non-primitive types - so it can be sent straight back to the
    Outlook add-in (or any other client) as an HTTP response body.
    """

    headers, msg = parse_eml(io.BytesIO(eml_bytes))

    sender = headers.get("from", "Unknown")
    subject = headers.get("subject", "Unknown")
    to_addr = headers.get("to", "Unknown")
    reply_to = headers.get("reply_to", "Unknown")
    return_path = headers.get("return_path", "Unknown")
    date_value = headers.get("date", "Unknown")

    routing_data = analyze_routing(msg)
    origin_ip = get_originating_ip(routing_data)

    attachments = analyze_attachments(msg)

    email_body = _extract_email_body(msg)

    iocs = extract_iocs(email_body)

    auth = analyze_authentication(msg)

    ips = extract_ips(msg)
    public_ips = get_public_ips(ips)
    public_ip = public_ips[0] if public_ips else "Unknown"

    ip_info = None
    ip_rep_vt = None

    if public_ip != "Unknown":
        ip_info = check_ip_reputation(public_ip)
        ip_rep_vt = check_ip_reputation_virustotal(public_ip)

    sender_domain = extract_domain(sender) if sender and sender != "Unknown" else "Unknown"

    domain_info = None
    domain_rep = None
    domain_age = None

    if sender_domain and sender_domain != "Unknown":
        domain_info = get_domain_info(sender_domain)
        domain_rep = check_domain_reputation(sender_domain)

    if domain_info and domain_info.get("created"):
        domain_age = calculate_domain_age(domain_info["created"])

    score, reasons = calculate_risk_score(
        auth,
        domain_age,
        ip_info,
        domain_rep,
        attachments,
        routing_data,
        origin_ip,
        ip_rep_vt=ip_rep_vt
    )

    spam_result = analyze_spam(
        email_body,
        headers=headers,
        auth=auth,
        iocs=iocs,
        attachments=attachments,
    )

    attack_type, attack_evidence = classify_attack(
        auth,
        domain_age,
        iocs,
        score,
        attachments=attachments,
        domain_rep=domain_rep
    )

    recommendations = get_recommendations(score)

    if score >= 70:
        verdict = "HIGH CONFIDENCE PHISHING"
    elif score >= 40:
        verdict = "SUSPICIOUS EMAIL"
    else:
        verdict = "LOW RISK"

    # Attachment dicts already only contain JSON-safe values (strings,
    # ints, bools, lists of strings) from attachment_analyzer.py.

    return {
        "headers": {
            "from": sender,
            "to": to_addr,
            "subject": subject,
            "date": date_value,
            "reply_to": reply_to,
            "return_path": return_path,
        },
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "attack_type": attack_type,
        "attack_evidence": attack_evidence,
        "recommendations": recommendations,
        "spam": spam_result,
        "auth": auth,
        "sender_domain": sender_domain,
        "domain_age_days": domain_age,
        "domain_info": domain_info,
        "domain_reputation": domain_rep,
        "origin_ip": origin_ip,
        "public_ip": public_ip,
        "ip_reputation_abuseipdb": ip_info,
        "ip_reputation_virustotal": ip_rep_vt,
        "iocs": iocs,
        "attachments": attachments,
        "routing_hops": len(routing_data) if routing_data else 0,
        "routing_data": routing_data,
    }


def analyze_eml_base64(eml_base64):
    """Convenience wrapper - the Outlook add-in gets the current email
    as base64 via Office.js's getEmlAsync, so this avoids making every
    caller decode it themselves."""

    eml_bytes = base64.b64decode(eml_base64)
    return analyze_eml_bytes(eml_bytes)

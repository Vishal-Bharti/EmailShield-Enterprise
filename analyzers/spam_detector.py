import re
from email.utils import parseaddr


SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify",
    "click here",
    "password",
    "account",
    "bank",
    "invoice",
    "free",
    "winner",
    "prize",
    "limited time",
    "suspended",
    "update now",
    "confirm",
    "secure",
    "login",
    "payment",
]


def analyze_spam(email_body, headers=None, auth=None, iocs=None, attachments=None):
    text = (email_body or "").lower()
    subject = ""
    from_domain = ""
    reply_to_domain = ""
    return_path_domain = ""

    if headers:
        subject = str(headers.get("subject", "") or "").lower()

        from_addr = str(headers.get("from", "") or "")
        reply_to_addr = str(headers.get("reply_to", "") or "")
        return_path_addr = str(headers.get("return_path", "") or "")

        _, from_email = parseaddr(from_addr)
        _, reply_to_email = parseaddr(reply_to_addr)
        _, return_path_email = parseaddr(return_path_addr)

        from_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""
        reply_to_domain = reply_to_email.split("@")[-1].lower() if "@" in reply_to_email else ""
        return_path_domain = return_path_email.split("@")[-1].lower() if "@" in return_path_email else ""

    spam_score = 0
    reasons = []

    combined_text = f"{text} {subject}"

    matched_keywords = [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in combined_text]
    if matched_keywords:
        spam_score += min(30, 10 + len(matched_keywords) * 5)
        reasons.append("Contains common phishing language")

    if headers:
        if from_domain and reply_to_domain and reply_to_domain != from_domain:
            spam_score += 15
            reasons.append("Reply-To domain differs from sender domain")

        if return_path_domain and from_domain and return_path_domain != from_domain:
            spam_score += 10
            reasons.append("Return-Path domain differs from sender domain")

        if subject and ("urgent" in subject or "verify" in subject or "account" in subject):
            spam_score += 5
            reasons.append("Suspicious subject line")

        spam_status = str(headers.get("x-spam-status", "") or "").lower()
        if "yes" in spam_status or "spam" in spam_status or "score=" in spam_status:
            spam_score += 20
            reasons.append("X-Spam-Status indicates spam")

        spam_flag = str(headers.get("x-spam-flag", "") or "").lower()
        if spam_flag == "yes" or spam_flag == "true":
            spam_score += 20
            reasons.append("X-Spam-Flag is set")

        x_mailer = str(headers.get("x-mailer", "") or "").lower()
        # NOTE: matching a generic word like "mail" here would flag most
        # legitimate clients (e.g. "Apple Mail", "Outlook Mail"). Only
        # match known bulk-mailer / scripting signatures instead.
        suspicious_mailer_tokens = ["phpmailer", "swaks", "python-smtplib", "sendblaster", "mass mailer"]
        if x_mailer and any(token in x_mailer for token in suspicious_mailer_tokens):
            spam_score += 3
            reasons.append("Unusual X-Mailer header")

        originating_ip = str(headers.get("x-originating-ip", "") or "")
        if originating_ip:
            spam_score += 5
            reasons.append("Contains X-Originating-IP header")

    if iocs and iocs.get("urls"):
        spam_score += min(20, 10 + len(iocs["urls"]) * 5)
        reasons.append("Contains external URLs")

    if iocs and iocs.get("ips"):
        spam_score += 10
        reasons.append("Contains suspicious IP indicators")

    if auth:
        if auth.get("spf") == "FAIL":
            spam_score += 10
            reasons.append("SPF authentication failed")
        if auth.get("dkim") == "FAIL":
            spam_score += 10
            reasons.append("DKIM authentication failed")
        if auth.get("dmarc") == "FAIL":
            spam_score += 10
            reasons.append("DMARC authentication failed")

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
            ".pptm",
        ]

        if any(
            any(filename.lower().endswith(ext) for ext in dangerous_extensions)
            for filename in [attachment.get("filename", "") for attachment in attachments]
        ):
            spam_score += 15
            reasons.append("Contains suspicious attachments")

    if not combined_text.strip():
        spam_score += 5
        reasons.append("No readable message content")

    spam_score = min(100, spam_score)
    is_spam = spam_score >= 60

    return {
        "spam_score": spam_score,
        "is_spam": is_spam,
        "reasons": reasons,
        "verdict": "Likely Spam" if is_spam else "Likely Not Spam",
    }

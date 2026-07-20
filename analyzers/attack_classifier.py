def classify_attack(
    auth,
    domain_age,
    iocs,
    score,
    attachments=None,
    domain_rep=None
):
    """Classify the likely attack type.

    Each candidate below carries a priority (higher = more specific /
    more severe) and only "wins" if its trigger conditions are met. The
    highest-priority match is returned, instead of the old behaviour
    of overwriting attack_type sequentially - which meant a later, weaker
    check could silently discard an earlier, more specific finding.
    """

    attachments = attachments or []

    candidates = []  # list of (priority, attack_type, evidence_list)

    # -------------------------
    # Malicious Attachment
    # -------------------------
    # Uses the signature-based detection from attachment_analyzer.py -
    # a real content/extension mismatch, disguised double extension, or
    # hidden script payload is strong, direct evidence on its own,
    # independent of URLs or auth results.

    attachment_evidence = []

    for attachment in attachments:

        filename = attachment.get("filename", "unknown")

        if attachment.get("extension_spoofed"):
            attachment_evidence.append(
                f"'{filename}' content does not match its extension "
                f"(detected: {attachment.get('detected_file_type')})"
            )

        if attachment.get("double_extension"):
            attachment_evidence.append(
                f"'{filename}' uses a disguised double extension"
            )

        if attachment.get("bidi_override"):
            attachment_evidence.append(
                f"'{filename}' uses Unicode filename spoofing"
            )

        if attachment.get("script_indicators"):
            attachment_evidence.append(
                f"'{filename}' contains suspicious script content "
                f"({', '.join(attachment['script_indicators'])})"
            )

    if attachment_evidence:
        candidates.append((90, "Malware Delivery (Malicious Attachment)", attachment_evidence))

    # -------------------------
    # Business Email Compromise (BEC)
    # -------------------------
    # Both SPF and DKIM failing on a sender claiming to be a known
    # party is the classic signature of a spoofed-sender BEC attempt.

    if auth["spf"] == "FAIL" and auth["dkim"] == "FAIL":
        candidates.append((
            80,
            "Business Email Compromise (BEC)",
            ["SPF and DKIM both failed - sender identity could not be verified"]
        ))

    # -------------------------
    # Malware Delivery via link
    # -------------------------

    if len(iocs["ips"]) > 0 and score >= 70:
        candidates.append((
            75,
            "Malware Delivery (Malicious Link)",
            ["Email contains raw IP-based links and a high overall risk score"]
        ))

    # -------------------------
    # Credential Harvesting (Phishing)
    # -------------------------
    # A bare URL is not evidence of phishing on its own - nearly every
    # legitimate email contains one (signatures, unsubscribe links,
    # etc). Require at least one corroborating signal alongside the URL
    # before calling it credential harvesting.

    if len(iocs["urls"]) > 0:

        phishing_evidence = []

        if domain_rep and domain_rep.get("malicious", 0) > 0:
            phishing_evidence.append("Linked domain flagged malicious by VirusTotal")

        if domain_age is not None and domain_age < 30:
            phishing_evidence.append(f"Linked/sender domain is newly registered ({domain_age} days)")

        if auth["spf"] == "FAIL" or auth["dkim"] == "FAIL":
            phishing_evidence.append("Sender authentication failed alongside embedded links")

        if phishing_evidence:
            phishing_evidence.insert(0, "Email contains URLs")
            candidates.append((70, "Credential Harvesting (Phishing)", phishing_evidence))

    # -------------------------
    # Pick the highest-priority match
    # -------------------------

    if candidates:
        candidates.sort(key=lambda c: c[0], reverse=True)
        _, attack_type, evidence = candidates[0]
    elif score >= 40:
        # Something scored it as risky but no specific attack pattern
        # matched - don't call it "Legitimate", that's misleading.
        attack_type = "Suspicious - Uncategorized"
        evidence = ["Risk score elevated but no specific attack pattern matched"]
    else:
        attack_type = "Legitimate"
        evidence = []

    # Domain age is useful supporting context regardless of which
    # category won, as long as it isn't already included.
    if (
        domain_age is not None
        and domain_age < 30
        and not any("newly registered" in e.lower() for e in evidence)
    ):
        evidence.append(f"Domain age only {domain_age} days")

    return attack_type, evidence
def calculate_risk_score(
    auth,
    domain_age,
    ip_info,
    domain_rep,
    attachments,
    routing_data,
    origin_ip
):

    score = 0

    reasons = []

    # =========================
    # SPF
    # =========================

    if auth["spf"] in ["FAIL", "SOFTFAIL"]:

        score += 20

        reasons.append(
            "SPF Failed"
        )

    elif auth["spf"] == "Unknown":

        score += 5

        reasons.append(
            "SPF Status Unknown"
        )

    # =========================
    # DKIM
    # =========================

    if auth["dkim"] == "FAIL":

        score += 20

        reasons.append(
            "DKIM Failed"
        )

    elif auth["dkim"] == "Unknown":

        score += 5

        reasons.append(
            "DKIM Status Unknown"
        )

    # =========================
    # DMARC
    # =========================

    if auth["dmarc"] == "FAIL":

        score += 20

        reasons.append(
            "DMARC Failed"
        )

    elif auth["dmarc"] == "Unknown":

        score += 5

        reasons.append(
            "DMARC Status Unknown"
        )

    # =========================
    # DOMAIN AGE
    # =========================

    if domain_age is not None:

        if domain_age < 30:

            score += 15

            reasons.append(
                f"New Domain ({domain_age} days old)"
            )

    # =========================
    # IP REPUTATION
    # =========================

    if ip_info:

        if ip_info["abuse_score"] > 50:

            score += 20

            reasons.append(
                "Malicious IP Reputation"
            )

        elif ip_info["abuse_score"] > 0:

            score += 10

            reasons.append(
                "Suspicious IP Reputation"
            )

    # =========================
    # DOMAIN REPUTATION
    # =========================

    if domain_rep:

        if domain_rep["malicious"] > 0:

            score += 20

            reasons.append(
                "VirusTotal Flagged Domain"
            )

        elif domain_rep["suspicious"] > 0:

            score += 10

            reasons.append(
                "VirusTotal Suspicious Domain"
            )

    # =========================
    # ROUTING ANALYSIS
    # =========================

    if len(routing_data) == 0:

        score += 10

        reasons.append(
            "No Routing Information Found"
        )

    if not origin_ip:

        score += 15

        reasons.append(
            "Originating IP Could Not Be Determined"
        )

    if len(routing_data) > 10:

        score += 10

        reasons.append(
            f"Excessive Relay Hops ({len(routing_data)})"
        )

    # =========================
    # ATTACHMENT ANALYSIS
    # =========================

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

        filename = (
            attachment["filename"]
            .lower()
        )

        if any(
            filename.endswith(ext)
            for ext in dangerous_extensions
        ):

            score += 25

            reasons.append(
                f"Dangerous Attachment ({filename})"
            )

    # =========================
    # SCORE CAP
    # =========================

    if score > 100:

        score = 100

    print("Final Score:", score)
    print("Reasons:", reasons)

    return score, reasons
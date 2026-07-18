def analyze_authentication(msg):

    auth_results = str(
        msg.get(
            "Authentication-Results",
            ""
        )
    ).lower()

    # Commonly seen values include: pass, fail, softfail, neutral, none
    # We map only what the risk scorer understands; everything else stays Unknown.
    result = {
        "spf": "Unknown",
        "dkim": "Unknown",
        "dmarc": "Unknown"
    }

    # SPF
    if "spf=pass" in auth_results:
        result["spf"] = "PASS"
    elif "spf=softfail" in auth_results:
        # Risk scorer counts SOFTFAIL as suspicious
        result["spf"] = "SOFTFAIL"
    elif "spf=fail" in auth_results:
        result["spf"] = "FAIL"

    # DKIM
    if "dkim=pass" in auth_results:
        result["dkim"] = "PASS"
    elif "dkim=fail" in auth_results:
        result["dkim"] = "FAIL"

    # DMARC
    if "dmarc=pass" in auth_results:
        result["dmarc"] = "PASS"
    elif "dmarc=fail" in auth_results:
        result["dmarc"] = "FAIL"

    return result

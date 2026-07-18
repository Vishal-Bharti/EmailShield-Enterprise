def classify_attack(
    auth,
    domain_age,
    iocs,
    score
):

    attack_type = "Legitimate"

    evidence = []

    # Credential Harvesting

    if len(iocs["urls"]) > 0:

        attack_type = "Credential Harvesting"

        evidence.append(
            "Email contains URLs"
        )

    # Malware Delivery

    if len(iocs["ips"]) > 0 and score >= 70:

        attack_type = "Malware Delivery"

        evidence.append(
            "Suspicious IP detected"
        )

    # Business Email Compromise

    if (
        auth["spf"] == "FAIL"
        and
        auth["dkim"] == "FAIL"
    ):

        attack_type = "Business Email Compromise (BEC)"

        evidence.append(
            "SPF and DKIM failed"
        )

    # Newly Registered Domain

    if (
        domain_age is not None
        and
        domain_age < 30
    ):

        evidence.append(
            f"Domain age only {domain_age} days"
        )

    return attack_type, evidence
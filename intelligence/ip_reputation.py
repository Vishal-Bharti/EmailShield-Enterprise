import requests
import time

from config import get_secret

API_KEY = get_secret("ABUSEIPDB_API_KEY")
VT_API_KEY = get_secret("VIRUSTOTAL_API_KEY")


def check_ip_reputation(ip):

    if not API_KEY:

        print("AbuseIPDB API key not configured, skipping lookup.")

        return {
            "abuse_score": 0,
            "country": "Unknown",
            "isp": "Unknown",
            "usage_type": "Unknown"
        }

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    max_attempts = 3

    for attempt in range(max_attempts):

        try:

            print(
                f"Attempt {attempt + 1} of {max_attempts}"
            )

            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=5
            )

            if response.status_code == 200:

                data = response.json()["data"]

                return {
                    "abuse_score": data.get(
                        "abuseConfidenceScore",
                        0
                    ),
                    "country": data.get(
                        "countryCode",
                        "Unknown"
                    ),
                    "isp": data.get(
                        "isp",
                        "Unknown"
                    ),
                    "usage_type": data.get(
                        "usageType",
                        "Unknown"
                    )
                }

            print(
                f"Status Code: {response.status_code}"
            )

            # 4xx errors (bad key, rate limit, invalid IP) won't be
            # fixed by retrying - stop wasting API calls on them.
            if 400 <= response.status_code < 500:
                break

        except Exception as e:

            print(
                f"Attempt {attempt + 1} Failed:",
                e
            )

        # Only wait before a retry that will actually happen.
        if attempt < max_attempts - 1:
            time.sleep(3)

    return {
        "abuse_score": 0,
        "country": "Unknown",
        "isp": "Unknown",
        "usage_type": "Unknown"
    }


def check_ip_reputation_virustotal(ip):
    """Second IP reputation source - VirusTotal's multi-engine votes.

    Complements AbuseIPDB (community abuse reports) with independent
    malicious/suspicious/harmless verdicts from many AV/security
    engines. Reuses the same VirusTotal key already used for domain
    reputation, so no extra signup is needed.
    """

    if not VT_API_KEY:

        print("VirusTotal API key not configured, skipping IP lookup.")

        return {
            "malicious": -1,
            "suspicious": -1,
            "harmless": -1
        }

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    max_attempts = 3

    for attempt in range(max_attempts):

        try:

            print(
                f"VT IP Attempt {attempt + 1} of {max_attempts}"
            )

            response = requests.get(
                url,
                headers=headers,
                timeout=5
            )

            if response.status_code == 200:

                data = response.json()

                stats = data["data"]["attributes"][
                    "last_analysis_stats"
                ]

                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0)
                }

            print(
                f"VT IP Status Code: {response.status_code}"
            )

            # 4xx errors (bad key, unknown IP, rate limit) won't be
            # fixed by retrying.
            if 400 <= response.status_code < 500:
                break

        except Exception as e:

            print(
                f"VT IP Attempt {attempt + 1} Failed:",
                e
            )

        if attempt < max_attempts - 1:
            time.sleep(2 ** attempt)

    return {
        "malicious": -1,
        "suspicious": -1,
        "harmless": -1
    }
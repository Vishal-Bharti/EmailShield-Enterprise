import requests
import time

from config import get_secret

API_KEY = get_secret("ABUSEIPDB_API_KEY")


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

    for attempt in range(2):

        try:

            print(
                f"Attempt {attempt + 1}"
            )

            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=10
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

        except Exception as e:

            print(
                f"Attempt {attempt + 1} Failed:",
                e
            )

        time.sleep(3)

    return {
        "abuse_score": 0,
        "country": "Unknown",
        "isp": "Unknown",
        "usage_type": "Unknown"
    }
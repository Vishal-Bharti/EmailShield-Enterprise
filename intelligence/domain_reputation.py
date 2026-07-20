import requests
import time

from config import get_secret

API_KEY = get_secret("VIRUSTOTAL_API_KEY")


def check_domain_reputation(domain):

    if not API_KEY:

        print("VirusTotal API key not configured, skipping lookup.")

        return {
            "malicious": -1,
            "suspicious": -1,
            "harmless": -1
        }

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    headers = {
        "x-apikey": API_KEY
    }

    for attempt in range(2):

        try:

            print(
                f"VT Attempt {attempt + 1}"
            )

            response = requests.get(
                url,
                headers=headers,
                timeout=10
            )

            print(
                "Status:",
                response.status_code
            )

            if response.status_code != 200:

                print(
                    response.text
                )

                time.sleep(
                    2 ** attempt
                )

                continue

            data = response.json()

            stats = data["data"]["attributes"][
                "last_analysis_stats"
            ]

            return {
                "malicious": stats.get(
                    "malicious",
                    0
                ),
                "suspicious": stats.get(
                    "suspicious",
                    0
                ),
                "harmless": stats.get(
                    "harmless",
                    0
                )
            }

        except Exception as e:

            print(
                f"VT Attempt {attempt + 1} Failed:",
                e
            )

            time.sleep(
                2 ** attempt
            )

    return {
        "malicious": -1,
        "suspicious": -1,
        "harmless": -1
    }
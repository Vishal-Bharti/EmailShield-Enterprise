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

    max_attempts = 3

    for attempt in range(max_attempts):

        try:

            print(
                f"VT Attempt {attempt + 1} of {max_attempts}"
            )

            response = requests.get(
                url,
                headers=headers,
                timeout=5
            )

            print(
                "Status:",
                response.status_code
            )

            if response.status_code != 200:

                print(
                    response.text
                )

                # 4xx errors (bad key, unknown domain, rate limit) won't
                # be fixed by retrying - stop wasting API calls on them.
                if 400 <= response.status_code < 500:
                    break

                if attempt < max_attempts - 1:
                    time.sleep(2 ** attempt)

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

            if attempt < max_attempts - 1:
                time.sleep(2 ** attempt)

    return {
        "malicious": -1,
        "suspicious": -1,
        "harmless": -1
    }
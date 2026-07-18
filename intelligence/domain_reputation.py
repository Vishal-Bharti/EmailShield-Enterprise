import requests
import urllib3
import time

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

API_KEY = "8ce682be18d8c79ccb57a43e27e75e1a5504f4ce0f85b13be2124b3677983a0f"


def check_domain_reputation(domain):

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    headers = {
        "x-apikey": API_KEY
    }

    for attempt in range(1):

        try:

            print(
                f"VT Attempt {attempt + 1}"
            )

            response = requests.get(
                url,
                headers=headers,
                timeout=5,
                verify=False
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
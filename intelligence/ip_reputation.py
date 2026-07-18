import requests
import time
import urllib3

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

API_KEY = "a5f76132498868cd87c9c1cb10665c5a7e5f3819b506039031da905b30a3b3874fa5e701bbfd7b72"


def check_ip_reputation(ip):

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    for attempt in range(1):

        try:

            print(
                f"Attempt {attempt + 1}"
            )

            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=5,
                verify=False
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
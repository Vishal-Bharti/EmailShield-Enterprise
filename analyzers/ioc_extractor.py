import re
from urllib.parse import urlparse


def extract_iocs(email_content):

    urls = re.findall(
        r'https?://[^\s<>"\']+',
        email_content
    )

    ips = re.findall(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        email_content
    )

    emails = re.findall(
        r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
        email_content
    )

    domains = []

    for url in urls:

        try:

            domain = urlparse(
                url
            ).netloc

            if domain:
                domains.append(
                    domain
                )

        except:
            pass

    return {
        "urls": list(set(urls)),
        "ips": list(set(ips)),
        "domains": list(set(domains)),
        "emails": list(set(emails))
    }
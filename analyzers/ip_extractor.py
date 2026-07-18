import re


def extract_ips(msg):

    received_headers = msg.get_all(
        "Received",
        []
    )

    ips = []

    pattern = r"(?:\d{1,3}\.){3}\d{1,3}"

    for header in received_headers:

        matches = re.findall(
            pattern,
            header
        )

        ips.extend(matches)

    return list(set(ips))
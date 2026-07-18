import re
import ipaddress


def get_originating_ip(
    routing_data
):

    for route in reversed(
        routing_data
    ):

        for ip in route["ips"]:

            try:

                addr = ipaddress.ip_address(
                    ip
                )

                if (
                    not addr.is_private
                    and
                    not addr.is_loopback
                ):

                    return ip

            except:

                pass

    return None

def analyze_routing(msg):

    received_headers = msg.get_all(
        "Received",
        []
    )

    routing_data = []

    for index, header in enumerate(
        received_headers,
        start=1
    ):

        ips = re.findall(
            r"(?:\d{1,3}\.){3}\d{1,3}",
            header
        )

        routing_data.append(
            {
                "hop": index,
                "header": header,
                "ips": ips
            }
        )

    return routing_data

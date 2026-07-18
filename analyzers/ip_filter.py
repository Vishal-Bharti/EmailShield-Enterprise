import ipaddress

def get_public_ips(ips):

    public_ips = []

    for ip in ips:

        try:

            if not ipaddress.ip_address(ip).is_private:
                public_ips.append(ip)

        except:
            pass

    return public_ips



import whois

from datetime import datetime, timezone


def get_domain_info(domain):

    try:

        data = whois.whois(domain)

        return {
            "registrar": data.registrar,
            "created": data.creation_date,
            "expires": data.expiration_date
        }

    except Exception as e:

        print("WHOIS Error:", e)

        return None


def calculate_domain_age(created):

    if not created:
        return None

    if isinstance(created, list):
        created = created[0]

    try:

        # Convert both dates to naive datetimes
        now = datetime.now()

        if hasattr(created, "tzinfo") and created.tzinfo is not None:
            created = created.replace(tzinfo=None)

        return (now - created).days

    except Exception as e:

        print("Domain Age Error:", e)
        return None
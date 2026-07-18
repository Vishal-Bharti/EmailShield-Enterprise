from email.utils import parseaddr


def extract_domain(email_address):

    if not email_address:
        return None

    _, email = parseaddr(email_address)

    if "@" in email:
        return email.split("@")[1].lower()

    return None
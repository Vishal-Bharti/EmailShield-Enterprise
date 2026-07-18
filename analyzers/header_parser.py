from email import policy
from email.parser import BytesParser


def parse_eml(file):

    msg = BytesParser(
        policy=policy.default
    ).parse(file)

    headers = {
        "from": msg.get("From"),
        "to": msg.get("To"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "reply_to": msg.get("Reply-To"),
        "return_path": msg.get("Return-Path"),
        "message_id": msg.get("Message-ID")
    }

    return headers, msg
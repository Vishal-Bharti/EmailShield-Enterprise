import hashlib


def analyze_attachments(msg):

    attachments = []

    for part in msg.walk():

        filename = part.get_filename()

        if filename:

            try:

                data = part.get_payload(
                    decode=True
                )

                size = len(data)

                sha256 = hashlib.sha256(
                    data
                ).hexdigest()

                attachments.append(
                    {
                        "filename": filename,
                        "size": size,
                        "sha256": sha256,
                        "content_type": part.get_content_type()
                    }
                )

            except Exception as e:

                print(
                    "Attachment Error:",
                    e
                )

    return attachments
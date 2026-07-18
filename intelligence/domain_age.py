from datetime import datetime, timezone


def calculate_domain_age(created):

    if not created:
        return None

    if isinstance(created, list):
        created = created[0]

    try:

        if created.tzinfo is None:

            created = created.replace(
                tzinfo=timezone.utc
            )

        return (
            datetime.now(timezone.utc) - created
        ).days

    except Exception as e:

        print(
            "Domain Age Error:",
            e
        )

        return None
import sqlite3
from datetime import datetime


def create_database():

    conn = sqlite3.connect(
        "emailshield.db"
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS emails (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            sender TEXT,
            subject TEXT,

            spf TEXT,
            dkim TEXT,
            dmarc TEXT,

            sender_ip TEXT,

            sender_domain TEXT,
            domain_age INTEGER,
            registrar TEXT,

            country TEXT,
            isp TEXT,
            abuse_score INTEGER,

            risk_score INTEGER,
            attack_type TEXT,
            verdict TEXT,

            report_date TEXT
        )
        """
    )

    existing_columns = {
        row[1]
        for row in cursor.execute(
            "PRAGMA table_info(emails)"
        )
    }

    for column_name, column_def in [
        ("spam_score", "INTEGER"),
        ("is_spam", "INTEGER"),
    ]:
        if column_name not in existing_columns:
            cursor.execute(
                f"ALTER TABLE emails ADD COLUMN {column_name} {column_def}"
            )

    conn.commit()
    conn.close()


def save_email(
    sender,
    subject,
    spf,
    dkim,
    dmarc,
    sender_ip,
    sender_domain,
    domain_age,
    registrar,
    country,
    isp,
    abuse_score,
    risk_score,
    spam_score,
    is_spam,
    attack_type,
    verdict
):

    conn = sqlite3.connect(
        "emailshield.db"
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO emails
        (
            sender,
            subject,
            spf,
            dkim,
            dmarc,
            sender_ip,
            sender_domain,
            domain_age,
            registrar,
            country,
            isp,
            abuse_score,
            risk_score,
            spam_score,
            is_spam,
            attack_type,
            verdict,
            report_date
        )
        VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sender,
            subject,
            spf,
            dkim,
            dmarc,
            sender_ip,
            sender_domain,
            domain_age,
            registrar,
            country,
            isp,
            abuse_score,
            risk_score,
            spam_score,
            is_spam,
            attack_type,
            verdict,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )

    conn.commit()
    conn.close()


def get_all_emails():

    conn = sqlite3.connect(
        "emailshield.db"
    )

    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM emails ORDER BY id DESC"
    )

    data = cursor.fetchall()

    conn.close()

    return data


def search_emails(keyword):

    conn = sqlite3.connect(
        "emailshield.db"
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM emails
        WHERE
            sender LIKE ?
            OR subject LIKE ?
            OR sender_domain LIKE ?
            OR sender_ip LIKE ?
            OR attack_type LIKE ?
        """,
        (
            f"%{keyword}%",
            f"%{keyword}%",
            f"%{keyword}%",
            f"%{keyword}%",
            f"%{keyword}%"
        )
    )

    results = cursor.fetchall()

    conn.close()

    return results
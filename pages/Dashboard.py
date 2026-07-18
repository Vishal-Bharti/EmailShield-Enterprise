import streamlit as st
import sqlite3
import pandas as pd
import altair as alt

st.set_page_config(
    page_title="EmailShield Dashboard",
    layout="wide"
)

st.title("📊 EmailShield Enterprise Dashboard")

# =====================================
# DATABASE
# =====================================

conn = sqlite3.connect(
    "emailshield.db"
)

df = pd.read_sql_query(
    "SELECT * FROM emails",
    conn
)

conn.close()

# =====================================
# HANDLE EMPTY DATABASE
# =====================================

if df.empty:

    st.warning(
        "No email records found in database."
    )

    st.stop()

# =====================================
# KPI METRICS
# =====================================

total_emails = len(df)

phishing_count = len(
    df[
        df["verdict"] ==
        "HIGH CONFIDENCE PHISHING"
    ]
)

suspicious_count = len(
    df[
        df["verdict"] ==
        "SUSPICIOUS EMAIL"
    ]
)

high_risk = len(
    df[
        df["risk_score"] >= 70
    ]
)

avg_score = round(
    df["risk_score"].mean(),
    1
)

col1, col2, col3, col4, col5 = st.columns(5)

with col1:

    st.metric(
        "Emails",
        total_emails
    )

with col2:

    st.metric(
        "Phishing",
        phishing_count
    )

with col3:

    st.metric(
        "Suspicious",
        suspicious_count
    )

with col4:

    st.metric(
        "High Risk",
        high_risk
    )

with col5:

    st.metric(
        "Avg Score",
        avg_score
    )

# =====================================
# ATTACK TYPE DISTRIBUTION
# =====================================

st.divider()

col1, col2 = st.columns(2)

with col1:

    st.subheader(
        "Attack Type Distribution"
    )

    attack_counts = (
        df["attack_type"]
        .value_counts()
        .reset_index()
    )

    attack_counts.columns = [
        "Attack Type",
        "Count"
    ]

    attack_chart = alt.Chart(
        attack_counts
    ).mark_bar().encode(
        x="Count:Q",
        y=alt.Y(
            "Attack Type:N",
            sort="-x"
        ),
        tooltip=[
            "Attack Type",
            "Count"
        ]
    )

    st.altair_chart(
        attack_chart,
        use_container_width=True
    )

# =====================================
# VERDICT DISTRIBUTION
# =====================================

with col2:

    st.subheader(
        "Verdict Distribution"
    )

    verdict_counts = (
        df["verdict"]
        .value_counts()
        .reset_index()
    )

    verdict_counts.columns = [
        "Verdict",
        "Count"
    ]

    pie_chart = (
        alt.Chart(
            verdict_counts
        )
        .mark_arc()
        .encode(
            theta="Count:Q",
            color="Verdict:N",
            tooltip=[
                "Verdict",
                "Count"
            ]
        )
    )

    st.altair_chart(
        pie_chart,
        use_container_width=True
    )

# =====================================
# TOP DOMAINS
# =====================================

st.divider()

col1, col2 = st.columns(2)

with col1:

    st.subheader(
        "Top Sender Domains"
    )

    domains = (
        df["sender_domain"]
        .value_counts()
        .reset_index()
    )

    domains.columns = [
        "Domain",
        "Count"
    ]

    st.dataframe(
        domains.head(10),
        use_container_width=True
    )

# =====================================
# TOP IPS
# =====================================

with col2:

    st.subheader(
        "Top Sender IPs"
    )

    top_ips = (
        df["sender_ip"]
        .value_counts()
        .reset_index()
    )

    top_ips.columns = [
        "IP Address",
        "Count"
    ]

    st.dataframe(
        top_ips.head(10),
        use_container_width=True
    )

# =====================================
# RISK SCORE DISTRIBUTION
# =====================================

st.divider()

st.subheader(
    "Risk Score Distribution"
)

st.bar_chart(
    df["risk_score"]
)

# =====================================
# HIGH RISK EMAILS
# =====================================

st.divider()

st.subheader(
    "High Risk Investigations"
)

high_risk_df = df[
    df["risk_score"] >= 70
]

if len(high_risk_df) > 0:

    st.dataframe(
        high_risk_df[
            [
                "report_date",
                "sender",
                "subject",
                "attack_type",
                "risk_score",
                "verdict"
            ]
        ],
        use_container_width=True
    )

else:

    st.info(
        "No high-risk emails found."
    )

# =====================================
# RECENT EMAILS
# =====================================

st.divider()

st.subheader(
    "Recent Investigations"
)

recent = df.sort_values(
    by="id",
    ascending=False
)

st.dataframe(
    recent.head(20),
    use_container_width=True
)

# =====================================
# THREAT HUNTING
# =====================================

st.divider()

st.subheader(
    "Threat Hunting"
)

search = st.text_input(
    "Search Sender, Subject, Domain, IP or Attack Type"
)

if search:

    results = df[
        (
            df["sender"]
            .astype(str)
            .str.contains(
                search,
                case=False,
                na=False
            )
        )
        |
        (
            df["subject"]
            .astype(str)
            .str.contains(
                search,
                case=False,
                na=False
            )
        )
        |
        (
            df["sender_domain"]
            .astype(str)
            .str.contains(
                search,
                case=False,
                na=False
            )
        )
        |
        (
            df["sender_ip"]
            .astype(str)
            .str.contains(
                search,
                case=False,
                na=False
            )
        )
        |
        (
            df["attack_type"]
            .astype(str)
            .str.contains(
                search,
                case=False,
                na=False
            )
        )
    ]

    st.success(
        f"{len(results)} matching records found"
    )

    st.dataframe(
        results,
        use_container_width=True
    )
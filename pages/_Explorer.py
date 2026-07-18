import streamlit as st
import sqlite3
import pandas as pd

st.set_page_config(
    page_title="IOC Explorer",
    layout="wide"
)

st.title("🌐 IOC Explorer")

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
# EMPTY DATABASE CHECK
# =====================================

if df.empty:

    st.warning(
        "No IOC data available."
    )

    st.stop()

# =====================================
# SUMMARY METRICS
# =====================================

total_domains = (
    df["sender_domain"]
    .nunique()
)

total_ips = (
    df["sender_ip"]
    .nunique()
)

high_risk_ips = len(
    df[
        df["abuse_score"] > 50
    ]
)

high_risk_domains = len(
    df[
        df["risk_score"] >= 70
    ]
)

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Unique Domains",
    total_domains
)

col2.metric(
    "Unique IPs",
    total_ips
)

col3.metric(
    "High-Risk IPs",
    high_risk_ips
)

col4.metric(
    "High-Risk Domains",
    high_risk_domains
)

# =====================================
# SEARCH IOC
# =====================================

st.divider()

st.subheader(
    "IOC Search"
)

ioc_search = st.text_input(
    "Search Domain, IP, Sender or Subject"
)

if ioc_search:

    results = df[
        (
            df["sender_domain"]
            .astype(str)
            .str.contains(
                ioc_search,
                case=False,
                na=False
            )
        )
        |
        (
            df["sender_ip"]
            .astype(str)
            .str.contains(
                ioc_search,
                case=False,
                na=False
            )
        )
        |
        (
            df["sender"]
            .astype(str)
            .str.contains(
                ioc_search,
                case=False,
                na=False
            )
        )
        |
        (
            df["subject"]
            .astype(str)
            .str.contains(
                ioc_search,
                case=False,
                na=False
            )
        )
    ]

    st.success(
        f"{len(results)} IOC matches found"
    )

    st.dataframe(
        results,
        use_container_width=True
    )

# =====================================
# TOP DOMAINS
# =====================================

st.divider()

st.subheader(
    "Top Domains"
)

domain_df = (
    df["sender_domain"]
    .value_counts()
    .reset_index()
)

domain_df.columns = [
    "Domain",
    "Count"
]

st.dataframe(
    domain_df.head(20),
    use_container_width=True
)

# =====================================
# TOP SOURCE IPS
# =====================================

st.divider()

st.subheader(
    "Top Source IPs"
)

ip_df = (
    df["sender_ip"]
    .value_counts()
    .reset_index()
)

ip_df.columns = [
    "IP Address",
    "Count"
]

st.dataframe(
    ip_df.head(20),
    use_container_width=True
)

# =====================================
# HIGH RISK IOCs
# =====================================

st.divider()

st.subheader(
    "High-Risk IOCs"
)

high_risk = df[
    (
        df["risk_score"] >= 70
    )
    |
    (
        df["abuse_score"] > 50
    )
]

if len(high_risk) > 0:

    st.dataframe(
        high_risk[
            [
                "sender_domain",
                "sender_ip",
                "risk_score",
                "abuse_score",
                "attack_type",
                "verdict",
                "report_date"
            ]
        ],
        use_container_width=True
    )

else:

    st.info(
        "No high-risk IOCs found."
    )

# =====================================
# DOMAIN INVESTIGATION
# =====================================

st.divider()

st.subheader(
    "Domain Investigation"
)

selected_domain = st.selectbox(
    "Select Domain",
    sorted(
        df["sender_domain"]
        .dropna()
        .unique()
    )
)

domain_records = df[
    df["sender_domain"]
    == selected_domain
]

st.metric(
    "Occurrences",
    len(domain_records)
)

st.dataframe(
    domain_records[
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

# =====================================
# IP INVESTIGATION
# =====================================

st.divider()

st.subheader(
    "IP Investigation"
)

selected_ip = st.selectbox(
    "Select IP",
    sorted(
        df["sender_ip"]
        .dropna()
        .unique()
    )
)

ip_records = df[
    df["sender_ip"]
    == selected_ip
]

st.metric(
    "Occurrences",
    len(ip_records)
)

st.dataframe(
    ip_records[
        [
            "report_date",
            "sender",
            "subject",
            "attack_type",
            "risk_score",
            "abuse_score",
            "verdict"
        ]
    ],
    use_container_width=True
)

# =====================================
# LATEST IOC ACTIVITY
# =====================================

st.divider()

st.subheader(
    "Latest IOC Activity"
)

latest = df.sort_values(
    by="id",
    ascending=False
)

st.dataframe(
    latest.head(25),
    use_container_width=True
)
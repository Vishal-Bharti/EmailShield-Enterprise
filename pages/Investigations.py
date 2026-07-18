import streamlit as st
import sqlite3
import pandas as pd

st.set_page_config(
    page_title="Investigations",
    layout="wide"
)

st.title(
    "🔍 Investigation Queue"
)

# =====================================
# DATABASE
# =====================================

conn = sqlite3.connect(
    "emailshield.db"
)

df = pd.read_sql_query(
    """
    SELECT *
    FROM emails
    ORDER BY risk_score DESC
    """,
    conn
)

conn.close()

# =====================================
# EMPTY DATABASE CHECK
# =====================================

if df.empty:

    st.warning(
        "No investigations available."
    )

    st.stop()

# =====================================
# FILTERS
# =====================================

st.subheader(
    "Investigation Filters"
)

col1, col2, col3 = st.columns(3)

with col1:

    verdict_filter = st.selectbox(
        "Verdict",
        [
            "All",
            "HIGH CONFIDENCE PHISHING",
            "SUSPICIOUS EMAIL",
            "LOW RISK"
        ]
    )

with col2:

    attack_types = (
        df["attack_type"]
        .dropna()
        .unique()
        .tolist()
    )

    attack_filter = st.selectbox(
        "Attack Type",
        ["All"] + attack_types
    )

with col3:

    min_score = st.slider(
        "Minimum Risk Score",
        0,
        100,
        0
    )

# =====================================
# APPLY FILTERS
# =====================================

filtered_df = df.copy()

if verdict_filter != "All":

    filtered_df = filtered_df[
        filtered_df["verdict"]
        == verdict_filter
    ]

if attack_filter != "All":

    filtered_df = filtered_df[
        filtered_df["attack_type"]
        == attack_filter
    ]

filtered_df = filtered_df[
    filtered_df["risk_score"]
    >= min_score
]

# =====================================
# KPI METRICS
# =====================================

st.divider()

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.metric(
        "Cases",
        len(filtered_df)
    )

with col2:

    st.metric(
        "Highest Score",
        int(
            filtered_df[
                "risk_score"
            ].max()
        )
        if not filtered_df.empty
        else 0
    )

with col3:

    st.metric(
        "Average Score",
        round(
            filtered_df[
                "risk_score"
            ].mean(),
            1
        )
        if not filtered_df.empty
        else 0
    )

with col4:

    st.metric(
        "Phishing Cases",
        len(
            filtered_df[
                filtered_df["verdict"]
                ==
                "HIGH CONFIDENCE PHISHING"
            ]
        )
    )

# =====================================
# INVESTIGATION TABLE
# =====================================

st.divider()

st.subheader(
    "Investigation Queue"
)

display_df = filtered_df[
    [
        "report_date",
        "sender",
        "subject",
        "attack_type",
        "risk_score",
        "verdict"
    ]
]

st.dataframe(
    display_df,
    use_container_width=True
)

# =====================================
# CASE DETAILS
# =====================================

st.divider()

st.subheader(
    "Case Details"
)

selected_email = st.selectbox(
    "Select Investigation",
    filtered_df["subject"]
)

selected_case = filtered_df[
    filtered_df["subject"]
    == selected_email
].iloc[0]

st.write(
    "### Incident Information"
)

st.write(
    "📧 Sender:",
    selected_case["sender"]
)

st.write(
    "📝 Subject:",
    selected_case["subject"]
)

st.write(
    "🎯 Attack Type:",
    selected_case["attack_type"]
)

st.write(
    "⚠ Risk Score:",
    selected_case["risk_score"]
)

st.write(
    "🚨 Verdict:",
    selected_case["verdict"]
)

st.write(
    "📅 Date:",
    selected_case["report_date"]
)

st.divider()

st.write(
    "### Domain Intelligence"
)

st.write(
    "🌐 Domain:",
    selected_case["sender_domain"]
)

st.write(
    "📆 Domain Age:",
    selected_case["domain_age"]
)

st.write(
    "🏢 Registrar:",
    selected_case["registrar"]
)

st.divider()

st.write(
    "### IP Intelligence"
)

st.write(
    "🌍 Source IP:",
    selected_case["sender_ip"]
)

st.write(
    "🌎 Country:",
    selected_case["country"]
)

st.write(
    "🏛 ISP:",
    selected_case["isp"]
)

st.write(
    "🔥 Abuse Score:",
    selected_case["abuse_score"]
)

# =====================================
# HIGH RISK CASES
# =====================================

st.divider()

st.subheader(
    "Top High-Risk Cases"
)

high_risk = filtered_df[
    filtered_df["risk_score"] >= 70
]

if len(high_risk) > 0:

    st.dataframe(
        high_risk[
            [
                "report_date",
                "subject",
                "attack_type",
                "risk_score",
                "verdict"
            ]
        ],
        use_container_width=True
    )

else:

    st.success(
        "No high-risk investigations found."
    )
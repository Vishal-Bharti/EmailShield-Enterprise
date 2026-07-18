import streamlit as st

st.set_page_config(
    page_title="EmailShield Enterprise",
    layout="wide"
)

# =====================================
# LIQUID GLASS CSS
# =====================================

st.markdown("""
<style>

.stApp{
    background:
    radial-gradient(circle at top left,
    rgba(96,165,250,0.20),
    transparent 35%),

    radial-gradient(circle at bottom right,
    rgba(192,132,252,0.20),
    transparent 35%),

    #f6f8fc;
}

header{
    visibility:hidden;
}

#MainMenu{
    visibility:hidden;
}

footer{
    visibility:hidden;
}

/* Metric Cards */

[data-testid="stMetric"]{

    background:rgba(255,255,255,0.75);

    backdrop-filter:blur(20px);

    border-radius:24px;

    border:1px solid rgba(
        255,255,255,0.7
    );

    padding:20px;

    box-shadow:
    0 8px 25px rgba(
        0,0,0,0.08
    );
}

/* Tabs */

.stTabs [data-baseweb="tab"]{

    background:rgba(
        255,255,255,0.7
    );

    backdrop-filter:blur(12px);

    border-radius:16px;

    margin-right:10px;
}

.stTabs [aria-selected="true"]{

    background:white;

    box-shadow:
    0 4px 20px rgba(
        0,0,0,0.08
    );
}

/* Buttons */

.stButton button{

    border-radius:16px;

    border:none;

    color:white;

    font-weight:600;

    background:
    linear-gradient(
        135deg,
        #3b82f6,
        #6366f1
    );

    box-shadow:
    0 6px 20px rgba(
        59,130,246,0.30
    );
}

/* Upload Area */

[data-testid="stFileUploader"]{

    background:rgba(
        255,255,255,0.7
    );

    border-radius:20px;

    padding:15px;

    backdrop-filter:blur(15px);
}

</style>
""", unsafe_allow_html=True)

# =====================================
# HERO SECTION
# =====================================

st.markdown("""
<div style="
padding:35px;
border-radius:32px;
background:rgba(255,255,255,0.75);
backdrop-filter:blur(20px);
-webkit-backdrop-filter:blur(20px);
box-shadow:0 10px 40px rgba(0,0,0,0.08);
margin-bottom:25px;
">

<h1 style="
margin:0;
font-size:56px;
font-weight:800;
color:#111827;
">
🛡 EmailShield Enterprise
</h1>

<p style="
font-size:20px;
margin-top:10px;
color:#6b7280;
">
Email Forensics & Threat Intelligence Platform
</p>

</div>
""", unsafe_allow_html=True)

# =====================================
# TOP KPI STRIP
# =====================================

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.metric(
        "Emails",
        "142"
    )

with c2:
    st.metric(
        "Threats",
        "34"
    )

with c3:
    st.metric(
        "High Risk",
        "12"
    )

with c4:
    st.metric(
        "IOCs",
        "286"
    )

st.markdown("<br>", unsafe_allow_html=True)

# =====================================
# UPLOAD
# =====================================

uploaded_file = st.file_uploader(
    "📧 Upload EML File",
    type=["eml"]
)

# =====================================
# DEMO UI
# =====================================

if uploaded_file:

    score = 78

    attack_type = "Credential Harvesting"

    verdict = "HIGH CONFIDENCE PHISHING"

    st.markdown("## Executive Summary")

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "Risk Score",
            f"{score}/100"
        )

    with col2:

        st.metric(
            "Attack Type",
            attack_type
        )

    with col3:

        st.metric(
            "Verdict",
            verdict
        )

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "📧 Summary",
        "🛣 Routing",
        "🌐 Intelligence",
        "📎 Attachments",
        "🎯 Detection",
        "🔍 IOCs"
    ])

    # =====================================
    # SUMMARY
    # =====================================

    with tab1:

        st.subheader(
            "Email Summary"
        )

        st.info(
            "📧 security@microsoft-update.com"
        )

        st.info(
            "📝 Verify Your Account Immediately"
        )

        st.info(
            "🌐 microsoft-update.com"
        )

        st.subheader(
            "Recommendations"
        )

        st.write(
            "• Block sender"
        )

        st.write(
            "• Investigate URLs"
        )
      
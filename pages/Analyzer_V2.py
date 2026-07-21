import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.pipeline import analyze_eml_bytes
from ui.theme import inject_theme, shield_orb_html

st.set_page_config(
    page_title="EmailShield Enterprise",
    page_icon="🛡",
    layout="wide"
)

inject_theme()

st.markdown(
    """
    <div class="es-hero">
        <div class="es-hero-mark">🛡</div>
        <div>
            <p class="es-hero-title">EmailShield Enterprise</p>
            <p class="es-hero-sub">Email Forensics &amp; Threat Intelligence Platform</p>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

# =====================================
# UPLOAD
# =====================================

uploaded_file = st.file_uploader(
    "📧 Upload EML File",
    type=["eml"]
)

if uploaded_file:

    with st.spinner("Analyzing email..."):

        try:
            result = analyze_eml_bytes(uploaded_file.getvalue())

        except Exception as e:
            st.error(f"Could not analyze this file: {e}")
            st.stop()

    score = result["score"]
    attack_type = result["attack_type"]
    verdict = result["verdict"]
    headers = result["headers"]
    auth = result["auth"]
    iocs = result["iocs"]
    attachments = result["attachments"]
    spam = result["spam"]

    # =====================================
    # EXECUTIVE SUMMARY
    # =====================================

    st.markdown("## Executive Summary")

    if score >= 70:
        verdict_desc = "High confidence phishing indicators detected"
    elif score >= 40:
        verdict_desc = "Some suspicious indicators - review recommended"
    else:
        verdict_desc = "No major threat indicators detected"

    st.markdown(
        shield_orb_html(score=score, title=verdict, desc=verdict_desc),
        unsafe_allow_html=True
    )

    st.write("")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Risk Score", f"{score}/100")

    with col2:
        st.metric("Attack Type", attack_type)

    with col3:
        st.metric("Spam Score", f"{spam['spam_score']}/100")

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

        st.subheader("Email Summary")

        st.info(f"📧 {headers.get('from', 'Unknown')}")
        st.info(f"📝 {headers.get('subject', 'Unknown')}")
        st.info(f"🌐 {result.get('sender_domain', 'Unknown')}")
        st.write(f"**To:** {headers.get('to', 'Unknown')}")
        st.write(f"**Date:** {headers.get('date', 'Unknown')}")

        st.subheader("Recommendations")

        for rec in result["recommendations"]:
            st.write(f"• {rec}")

        if spam["reasons"]:
            st.subheader("Spam Indicators")
            for reason in spam["reasons"]:
                st.write(f"• {reason}")

    # =====================================
    # ROUTING
    # =====================================

    with tab2:

        st.subheader("Routing Analysis")

        origin_ip = result.get("origin_ip")

        if origin_ip:
            st.success(f"Originating IP: {origin_ip}")
        else:
            st.warning("Unable to determine originating IP.")

        routing_data = result.get("routing_data") or []

        if routing_data:

            st.write(f"Total Hops: {len(routing_data)}")

            for hop in routing_data:

                st.markdown(f"### Hop {hop['hop']}")

                if hop["ips"]:
                    st.write("IPs:", ", ".join(hop["ips"]))
                else:
                    st.write("IPs: None Found")

                with st.expander(f"View Header - Hop {hop['hop']}"):
                    st.code(hop["header"])

                st.divider()

        else:
            st.warning("No routing information found.")

    # =====================================
    # INTELLIGENCE
    # =====================================

    with tab3:

        st.subheader("Authentication")

        c1, c2, c3 = st.columns(3)
        c1.metric("SPF", auth["spf"])
        c2.metric("DKIM", auth["dkim"])
        c3.metric("DMARC", auth["dmarc"])

        st.subheader("Domain Intelligence")

        domain_info = result.get("domain_info")
        domain_age = result.get("domain_age_days")

        if domain_info:
            st.write("Registrar:", domain_info.get("registrar", "Unknown"))
            st.write("Domain Age (days):", domain_age)
            st.write("Created:", domain_info.get("created"))

            if domain_age is not None and domain_age < 30:
                st.error("⚠ Newly Registered Domain")
        else:
            st.write("No WHOIS data available.")

        domain_rep = result.get("domain_reputation")

        if domain_rep:

            st.subheader("Domain Reputation (VirusTotal)")

            if domain_rep.get("malicious", -1) == -1:
                st.warning("VirusTotal Reputation Unavailable")
            else:
                st.write("Malicious:", domain_rep["malicious"])
                st.write("Suspicious:", domain_rep["suspicious"])
                st.write("Harmless:", domain_rep["harmless"])

                if domain_rep["malicious"] > 0:
                    st.error("⚠ Domain flagged by VirusTotal")

        st.subheader("IP Reputation")

        ip_info = result.get("ip_reputation_abuseipdb")
        ip_rep_vt = result.get("ip_reputation_virustotal")

        if ip_info:
            st.write("IP Address:", result.get("public_ip"))
            st.write("Country:", ip_info.get("country"))
            st.write("ISP:", ip_info.get("isp"))
            st.write("Abuse Score (AbuseIPDB):", ip_info.get("abuse_score"))
        else:
            st.write("No IP reputation data available.")

        if ip_rep_vt and ip_rep_vt.get("malicious", -1) != -1:
            st.write(
                f"VirusTotal - Malicious: {ip_rep_vt['malicious']}, "
                f"Suspicious: {ip_rep_vt['suspicious']}, "
                f"Harmless: {ip_rep_vt['harmless']}"
            )

    # =====================================
    # ATTACHMENTS
    # =====================================

    with tab4:

        st.subheader("Attachment Intelligence")

        if attachments:

            for attachment in attachments:

                st.write("**File Name:**", attachment["filename"])
                st.write("Declared Type:", attachment["content_type"])
                st.write("Detected Type:", attachment.get("detected_file_type", "UNKNOWN"))
                st.write("Size:", f"{attachment['size']} bytes")
                st.write("SHA256:", attachment["sha256"])

                if attachment.get("extension_spoofed"):
                    st.error("🚨 Extension spoofing detected - content does not match extension")

                if attachment.get("double_extension"):
                    st.error("🚨 Double extension trick detected")

                if attachment.get("bidi_override"):
                    st.error("🚨 Unicode filename spoofing detected")

                if attachment.get("script_indicators"):
                    st.error("🚨 Suspicious script content: " + ", ".join(attachment["script_indicators"]))

                st.divider()

        else:
            st.write("No attachments found.")

    # =====================================
    # DETECTION
    # =====================================

    with tab5:

        st.subheader("Attack Classification")

        st.write("**Attack Type:**", attack_type)
        st.write("**Verdict:**", verdict)

        st.write("Evidence:")
        for item in result["attack_evidence"]:
            st.write(f"• {item}")

        st.subheader("RCA Findings")

        for reason in result["reasons"]:
            st.write(f"• {reason}")

    # =====================================
    # IOCS
    # =====================================

    with tab6:

        st.subheader("Indicators of Compromise")

        st.write("**Domains:**", iocs["domains"] or "None")
        st.write("**IPs:**", iocs["ips"] or "None")
        st.write("**URLs:**", iocs["urls"] or "None")
        st.write("**Email Addresses:**", iocs["emails"] or "None")

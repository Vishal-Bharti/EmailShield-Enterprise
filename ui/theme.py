"""
EmailShield Enterprise - Liquid Glass theme.

Design tokens
-------------
Canvas      #EEF3FB  pale cool blue-white base, aurora blobs drift beneath the glass
Ink         #0C1526  primary text
Ink Muted   #5B6A85  secondary text / captions
Aurora Blue #2F6FED  primary accent
Aurora Vlt  #7C5CFC  secondary accent
Aurora Cyan #17B8C4  tertiary accent
Risk High   #E4483A  high risk / danger
Risk Mid    #F5A524  suspicious / warning
Risk Low    #21B573  clean / safe

Type
----
Display  Space Grotesk   headings, the risk score, KPI numbers
Body     Manrope         paragraphs, labels, UI copy
Mono     JetBrains Mono  hashes, IPs, domains, headers - raw forensic data

Signature element
------------------
The "Shield Orb": a glass sphere with a conic-gradient ring. While an
email is being analyzed it pulses in a neutral aurora gradient
(indeterminate scanning state). Once a risk score is known, the same
ring resolves into a colored, proportionally-filled gauge (green /
amber / red) with the score inside - the loading state and the result
state are the same object, not two disconnected effects.
"""

import time

import streamlit as st


LIQUID_GLASS_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Manrope:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
    --canvas: #EEF3FB;
    --ink: #0C1526;
    --ink-muted: #5B6A85;
    --aurora-blue: #2F6FED;
    --aurora-violet: #7C5CFC;
    --aurora-cyan: #17B8C4;
    --risk-high: #E4483A;
    --risk-mid: #F5A524;
    --risk-low: #21B573;
    --glass-fill: rgba(255, 255, 255, 0.55);
    --glass-fill-strong: rgba(255, 255, 255, 0.72);
    --glass-border: rgba(255, 255, 255, 0.65);
    --glass-shadow: 0 8px 32px rgba(47, 111, 237, 0.10), 0 2px 8px rgba(12, 21, 38, 0.06);
}

/* ---------- Aurora canvas ---------- */

.stApp {
    background:
        radial-gradient(ellipse 900px 600px at 8% -5%, rgba(47, 111, 237, 0.16), transparent 55%),
        radial-gradient(ellipse 800px 700px at 100% 10%, rgba(124, 92, 252, 0.14), transparent 55%),
        radial-gradient(ellipse 700px 600px at 20% 100%, rgba(23, 184, 196, 0.14), transparent 55%),
        radial-gradient(ellipse 600px 500px at 90% 95%, rgba(47, 111, 237, 0.10), transparent 55%),
        var(--canvas);
    background-attachment: fixed;
    animation: aurora-drift 40s ease-in-out infinite alternate;
}

@keyframes aurora-drift {
    0%   { background-position: 0% 0%, 100% 0%, 0% 100%, 100% 100%, 0 0; }
    100% { background-position: 4% 6%, 96% 4%, 6% 94%, 94% 96%, 0 0; }
}

header[data-testid="stHeader"] {
    background: transparent;
}

#MainMenu, footer { visibility: hidden; }

/* ---------- Typography ---------- */

html, body, [class*="css"] {
    font-family: 'Manrope', sans-serif;
    color: var(--ink);
}

h1, h2, h3 {
    font-family: 'Space Grotesk', sans-serif !important;
    color: var(--ink) !important;
    letter-spacing: -0.01em;
}

.stMarkdown code, .stCode, [data-testid="stCodeBlock"] {
    font-family: 'JetBrains Mono', monospace !important;
}

/* ---------- Block container ---------- */

.main .block-container {
    padding-top: 2rem;
    max-width: 1100px;
}

/* ---------- Hero ---------- */

.es-hero {
    display: flex;
    align-items: center;
    gap: 18px;
    padding: 26px 30px;
    border-radius: 26px;
    background: var(--glass-fill);
    backdrop-filter: blur(24px);
    -webkit-backdrop-filter: blur(24px);
    border: 1px solid var(--glass-border);
    box-shadow: var(--glass-shadow);
    margin-bottom: 22px;
    animation: es-fade-up 0.6s ease both;
}

.es-hero-mark {
    width: 54px;
    height: 54px;
    border-radius: 16px;
    background: conic-gradient(from 180deg, var(--aurora-blue), var(--aurora-violet), var(--aurora-cyan), var(--aurora-blue));
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 24px;
    flex-shrink: 0;
    box-shadow: 0 6px 18px rgba(47, 111, 237, 0.35);
}

.es-hero-title {
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 700;
    font-size: 28px;
    line-height: 1.1;
    color: var(--ink);
    margin: 0;
}

.es-hero-sub {
    font-family: 'Manrope', sans-serif;
    font-size: 14px;
    color: var(--ink-muted);
    margin-top: 4px;
}

.es-chip-row {
    display: flex;
    gap: 8px;
    margin-left: auto;
    flex-wrap: wrap;
}

.es-chip {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11.5px;
    padding: 6px 12px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.6);
    border: 1px solid var(--glass-border);
    color: var(--ink-muted);
    white-space: nowrap;
}

.es-chip.on { color: var(--risk-low); border-color: rgba(33, 181, 115, 0.35); background: rgba(33, 181, 115, 0.08); }
.es-chip.off { color: var(--risk-mid); border-color: rgba(245, 165, 36, 0.35); background: rgba(245, 165, 36, 0.08); }

/* ---------- Glass card wrapper (bordered containers) ---------- */

[data-testid="stVerticalBlockBorderWrapper"] {
    background: var(--glass-fill) !important;
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid var(--glass-border) !important;
    border-radius: 22px !important;
    box-shadow: var(--glass-shadow);
    padding: 4px;
}

/* ---------- Metrics ---------- */

[data-testid="stMetric"] {
    background: var(--glass-fill-strong);
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
    border: 1px solid var(--glass-border);
    border-radius: 20px;
    padding: 18px 20px;
    box-shadow: var(--glass-shadow);
}

[data-testid="stMetricValue"] {
    font-family: 'Space Grotesk', sans-serif !important;
    color: var(--ink) !important;
}

[data-testid="stMetricLabel"] {
    font-family: 'Manrope', sans-serif !important;
    color: var(--ink-muted) !important;
}

/* ---------- Buttons ---------- */

.stButton button, .stDownloadButton button {
    font-family: 'Manrope', sans-serif;
    font-weight: 600;
    border-radius: 14px;
    border: 1px solid var(--glass-border);
    background: linear-gradient(135deg, var(--aurora-blue), var(--aurora-violet));
    color: #ffffff;
    box-shadow: 0 6px 18px rgba(47, 111, 237, 0.28);
    transition: transform 0.15s ease, box-shadow 0.15s ease;
}

.stButton button:hover, .stDownloadButton button:hover {
    transform: translateY(-1px);
    box-shadow: 0 10px 24px rgba(47, 111, 237, 0.36);
    color: #ffffff;
}

/* ---------- File uploader ---------- */

[data-testid="stFileUploaderDropzone"] {
    background: var(--glass-fill);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1.5px dashed rgba(47, 111, 237, 0.45) !important;
    border-radius: 22px;
}

/* ---------- Alerts ---------- */

[data-testid="stAlert"] {
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border-radius: 16px;
    border: 1px solid var(--glass-border);
}

/* ---------- Expander ---------- */

[data-testid="stExpander"] {
    background: var(--glass-fill);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border: 1px solid var(--glass-border) !important;
    border-radius: 16px !important;
    overflow: hidden;
}

/* ---------- Progress bar ---------- */

[data-testid="stProgress"] > div > div {
    background: linear-gradient(90deg, var(--aurora-blue), var(--aurora-violet), var(--aurora-cyan)) !important;
}

/* ---------- Status widget (scan console) ---------- */

[data-testid="stStatusWidget"] {
    background: var(--glass-fill) !important;
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid var(--glass-border) !important;
    border-radius: 18px !important;
}

/* ---------- Divider ---------- */

hr { border-color: rgba(12, 21, 38, 0.08) !important; }

/* ---------- Sidebar (page nav) ---------- */

[data-testid="stSidebar"] {
    background: rgba(255, 255, 255, 0.5);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border-right: 1px solid var(--glass-border);
}

/* ---------- Severity utility classes ---------- */

.es-sev-high { border-left: 4px solid var(--risk-high) !important; }
.es-sev-mid  { border-left: 4px solid var(--risk-mid) !important; }
.es-sev-low  { border-left: 4px solid var(--risk-low) !important; }

/* ---------- Fade-up entrance ---------- */

@keyframes es-fade-up {
    from { opacity: 0; transform: translateY(10px); }
    to   { opacity: 1; transform: translateY(0); }
}

/* ---------- Shield Orb ---------- */

.es-orb-wrap {
    display: flex;
    align-items: center;
    gap: 22px;
    padding: 10px 6px;
}

.es-orb {
    position: relative;
    width: 108px;
    height: 108px;
    border-radius: 50%;
    flex-shrink: 0;
    background: var(--glass-fill-strong);
    backdrop-filter: blur(10px);
    border: 1px solid var(--glass-border);
    box-shadow: 0 10px 30px rgba(47, 111, 237, 0.20);
    display: flex;
    align-items: center;
    justify-content: center;
}

.es-orb::before {
    content: "";
    position: absolute;
    inset: -3px;
    border-radius: 50%;
    padding: 3px;
    background: conic-gradient(from 0deg, var(--ring-color-1, var(--aurora-blue)) 0deg, var(--ring-color-2, var(--aurora-cyan)) var(--ring-deg, 360deg), rgba(255,255,255,0.15) var(--ring-deg, 360deg));
    -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
    -webkit-mask-composite: xor;
    mask-composite: exclude;
}

.es-orb.scanning::before {
    animation: es-orb-spin 2.2s linear infinite;
}

.es-orb.result::before {
    animation: es-orb-settle 0.8s ease-out both;
}

@keyframes es-orb-spin {
    from { transform: rotate(0deg); }
    to   { transform: rotate(360deg); }
}

@keyframes es-orb-settle {
    from { opacity: 0; transform: scale(0.85) rotate(-40deg); }
    to   { opacity: 1; transform: scale(1) rotate(0deg); }
}

.es-orb-value {
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 700;
    font-size: 26px;
    color: var(--ink);
    z-index: 1;
}

.es-orb-value small {
    font-family: 'Manrope', sans-serif;
    font-weight: 600;
    font-size: 12px;
    color: var(--ink-muted);
    display: block;
}

.es-orb-caption {
    font-family: 'Manrope', sans-serif;
}

.es-orb-caption .es-orb-title {
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 700;
    font-size: 19px;
    color: var(--ink);
    margin-bottom: 3px;
}

.es-orb-caption .es-orb-desc {
    font-size: 13.5px;
    color: var(--ink-muted);
}

/* ---------- Splash screen ---------- */

.es-splash {
    position: fixed;
    inset: 0;
    z-index: 9999;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 18px;
    background:
        radial-gradient(ellipse 900px 700px at 20% 10%, rgba(47, 111, 237, 0.20), transparent 55%),
        radial-gradient(ellipse 800px 700px at 85% 90%, rgba(124, 92, 252, 0.18), transparent 55%),
        var(--canvas);
    animation: es-splash-out 0.5s ease 1.35s both;
}

.es-splash-orb {
    width: 84px;
    height: 84px;
    border-radius: 50%;
    background: var(--glass-fill-strong);
    backdrop-filter: blur(10px);
    border: 1px solid var(--glass-border);
    position: relative;
    box-shadow: 0 10px 30px rgba(47, 111, 237, 0.25);
}

.es-splash-orb::before {
    content: "";
    position: absolute;
    inset: -3px;
    border-radius: 50%;
    padding: 3px;
    background: conic-gradient(from 0deg, var(--aurora-blue), var(--aurora-violet), var(--aurora-cyan), var(--aurora-blue));
    -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
    -webkit-mask-composite: xor;
    mask-composite: exclude;
    animation: es-orb-spin 1.1s linear infinite;
}

.es-splash-text {
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 600;
    font-size: 15px;
    color: var(--ink-muted);
    letter-spacing: 0.02em;
}

@keyframes es-splash-out {
    to { opacity: 0; visibility: hidden; }
}
"""


def inject_theme():
    """Inject the Liquid Glass CSS once per page."""

    st.markdown(
        f"<style>{LIQUID_GLASS_CSS}</style>",
        unsafe_allow_html=True
    )


def render_splash():
    """Show a brief animated splash once per browser session.

    Streamlit reruns the whole script on every interaction, so this is
    gated behind session_state - without the gate it would replay on
    every button click, which would be disruptive rather than a
    one-time loading moment.
    """

    if st.session_state.get("es_splash_shown"):
        return

    st.session_state["es_splash_shown"] = True

    placeholder = st.empty()

    placeholder.markdown(
        """
        <div class="es-splash">
            <div class="es-splash-orb"></div>
            <div class="es-splash-text">Initializing EmailShield&hellip;</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    time.sleep(1.4)
    placeholder.empty()


def shield_orb_html(score=None, title=None, desc=None):
    """Render the Shield Orb.

    score=None -> neutral aurora ring, spinning (scanning state).
    score=int  -> ring fill proportional to score/100, colored by
                  severity, with the number inside (result state).
    """

    if score is None:
        return f"""
        <div class="es-orb-wrap">
            <div class="es-orb scanning">
                <div class="es-orb-value"><small>Scanning</small>&hellip;</div>
            </div>
            <div class="es-orb-caption">
                <div class="es-orb-title">{title or "Analyzing email"}</div>
                <div class="es-orb-desc">{desc or "Running header, IOC, and attachment checks"}</div>
            </div>
        </div>
        """

    score = max(0, min(100, int(score)))

    if score >= 70:
        c1, c2, verdict = "#E4483A", "#F5A524", "High Risk"
    elif score >= 40:
        c1, c2, verdict = "#F5A524", "#F7C948", "Suspicious"
    else:
        c1, c2, verdict = "#21B573", "#17B8C4", "Low Risk"

    ring_deg = round(score / 100 * 360)

    return f"""
    <div class="es-orb-wrap">
        <div class="es-orb result" style="--ring-color-1:{c1}; --ring-color-2:{c2}; --ring-deg:{ring_deg}deg;">
            <div class="es-orb-value">{score}<small>/ 100</small></div>
        </div>
        <div class="es-orb-caption">
            <div class="es-orb-title">{title or verdict}</div>
            <div class="es-orb-desc">{desc or "Overall risk score for this email"}</div>
        </div>
    </div>
    """

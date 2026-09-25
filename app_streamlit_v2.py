"""
QR / URL Phishing Risk Analyzer — Web v2

Mobile-first Streamlit web application built on the existing project engine.
Features:
- Live phone-style QR scanner (back camera) via streamlit-qrcode-scanner
- QR image upload fallback
- URL analysis
- Safe-site "Open website" action for SECURE PLATFORM only
- Scan history for the current session + CSV export
- Detailed security checks and model explanations
- Mobile-friendly dashboard and project information
"""

from __future__ import annotations

import csv
import io
from datetime import datetime
from urllib.parse import urlparse

import streamlit as st
import tldextract

from risk_engine import PhishingRiskEngine
from qr_utils import decode_qr
from glossary import FEATURE_GLOSSARY, MODEL_GLOSSARY

try:
    from streamlit_qrcode_scanner import qrcode_scanner
    QR_SCANNER_AVAILABLE = True
except Exception:
    QR_SCANNER_AVAILABLE = False


st.set_page_config(
    page_title="PhishGuard QR",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)


# -----------------------------
# Styling
# -----------------------------
st.markdown(
    """
    <style>
    .block-container {max-width: 900px; padding-top: 1rem; padding-bottom: 3rem;}
    .hero {padding: 1.2rem 1.1rem; border-radius: 22px; background: linear-gradient(135deg, #101828, #1d2939); color: white; margin-bottom: 1rem;}
    .hero h1 {margin: 0; font-size: 2rem;}
    .hero p {margin: .45rem 0 0; opacity: .86;}
    .scan-card {padding: .8rem; border: 1px solid rgba(128,128,128,.25); border-radius: 18px;}
    .small-muted {font-size: .86rem; opacity: .72;}
    .safe-note {padding: .7rem .9rem; border-radius: 14px; background: rgba(46, 160, 67, .10); border: 1px solid rgba(46, 160, 67, .30);}
    .warn-note {padding: .7rem .9rem; border-radius: 14px; background: rgba(210, 153, 34, .10); border: 1px solid rgba(210, 153, 34, .30);}
    @media (max-width: 640px) {
        .hero h1 {font-size: 1.55rem;}
        .block-container {padding-left: .75rem; padding-right: .75rem;}
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource(show_spinner="Loading AI detection models...")
def load_engine():
    return PhishingRiskEngine()


engine = load_engine()


if "history" not in st.session_state:
    st.session_state.history = []
if "last_result" not in st.session_state:
    st.session_state.last_result = None
if "last_source" not in st.session_state:
    st.session_state.last_source = None
if "last_scanned_code" not in st.session_state:
    st.session_state.last_scanned_code = None


VERDICT_CONTENT = {
    "SECURE PLATFORM": {
        "icon": "🟢",
        "headline": "Looks safe",
        "kind": "success",
        "explanation": "The URL passed the strict secure-platform checks used by this project.",
        "advice": [
            "You can open the site using the button below, but still verify the domain if you are entering sensitive information.",
            "Never share OTPs, passwords, PINs or card details from an unexpected message.",
        ],
    },
    "LOW RISK": {
        "icon": "🟢",
        "headline": "Low risk",
        "kind": "success",
        "explanation": "No major warning pattern was detected, but the model cannot guarantee that a site is safe.",
        "advice": [
            "Check the exact domain before entering credentials.",
            "Use the official app or manually typed website for sensitive transactions.",
        ],
    },
    "SUSPICIOUS": {
        "icon": "🟠",
        "headline": "Be careful — suspicious",
        "kind": "warning",
        "explanation": "One or more warning patterns were detected. Treat this link cautiously.",
        "advice": [
            "Do not enter passwords, OTPs, PINs or card details.",
            "Open the official service directly instead of following the scanned link.",
        ],
    },
    "HIGH RISK / LIKELY PHISHING": {
        "icon": "🔴",
        "headline": "Danger — likely phishing",
        "kind": "error",
        "explanation": "Multiple strong warning patterns were detected by the project's models/rules.",
        "advice": [
            "Do not open the link or submit personal information.",
            "If it came from a message, report/delete the message and verify the sender through another channel.",
        ],
    },
}


def normalise_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not urlparse(url).scheme:
        return "https://" + url
    return url


def is_web_url(url: str) -> bool:
    return urlparse(url).scheme.lower() in {"http", "https"} and bool(urlparse(url).netloc)


def domain_summary(url: str) -> dict:
    test_url = url if urlparse(url).scheme else "https://" + url
    ext = tldextract.extract(test_url)
    parsed = urlparse(test_url)
    return {
        "Domain": f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain,
        "Subdomain": ext.subdomain or "None",
        "Scheme": parsed.scheme.upper(),
        "Path": parsed.path or "/",
        "Query": "Present" if parsed.query else "None",
    }


def security_checks(result: dict) -> list[tuple[str, str, str]]:
    feat = result["features"]
    checks = [
        ("HTTPS", "PASS" if feat["has_https_scheme"] else "WARN", "Encrypted connection" if feat["has_https_scheme"] else "No HTTPS scheme"),
        ("IP address", "PASS" if not feat["has_ip"] else "WARN", "Normal domain" if not feat["has_ip"] else "Raw numeric IP used"),
        ("URL shortener", "PASS" if not feat["is_shortened"] else "WARN", "No known shortener" if not feat["is_shortened"] else "Destination is hidden behind a shortener"),
        ("Suspicious TLD", "PASS" if not feat["suspicious_tld"] else "WARN", "TLD not on project warning list" if not feat["suspicious_tld"] else "TLD is on the project warning list"),
        ("Subdomains", "PASS" if not feat["many_subdomains"] else "WARN", f"{feat['subdomain_count']} subdomain(s)"),
        ("URL length", "PASS" if not feat["long_url"] else "WARN", f"{feat['url_length']} characters"),
        ("Brand impersonation", "WARN" if result.get("impersonation_note") else "PASS", "Brand/domain mismatch detected" if result.get("impersonation_note") else "No project-listed mismatch detected"),
    ]
    return checks


def save_history(result: dict, source: str):
    record = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "url": result["url"],
        "risk": result["risk_percentage"],
        "verdict": result["verdict"],
    }
    st.session_state.history.insert(0, record)
    st.session_state.history = st.session_state.history[:50]


def analyze_and_store(url: str, source: str):
    url = normalise_url(url)
    if not url:
        st.warning("Please provide a URL first.")
        return
    if len(url) > 2048:
        url = url[:2048]
        st.warning("The URL was truncated to 2048 characters for analysis.")
    with st.spinner("Analyzing with Random Forest + Character-CNN + security rules..."):
        result = engine.analyze(url)
    st.session_state.last_result = result
    st.session_state.last_source = source
    save_history(result, source)


def render_result(result: dict):
    verdict = result["verdict"]
    risk = result["risk_percentage"]
    content = VERDICT_CONTENT.get(verdict, VERDICT_CONTENT["SUSPICIOUS"])

    st.divider()
    st.subheader(f"{content['icon']} {content['headline']}")
    if content["kind"] == "success":
        st.success(content["explanation"])
    elif content["kind"] == "warning":
        st.warning(content["explanation"])
    else:
        st.error(content["explanation"])

    st.progress(min(max(int(risk), 0), 100), text=f"Risk score: {risk}%")

    if result.get("impersonation_note"):
        st.error(f"🚨 **Brand impersonation:** {result['impersonation_note']}")

    c1, c2, c3 = st.columns(3)
    c1.metric("Random Forest", f"{result['rf_probability']}%")
    c2.metric("Character-CNN", f"{result['cnn_probability']}%")
    c3.metric("Heuristics", f"{result['heuristic_score']}%")

    st.markdown("### 🔎 What was detected")
    reasons = result.get("top_reasons") or []
    if reasons:
        for reason in reasons:
            st.markdown(f"- **{FEATURE_GLOSSARY.get(reason, reason.replace('_', ' ').title())}**")
    else:
        st.write("No active red-flag features were selected by the explanation layer.")

    st.markdown("### 🧪 Security checks")
    for name, status, detail in security_checks(result):
        icon = "✅" if status == "PASS" else "⚠️"
        st.write(f"{icon} **{name}:** {detail}")

    st.markdown("### 🌐 Link details")
    st.json(domain_summary(result["url"]))
    st.code(result["url"], language="text")

    if verdict == "SECURE PLATFORM" and is_web_url(result["url"]):
        st.markdown('<div class="safe-note"><b>Safe-site action:</b> the project gave this URL its strictest secure-platform label. Opening is still your decision.</div>', unsafe_allow_html=True)
        st.link_button("🌐 Open website", result["url"], use_container_width=True)
    else:
        st.markdown('<div class="warn-note"><b>Website opening disabled here.</b> Use the official website/app directly when a link is suspicious or not in the strict secure category.</div>', unsafe_allow_html=True)

    with st.expander("🤖 Technical model details"):
        st.write(MODEL_GLOSSARY["Random Forest"])
        st.write(MODEL_GLOSSARY["Character-CNN"])
        st.write(MODEL_GLOSSARY["Heuristic score"])
        st.json(result["features"])

    st.markdown("### 🛡️ Recommended action")
    for tip in content["advice"]:
        st.markdown(f"- {tip}")


def scanner_tab():
    st.subheader("📷 Live QR Scanner")
    st.caption("Point your phone's back camera at a QR code. The scanner reads the code and sends only the decoded text to the local risk engine.")

    if not QR_SCANNER_AVAILABLE:
        st.error("The live scanner component is not installed in this environment.")
        st.code("pip install streamlit-qrcode-scanner", language="bash")
        return

    qr_code = qrcode_scanner(key="phishguard_qr_scanner")
    if qr_code:
        if isinstance(qr_code, (list, tuple)):
            qr_code = qr_code[0] if qr_code else ""
        if qr_code:
            qr_code = str(qr_code).strip()
            st.success("QR code detected")
            st.code(qr_code, language="text")
            if qr_code != st.session_state.last_scanned_code:
                st.session_state.last_scanned_code = qr_code
                analyze_and_store(qr_code, "Live camera")
            else:
                st.caption("Already analyzed in this scan session.")
            if st.button("Scan another QR", key="scan_again", use_container_width=True):
                st.session_state.last_scanned_code = None
                st.rerun()


def upload_tab():
    st.subheader("📁 Scan a QR image")
    st.caption("Use this when the live camera is unavailable or when you already have a QR screenshot/photo.")
    uploaded = st.file_uploader("Choose a QR image", type=["png", "jpg", "jpeg", "bmp"])
    if uploaded:
        try:
            import tempfile
            import os
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "qr_input")
                with open(path, "wb") as f:
                    f.write(uploaded.getvalue())
                urls = decode_qr(path)
            if not urls:
                st.error("No QR code was detected in that image.")
            else:
                st.success("QR code detected")
                analyze_and_store(urls[0], "QR image")
        except ValueError as exc:
            st.error(str(exc))


def url_tab():
    st.subheader("⌨️ Check a URL")
    url = st.text_input("Paste a URL", placeholder="https://example.com", key="manual_url")
    if st.button("🔍 Analyze URL", type="primary", use_container_width=True):
        analyze_and_store(url, "Manual URL")


def history_tab():
    st.subheader("🕘 Scan history")
    if not st.session_state.history:
        st.info("No scans in this browser session yet.")
        return

    st.dataframe(st.session_state.history, use_container_width=True, hide_index=True)

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["time", "source", "url", "risk", "verdict"])
    writer.writeheader()
    writer.writerows(st.session_state.history)
    st.download_button(
        "⬇️ Download history CSV",
        data=output.getvalue(),
        file_name="phishguard_scan_history.csv",
        mime="text/csv",
        use_container_width=True,
    )

    if st.button("Clear session history", use_container_width=True):
        st.session_state.history = []
        st.session_state.last_result = None
        st.rerun()


# -----------------------------
# Main UI
# -----------------------------
st.markdown(
    """
    <div class="hero">
      <h1>🛡️ PhishGuard QR</h1>
      <p>QR & URL phishing-risk analysis using machine learning, a character CNN and transparent security checks.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.info("🔒 Privacy design: this project treats a decoded QR value as text for analysis. It does not execute the QR payload or intentionally visit the scanned URL.")

scan, upload, manual, history = st.tabs(["📷 Scan QR", "📁 QR Image", "⌨️ URL", "🕘 History"])

with scan:
    scanner_tab()
with upload:
    upload_tab()
with manual:
    url_tab()
with history:
    history_tab()

st.divider()

with st.expander("ℹ️ How the detection works"):
    st.markdown(
        """
        **Three signals are combined:**
        - **Random Forest:** 21 lexical/structural URL features.
        - **Character-CNN:** reads the URL string character-by-character.
        - **Heuristic engine:** transparent checks such as raw IPs, URL shorteners, HTTPS usage and suspicious patterns.

        The result is a project-specific risk score, not a guarantee. A low score cannot prove that a website is trustworthy.
        """
    )

st.caption("Educational cybersecurity project • No automatic navigation to scanned URLs • Use the strict secure-platform button only when you understand the result.")

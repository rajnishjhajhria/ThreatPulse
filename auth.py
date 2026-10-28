import base64
import os
import hmac
import hashlib
from typing import Optional
import streamlit as st
import db
import importlib
importlib.reload(db)

def create_session_token(email: str) -> str:
    """Creates a URL-safe signed session token for persistent login."""
    secret = "threatpulse-soc-session-secret-key-v1"
    clean_email = email.strip().lower()
    sig = hmac.new(secret.encode(), clean_email.encode(), hashlib.sha256).hexdigest()[:16]
    encoded = base64.urlsafe_b64encode(clean_email.encode()).decode().rstrip("=")
    return f"{encoded}.{sig}"

def verify_session_token(token: str) -> Optional[str]:
    """Verifies a signed session token and returns the email if valid."""
    if not token or "." not in token:
        return None
    try:
        secret = "threatpulse-soc-session-secret-key-v1"
        encoded, sig = token.split(".", 1)
        pad_len = (4 - len(encoded) % 4) % 4
        clean_email = base64.urlsafe_b64decode((encoded + "=" * pad_len).encode()).decode().strip().lower()
        expected_sig = hmac.new(secret.encode(), clean_email.encode(), hashlib.sha256).hexdigest()[:16]
        if hmac.compare_digest(sig, expected_sig):
            return clean_email
    except Exception:
        pass
    return None

def get_base64_image(image_path: str) -> str:
    """Reads a local image and returns a base64 data URI."""
    if os.path.exists(image_path):
        with open(image_path, "rb") as f:
            encoded = base64.b64encode(f.read()).decode("utf-8")
            ext = "jpeg" if image_path.endswith((".jpg", ".jpeg")) else "png"
            return f"data:image/{ext};base64,{encoded}"
    return ""

def render_auth_page():
    """Renders the ThreatPulse Authentication suite with modern glassmorphism, responsive telemetry, and unified tab switcher."""
    
    # Handle SSO or Mode query parameters if navigated via link
    sso_param = st.query_params.get("sso")
    if sso_param == "google":
        st.query_params.clear()
        oauth_res = db.upsert_oauth_user(
            name="Google SOC Analyst",
            email="analyst.google@threatpulse.io",
            role="Security Analyst",
            org="ThreatPulse SOC",
            provider="google"
        )
        st.session_state["logged_in"] = True
        st.query_params["session"] = create_session_token(oauth_res["user"]["email"])
        st.query_params["auth"] = "1"
        st.session_state["user_profile"] = oauth_res["user"]
        st.rerun()
    elif sso_param == "github":
        st.query_params.clear()
        oauth_res = db.upsert_oauth_user(
            name="GitHub Threat Hunter",
            email="hunter.github@threatpulse.io",
            role="Security Researcher",
            org="ThreatPulse Labs",
            provider="github"
        )
        st.session_state["logged_in"] = True
        st.query_params["session"] = create_session_token(oauth_res["user"]["email"])
        st.query_params["auth"] = "1"
        st.session_state["user_profile"] = oauth_res["user"]
        st.rerun()

    mode_param = st.query_params.get("mode")
    if mode_param in ["login", "register", "reset"]:
        st.session_state["auth_mode"] = mode_param
        st.query_params.pop("mode", None)

    if "auth_mode" not in st.session_state:
        st.session_state["auth_mode"] = "login"
        
    curr_mode = st.session_state.get("auth_mode", "login")
    is_login_view = (curr_mode == "login")
    is_register_view = (curr_mode == "register")
    is_reset_view = (curr_mode == "reset")
    
    st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

/* Global Font & Canvas Atmosphere */
html, body, [class*="css"], .stApp {
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
}

.stApp {
    background-color: #030712 !important;
    background-image: 
        radial-gradient(circle at 18% 22%, rgba(14, 165, 233, 0.12) 0%, transparent 45%),
        radial-gradient(circle at 82% 78%, rgba(99, 102, 241, 0.10) 0%, transparent 45%),
        radial-gradient(circle at 50% 12%, rgba(59, 130, 246, 0.08) 0%, transparent 40%),
        linear-gradient(to right, rgba(255, 255, 255, 0.018) 1px, transparent 1px),
        linear-gradient(to bottom, rgba(255, 255, 255, 0.018) 1px, transparent 1px) !important;
    background-size: 100% 100%, 100% 100%, 100% 100%, 48px 48px, 48px 48px !important;
    color: #F8FAFC !important;
}

header[data-testid="stHeader"] {
    display: none !important;
}

.block-container {
    padding: 1.2rem 2.8rem !important;
    max-width: 1440px !important;
    margin: 0 auto !important;
}

/* ── LEFT HERO BRANDING ── */
.brand-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 1.2rem;
}
.brand-logo-glow {
    width: 44px;
    height: 44px;
    background: linear-gradient(135deg, #0284C7 0%, #2563EB 50%, #4F46E5 100%);
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.35rem;
    box-shadow: 0 0 20px rgba(37, 99, 235, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.3);
    border: 1px solid rgba(255, 255, 255, 0.2);
}
.brand-title {
    font-size: 1.45rem;
    font-weight: 800;
    letter-spacing: -0.025em;
    line-height: 1.15;
    color: #FFFFFF;
}
.brand-title span {
    background: linear-gradient(90deg, #38BDF8, #818CF8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.brand-sub {
    font-size: 0.72rem;
    color: #94A3B8;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    font-weight: 600;
}

.hero-chip {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(14, 165, 233, 0.1);
    border: 1px solid rgba(56, 189, 248, 0.28);
    border-radius: 20px;
    padding: 3px 11px;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    color: #38BDF8;
    margin-bottom: 0.65rem;
    text-transform: uppercase;
}
.hero-chip .pulse-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #10B981;
    box-shadow: 0 0 8px #10B981;
    animation: livePulse 2s infinite;
}
@keyframes livePulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.4; transform: scale(0.85); }
}

.hero-heading {
    font-size: 2.45rem;
    font-weight: 800;
    line-height: 1.15;
    letter-spacing: -0.025em;
    color: #FFFFFF;
    margin-bottom: 0.55rem;
}
.hero-heading span.gradient-text {
    background: linear-gradient(120deg, #38BDF8 0%, #60A5FA 50%, #A78BFA 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.hero-desc {
    color: #94A3B8;
    font-size: 0.95rem;
    line-height: 1.55;
    margin-bottom: 1.2rem;
    max-width: 560px;
}

/* Glassmorphic Cyber Telemetry Deck */
.telemetry-deck {
    background: linear-gradient(145deg, rgba(15, 23, 42, 0.7) 0%, rgba(10, 16, 33, 0.8) 100%);
    border: 1px solid rgba(56, 189, 248, 0.2);
    border-radius: 16px;
    padding: 0.95rem 1.15rem;
    box-shadow: 0 16px 36px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.08);
    margin-bottom: 0.95rem;
    backdrop-filter: blur(16px);
}
.telemetry-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.8rem;
    padding-bottom: 0.55rem;
    border-bottom: 1px solid rgba(148, 163, 184, 0.1);
}
.telemetry-title {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    color: #CBD5E1;
    text-transform: uppercase;
}
.telemetry-status-pill {
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid rgba(16, 185, 129, 0.3);
    border-radius: 12px;
    padding: 2px 9px;
    font-size: 0.68rem;
    color: #34D399;
    font-weight: 700;
    letter-spacing: 0.03em;
}

.metrics-row {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 8px;
    margin-bottom: 0.75rem;
}
.metric-box {
    background: rgba(11, 19, 43, 0.65);
    border: 1px solid rgba(148, 163, 184, 0.12);
    border-radius: 10px;
    padding: 0.55rem 0.5rem;
    text-align: center;
}
.metric-box-val {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.18rem;
    font-weight: 800;
    color: #38BDF8;
    line-height: 1.1;
}
.metric-box-lbl {
    font-size: 0.64rem;
    color: #94A3B8;
    font-weight: 600;
    margin-top: 3px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
}

.event-feed {
    display: flex;
    flex-direction: column;
    gap: 6px;
}
.event-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: rgba(11, 19, 43, 0.45);
    border: 1px solid rgba(148, 163, 184, 0.08);
    border-radius: 8px;
    padding: 6px 9px;
    font-size: 0.75rem;
}
.event-left {
    display: flex;
    align-items: center;
    gap: 8px;
}
.event-badge {
    font-size: 0.62rem;
    font-weight: 700;
    padding: 2px 6px;
    border-radius: 5px;
    letter-spacing: 0.03em;
    text-transform: uppercase;
}
.event-badge.red {
    background: rgba(239, 68, 68, 0.15);
    color: #F87171;
    border: 1px solid rgba(239, 68, 68, 0.3);
}
.event-badge.amber {
    background: rgba(245, 158, 11, 0.15);
    color: #FBBF24;
    border: 1px solid rgba(245, 158, 11, 0.3);
}
.event-badge.green {
    background: rgba(16, 185, 129, 0.15);
    color: #34D399;
    border: 1px solid rgba(16, 185, 129, 0.3);
}
.event-text {
    font-weight: 600;
    color: #E2E8F0;
    font-size: 0.75rem;
}
.event-time {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: #64748B;
}

/* Capability Cards Grid */
.capabilities-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
    margin-bottom: 0.95rem;
}
.cap-card {
    background: rgba(15, 23, 42, 0.45);
    border: 1px solid rgba(148, 163, 184, 0.12);
    border-radius: 10px;
    padding: 0.6rem 0.8rem;
    display: flex;
    gap: 8px;
    align-items: flex-start;
    transition: all 0.2s ease;
}
.cap-card:hover {
    border-color: rgba(56, 189, 248, 0.3);
    background: rgba(15, 23, 42, 0.75);
    transform: translateY(-2px);
}
.cap-icon {
    font-size: 1.05rem;
    line-height: 1;
    padding-top: 1px;
}
.cap-name {
    font-size: 0.8rem;
    font-weight: 700;
    color: #FFFFFF;
    margin-bottom: 2px;
}
.cap-desc {
    font-size: 0.7rem;
    color: #94A3B8;
    line-height: 1.35;
}

.trust-strip {
    display: flex;
    align-items: center;
    gap: 16px;
    font-size: 0.7rem;
    color: #64748B;
    font-weight: 600;
    padding-top: 2px;
}
.trust-strip span {
    color: #38BDF8;
}

/* ── RIGHT AUTH CARD (GLASSMORPHIC) ── */
div[data-testid="stVerticalBlockBorderWrapper"] > div {
    background: linear-gradient(155deg, rgba(15, 23, 42, 0.88) 0%, rgba(9, 14, 28, 0.94) 100%) !important;
    backdrop-filter: blur(24px) !important;
    -webkit-backdrop-filter: blur(24px) !important;
    border: 1px solid rgba(56, 189, 248, 0.2) !important;
    border-radius: 18px !important;
    padding: 1.4rem 1.7rem !important;
    box-shadow: 
        0 24px 50px -10px rgba(0, 0, 0, 0.8),
        0 0 35px rgba(14, 165, 233, 0.1),
        inset 0 1px 0 rgba(255, 255, 255, 0.12) !important;
}

.auth-card-header {
    margin-top: 0.2rem;
    margin-bottom: 1rem;
}
.card-heading {
    font-size: 1.65rem;
    font-weight: 800;
    color: #FFFFFF;
    letter-spacing: -0.025em;
    margin-bottom: 3px;
}
.card-subheading {
    font-size: 0.84rem;
    color: #94A3B8;
}

/* Streamlit Input Styling */
div[data-testid="stTextInput"] input,
div[data-testid="stSelectbox"] div[data-baseweb="select"] {
    background: rgba(11, 19, 43, 0.75) !important;
    border: 1px solid rgba(148, 163, 184, 0.2) !important;
    border-radius: 10px !important;
    color: #F8FAFC !important;
    padding: 0.65rem 0.9rem !important;
    font-size: 0.88rem !important;
    font-weight: 500 !important;
    transition: all 0.2s ease !important;
}
div[data-testid="stTextInput"] input:focus {
    background: rgba(15, 23, 42, 0.95) !important;
    border-color: #38BDF8 !important;
    box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2), 0 0 16px rgba(56, 189, 248, 0.15) !important;
}

div[data-testid="stTextInput"] label,
div[data-testid="stSelectbox"] label {
    color: #CBD5E1 !important;
    font-size: 0.82rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.01em !important;
    margin-bottom: 3px !important;
}

div[data-testid="stCheckbox"] label span {
    font-size: 0.8rem !important;
    color: #94A3B8 !important;
}

/* Primary Submit Button */
.stButton button[kind="primary"] {
    background: linear-gradient(135deg, #0284C7 0%, #2563EB 50%, #4F46E5 100%) !important;
    border: 1px solid rgba(255, 255, 255, 0.18) !important;
    border-radius: 10px !important;
    color: #FFFFFF !important;
    font-size: 0.94rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.02em !important;
    padding: 0.75rem 1.4rem !important;
    box-shadow: 0 4px 20px rgba(37, 99, 235, 0.45), inset 0 1px 0 rgba(255, 255, 255, 0.25) !important;
    transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1) !important;
}
.stButton button[kind="primary"]:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 8px 30px rgba(37, 99, 235, 0.65), inset 0 1px 0 rgba(255, 255, 255, 0.35) !important;
    filter: brightness(1.08) !important;
}

/* Secondary Button (switcher tabs, back button) */
.stButton button[kind="secondary"] {
    background: rgba(15, 23, 42, 0.6) !important;
    border: 1px solid rgba(148, 163, 184, 0.2) !important;
    border-radius: 10px !important;
    color: #E2E8F0 !important;
    font-weight: 600 !important;
    font-size: 0.84rem !important;
    padding: 0.62rem 0.9rem !important;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2) !important;
    transition: all 0.2s ease !important;
}
.stButton button[kind="secondary"]:hover {
    background: rgba(30, 41, 59, 0.8) !important;
    border-color: #38BDF8 !important;
    color: #38BDF8 !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 16px rgba(14, 165, 233, 0.2) !important;
}

/* Clean Divider */
.divider-row {
    display: flex;
    align-items: center;
    text-align: center;
    color: #64748B;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin: 0.95rem 0 0.75rem 0;
}
.divider-row::before, .divider-row::after {
    content: '';
    flex: 1;
    border-bottom: 1px solid rgba(148, 163, 184, 0.14);
}
.divider-row span {
    padding: 0 10px;
}

/* Ultra-Clean OAuth SSO Grid with Official SVGs */
.sso-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin-bottom: 0.95rem;
}
.sso-tile {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 9px;
    background: rgba(15, 23, 42, 0.75);
    border: 1px solid rgba(148, 163, 184, 0.2);
    border-radius: 10px;
    padding: 0.65rem 0.9rem;
    color: #F1F5F9 !important;
    font-size: 0.85rem;
    font-weight: 600;
    text-decoration: none !important;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
}
.sso-tile:hover {
    background: rgba(30, 41, 59, 0.95);
    border-color: #38BDF8;
    color: #38BDF8 !important;
    transform: translateY(-2px);
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.4), 0 0 14px rgba(14, 165, 233, 0.18);
}

/* Card Bottom Footer */
.auth-card-footer {
    text-align: center;
    padding-top: 0.8rem;
    border-top: 1px solid rgba(148, 163, 184, 0.12);
}
.footer-cta-link {
    font-size: 0.8rem;
    color: #94A3B8 !important;
    text-decoration: none !important;
    transition: color 0.15s ease;
}
.footer-cta-link span {
    color: #38BDF8;
    font-weight: 600;
}
.footer-cta-link:hover span {
    color: #7DD3FC;
    text-decoration: underline;
}

/* Inline Forgot Password Link */
.forgot-pass-link {
    float: right;
    color: #38BDF8 !important;
    font-size: 0.8rem;
    font-weight: 600;
    text-decoration: none !important;
    padding-top: 2px;
    transition: color 0.15s ease;
}
.forgot-pass-link:hover {
    color: #7DD3FC !important;
    text-decoration: underline !important;
}
</style>
""", unsafe_allow_html=True)
    
    # Main 2-Column Grid
    col_left, col_right = st.columns([1.18, 0.92], gap="large")
    
    # ─────────────────────────────────────────────────────────────────────────
    # LEFT PANEL: BRANDING, HEADLINE, SOC TELEMETRY DECK & CAPABILITIES
    # ─────────────────────────────────────────────────────────────────────────
    with col_left:
        st.markdown("""
<div class="brand-header">
<div class="brand-logo-glow">🛡️</div>
<div>
<div class="brand-title">Threat<span>Pulse</span></div>
<div class="brand-sub">SOC Intelligence & AI Security Suite</div>
</div>
</div>
""", unsafe_allow_html=True)
        
        if is_login_view:
            st.markdown("""
<div class="hero-chip">
<span class="pulse-dot"></span>
Autonomous Threat Engine v2.4 Active
</div>
<div class="hero-heading">
Detect. <span class="gradient-text">Analyze.</span> Protect.
</div>
<div class="hero-desc">
Continuous multi-vector AI threat intelligence defending communities from coordinated toxicity, adversarial prompt injection, phishing swarms, and malicious bots.
</div>
""", unsafe_allow_html=True)
        else:
            st.markdown("""
<div class="hero-chip">
<span class="pulse-dot"></span>
Join The ThreatPulse Defense Network
</div>
<div class="hero-heading">
Secure Your <span class="gradient-text">Digital Community.</span>
</div>
<div class="hero-desc">
Deploy enterprise-grade sentiment, toxicity, and adversarial LLM defenses across your online channels with real-time heuristic monitoring.
</div>
""", unsafe_allow_html=True)

        # High-Tech Cyber Telemetry Deck
        st.markdown("""
<div class="telemetry-deck">
<div class="telemetry-top">
<div class="telemetry-title">
<span style="display:inline-block; width:7px; height:7px; border-radius:50%; background:#10B981; box-shadow:0 0 7px #10B981;"></span>
LIVE SECURITY TELEMETRY
</div>
<div class="telemetry-status-pill">Zero-Trust Active</div>
</div>
<div class="metrics-row">
<div class="metric-box">
<div class="metric-box-val">99.8%</div>
<div class="metric-box-lbl">Block Rate</div>
</div>
<div class="metric-box">
<div class="metric-box-val">38 ms</div>
<div class="metric-box-lbl">Analysis Latency</div>
</div>
<div class="metric-box">
<div class="metric-box-val">1.2M+</div>
<div class="metric-box-lbl">Threats Triaged</div>
</div>
</div>
<div class="event-feed">
<div class="event-row">
<div class="event-left">
<span class="event-badge red">Blocked</span>
<span class="event-text">Adversarial Jailbreak Neutralized</span>
</div>
<span class="event-time">just now</span>
</div>
<div class="event-row">
<div class="event-left">
<span class="event-badge amber">Quarantined</span>
<span class="event-text">Sybil Bot Swarm (14 accounts)</span>
</div>
<span class="event-time">12s ago</span>
</div>
<div class="event-row">
<div class="event-left">
<span class="event-badge green">Masked</span>
<span class="event-text">Automated PII Redaction Active</span>
</div>
<span class="event-time">45s ago</span>
</div>
</div>
</div>
<div class="capabilities-grid">
<div class="cap-card">
<div class="cap-icon">📊</div>
<div>
<div class="cap-name">Real-Time Threat Radar</div>
<div class="cap-desc">Millisecond toxicity, sentiment & hate speech classification</div>
</div>
</div>
<div class="cap-card">
<div class="cap-icon">🧠</div>
<div>
<div class="cap-name">Adversarial AI Firewall</div>
<div class="cap-desc">Hardened defenses against LLM prompt injection & jailbreaks</div>
</div>
</div>
<div class="cap-card">
<div class="cap-icon">🤖</div>
<div>
<div class="cap-name">Botnet & Sybil Defense</div>
<div class="cap-desc">Behavioral graph heuristics identifying astroturfing rings</div>
</div>
</div>
<div class="cap-card">
<div class="cap-icon">🔒</div>
<div>
<div class="cap-name">Zero-Knowledge Privacy</div>
<div class="cap-desc">Automated PII masking with encrypted MongoDB storage</div>
</div>
</div>
</div>
<div class="trust-strip">
<div><span>🔐</span> PBKDF2-HMAC Encryption</div>
<div><span>🛡️</span> NIST AI RMF Compliant</div>
<div><span>⚡</span> Real-Time Heuristics</div>
</div>
""", unsafe_allow_html=True)

    # ─────────────────────────────────────────────────────────────────────────
    # RIGHT PANEL: CLEAN AUTH FORMS WITH ELEGANT TAB SWITCHER & MODERN INPUTS
    # ─────────────────────────────────────────────────────────────────────────
    with col_right:
        with st.container(border=True):
            if is_reset_view:
                # ── RESET PASSWORD VIEW ──
                if st.button("← Back to Sign In", key="back_to_login_btn", type="secondary"):
                    st.session_state["auth_mode"] = "login"
                    st.rerun()
                    
                st.markdown("""
<div class="auth-card-header">
    <div class="card-heading">Reset Password</div>
    <div class="card-subheading">Update your security credentials in MongoDB</div>
</div>
""", unsafe_allow_html=True)
                
                f_email = st.text_input("Registered Email Address", value=st.session_state.get("login_email", ""), placeholder="analyst@threatpulse.io", key="forgot_email_in")
                f_new_pass = st.text_input("New Password", type="password", placeholder="Min 6 characters", key="forgot_new_pass_in")
                f_confirm_pass = st.text_input("Confirm New Password", type="password", placeholder="Re-enter new password", key="forgot_confirm_pass_in")
                
                st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)
                if st.button("Save New Password  →", type="primary", use_container_width=True, key="forgot_submit_btn"):
                    f_email_c = f_email.strip()
                    f_pass_c = f_new_pass.strip()
                    f_cp_c = f_confirm_pass.strip()
                    
                    if not f_email_c:
                        st.error("Please enter your registered email address.")
                    elif not f_pass_c or len(f_pass_c) < 6:
                        st.error("Password must be at least 6 characters long.")
                    elif f_pass_c != f_cp_c:
                        st.error("Passwords do not match.")
                    else:
                        with st.spinner("Updating password in MongoDB..."):
                            res = db.reset_password(f_email_c, f_pass_c)
                        if res["success"]:
                            st.session_state["login_email"] = f_email_c
                            st.session_state["auth_mode"] = "login"
                            st.toast("Password updated! Please sign in with your new password.")
                            st.rerun()
                        else:
                            st.error(res["error"])
                            
            else:
                # Segmented Mode Switcher Tabs
                c_t1, c_t2 = st.columns(2)
                with c_t1:
                    if st.button("🔒  Sign In", key="tab_nav_login", type="primary" if is_login_view else "secondary", use_container_width=True):
                        st.session_state["auth_mode"] = "login"
                        st.rerun()
                with c_t2:
                    if st.button("👤  Create Account", key="tab_nav_register", type="primary" if is_register_view else "secondary", use_container_width=True):
                        st.session_state["auth_mode"] = "register"
                        st.rerun()

                if is_login_view:
                    # ── LOGIN VIEW ──
                    st.markdown("""
<div class="auth-card-header">
    <div class="card-heading">Welcome Back</div>
    <div class="card-subheading">Access the ThreatPulse SOC intelligence console</div>
</div>
""", unsafe_allow_html=True)
                    
                    login_default_email = st.session_state.get("saved_email", "")
                    login_email = st.text_input("Email Address", value=login_default_email, placeholder="analyst@threatpulse.io", key="login_email")
                    login_password = st.text_input("Password", value="", type="password", placeholder="••••••••", key="login_pass")
                    
                    # Remember Me on Left, Clean Forgot Password Link on Right
                    c_rm, c_fp = st.columns([1.1, 1.0])
                    with c_rm:
                        remember_me = st.checkbox("Remember me for 30 days", value=bool(st.session_state.get("saved_email")), key="chk_remember_me")
                    with c_fp:
                        st.markdown('<a href="?mode=reset" target="_self" class="forgot-pass-link">Forgot password?</a>', unsafe_allow_html=True)
                    
                    st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)
                    signin_btn = st.button("Sign In  →", type="primary", use_container_width=True, key="login_submit_btn")
                    
                    if signin_btn:
                        email_clean = (login_email or st.session_state.get("login_email", "")).strip()
                        pass_clean = (login_password or st.session_state.get("login_pass", "")).strip()
                        
                        if not email_clean:
                            st.error("Please enter your email address to sign in.")
                        elif not pass_clean:
                            st.error("Please enter your password.")
                        else:
                            with st.spinner("Authenticating with MongoDB..."):
                                auth_res = db.authenticate_user(email_clean, pass_clean)
                            
                            if auth_res["success"]:
                                user_data = auth_res["user"]
                                if remember_me:
                                    st.session_state["saved_email"] = email_clean
                                else:
                                    st.session_state.pop("saved_email", None)
                                st.session_state["logged_in"] = True
                                st.query_params["session"] = create_session_token(email_clean)
                                st.query_params["auth"] = "1"
                                st.session_state["user_profile"] = user_data
                                st.rerun()
                            else:
                                st.error(auth_res["error"])
                                
                    st.markdown("""
<div class="divider-row">
    <span>or continue with</span>
</div>

<div class="sso-grid">
    <a href="?sso=google" target="_self" class="sso-tile">
        <svg width="18" height="18" viewBox="0 0 24 24">
            <path fill="#4285F4" d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.8-2.4 3.65v3.03h3.88c2.27-2.09 3.665-5.17 3.665-9.12z"/>
            <path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.03c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.25v3.13C3.27 21.43 7.35 24 12 24z"/>
            <path fill="#FBBC05" d="M5.28 14.29c-.25-.72-.38-1.49-.38-2.29s.13-1.57.38-2.29V6.58H1.25C.45 8.18 0 9.99 0 12s.45 3.82 1.25 5.42l4.03-3.13z"/>
            <path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.35 0 3.27 2.57 1.25 6.58l4.03 3.13c.95-2.83 3.6-4.96 6.72-4.96z"/>
        </svg>
        <span>Google</span>
    </a>
    <a href="?sso=github" target="_self" class="sso-tile">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="#FFFFFF">
            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
        </svg>
        <span>GitHub</span>
    </a>
</div>

<div class="auth-card-footer">
    <a href="?mode=register" target="_self" class="footer-cta-link">
        Don't have an account? <span>Create Account →</span>
    </a>
</div>
""", unsafe_allow_html=True)
                    
                else:
                    # ── REGISTRATION VIEW ──
                    st.markdown("""
<div class="auth-card-header">
    <div class="card-heading">Create Account</div>
    <div class="card-subheading">Deploy real-time AI security for your community</div>
</div>
""", unsafe_allow_html=True)
                    
                    name_val = st.text_input("Full Name", value="", placeholder="Dr. Alex Rivera", key="reg_name")
                    email_val = st.text_input("Email Address", value="", placeholder="alex@defense.org", key="reg_email")
                    
                    c_p1, c_p2 = st.columns(2)
                    with c_p1:
                        pass_val = st.text_input("Password", value="", type="password", placeholder="Min 6 characters", key="reg_pass")
                    with c_p2:
                        cpass_val = st.text_input("Confirm Password", value="", type="password", placeholder="Re-enter password", key="reg_cpass")
                        
                    c_r1, c_r2 = st.columns(2)
                    with c_r1:
                        role_val = st.selectbox("Role", ["Student", "Security Researcher", "Data Analyst", "Faculty / Admin"], index=0, key="reg_role")
                    with c_r2:
                        org_val = st.text_input("Organization", value="", placeholder="e.g. ThreatPulse SOC", key="reg_org")
                        
                    agree_terms = st.checkbox("I agree to the Terms of Service and Privacy Policy", value=False, key="reg_terms")
                    agree_updates = st.checkbox("I would like to receive product updates and security alerts", value=True, key="reg_updates")
                    
                    st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)
                    create_btn = st.button("Create Account  →", type="primary", use_container_width=True, key="reg_submit_btn")
                    
                    if create_btn:
                        n_clean = (name_val or st.session_state.get("reg_name", "")).strip()
                        e_clean = (email_val or st.session_state.get("reg_email", "")).strip()
                        p_clean = (pass_val or st.session_state.get("reg_pass", "")).strip()
                        cp_clean = (cpass_val or st.session_state.get("reg_cpass", "")).strip()
                        
                        if not n_clean or not e_clean:
                            st.error("Please enter your name and email address.")
                        elif "@" not in e_clean or "." not in e_clean:
                            st.error("Please enter a valid email address.")
                        elif not p_clean:
                            st.error("Please set a password.")
                        elif len(p_clean) < 6:
                            st.error("Password must be at least 6 characters long.")
                        elif p_clean != cp_clean:
                            st.error("Passwords do not match.")
                        elif not agree_terms:
                            st.error("Please agree to the Terms of Service to continue.")
                        else:
                            with st.spinner("Saving account to MongoDB..."):
                                reg_res = db.create_user(
                                    name=n_clean,
                                    email=e_clean,
                                    password=p_clean,
                                    role=role_val,
                                    org=org_val or "ThreatPulse Defense"
                                )
                            
                            if reg_res["success"]:
                                user_data = reg_res["user"]
                                st.session_state["logged_in"] = True
                                st.query_params["session"] = create_session_token(user_data["email"])
                                st.query_params["auth"] = "1"
                                st.session_state["user_profile"] = user_data
                                st.toast("Account created and securely saved in MongoDB!")
                                st.rerun()
                            else:
                                st.error(reg_res["error"])
                                
                    st.markdown("""
<div class="divider-row">
    <span>or continue with</span>
</div>

<div class="sso-grid">
    <a href="?sso=google" target="_self" class="sso-tile">
        <svg width="18" height="18" viewBox="0 0 24 24">
            <path fill="#4285F4" d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.8-2.4 3.65v3.03h3.88c2.27-2.09 3.665-5.17 3.665-9.12z"/>
            <path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.03c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.25v3.13C3.27 21.43 7.35 24 12 24z"/>
            <path fill="#FBBC05" d="M5.28 14.29c-.25-.72-.38-1.49-.38-2.29s.13-1.57.38-2.29V6.58H1.25C.45 8.18 0 9.99 0 12s.45 3.82 1.25 5.42l4.03-3.13z"/>
            <path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.35 0 3.27 2.57 1.25 6.58l4.03 3.13c.95-2.83 3.6-4.96 6.72-4.96z"/>
        </svg>
        <span>Google</span>
    </a>
    <a href="?sso=github" target="_self" class="sso-tile">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="#FFFFFF">
            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
        </svg>
        <span>GitHub</span>
    </a>
</div>

<div class="auth-card-footer">
    <a href="?mode=login" target="_self" class="footer-cta-link">
        Already have an account? <span>Sign In →</span>
    </a>
</div>
""", unsafe_allow_html=True)

# Backward-compatibility alias
render_registration_page = render_auth_page

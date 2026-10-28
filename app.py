import io
import os
from datetime import datetime, timedelta, timezone
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import core
import importlib
importlib.reload(core)
import db
importlib.reload(db)
import auth
import re
import tabs_views
importlib.reload(auth)
importlib.reload(tabs_views)
from tabs_views import (
    render_phishing_view,
    render_pii_view,
    render_bots_view,
    render_inspector_view,
    render_ai_security_view
)

# ─────────────────────────────────────────────────────────────────────────────
# 1. PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ThreatPulse | Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────────────────────────────────────
# Authentication Guard with Persistent Session Restoration across Browser Refresh
# ─────────────────────────────────────────────────────────────────────────────
if not st.session_state.get("logged_in") or not st.session_state.get("user_profile"):
    session_token = st.query_params.get("session")
    if session_token and hasattr(auth, "verify_session_token"):
        restored_email = auth.verify_session_token(session_token)
        if restored_email:
            user_doc = db.get_user_by_email(restored_email)
            if user_doc:
                st.session_state["logged_in"] = True
                st.session_state["user_profile"] = db.sanitize_user(user_doc)
                st.session_state["saved_email"] = restored_email
            elif "@" in restored_email:
                st.session_state["logged_in"] = True
                st.session_state["user_profile"] = {
                    "name": restored_email.split("@")[0].replace(".", " ").title(),
                    "email": restored_email,
                    "role": "Security Analyst",
                    "org": "ThreatPulse Defense",
                    "auth_provider": "local"
                }

is_authenticated = bool(st.session_state.get("logged_in") and st.session_state.get("user_profile"))
if not is_authenticated:
    st.session_state["logged_in"] = False
    if hasattr(auth, "render_auth_page"):
        auth.render_auth_page()
    else:
        auth.render_registration_page()
    st.stop()

# ─────────────────────────────────────────────────────────────────────────────
# Helper to safely render multi-line HTML without Markdown code-block indentation bugs
def render_html(html_str: str):
    clean = re.sub(r'^[ \t]+', '', html_str, flags=re.MULTILINE)
    st.markdown(clean, unsafe_allow_html=True)

# 2. GLOBAL THEME & STYLES (MATCHING REFERENCE DESIGN)
# ─────────────────────────────────────────────────────────────────────────────
render_html("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

html, body, p, h1, h2, h3, h4, h5, h6, input, textarea, select {
    font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif !important;
}

.stApp {
    background-color: #060B18 !important;
    color: #F8FAFC !important;
}

header[data-testid="stHeader"] {
    background: transparent !important;
}
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
.stDeployButton {display:none;}

.block-container {
    padding-top: 1rem !important;
    padding-bottom: 2.5rem !important;
    max-width: 1560px !important;
}

/* ─────────────────────────────────────────────────────────────
   SIDEBAR & NAVIGATION PILL REDESIGN (MATCHING THREATPULSE TARGET)
   ───────────────────────────────────────────────────────────── */

/* Fix ligature icon fonts from turning into raw text like 'keyboard_doubl...' */
[data-testid="stSidebarCollapseButton"],
button[data-testid="stSidebarCollapseButton"],
[data-testid="collapsedControl"],
header[data-testid="stHeader"] button[kind="header"],
div[data-testid="stSidebarUserContent"] > div:first-child:has(button[aria-label*="sidebar" i]),
button[aria-label*="sidebar" i] {
    display: none !important;
    visibility: hidden !important;
    height: 0 !important;
    width: 0 !important;
    padding: 0 !important;
    margin: 0 !important;
    overflow: hidden !important;
}

/* Sidebar Container */
[data-testid="stSidebar"] {
    background-color: #070D1E !important;
    border-right: 1px solid #14203D !important;
}

[data-testid="stSidebar"] .block-container {
    padding-top: 0.9rem !important;
    padding-bottom: 1.5rem !important;
    padding-left: 0.85rem !important;
    padding-right: 0.85rem !important;
}

/* Navigation Radiogroup Container */
[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-testid="stRadioGroup"],
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] {
    display: flex !important;
    flex-direction: column !important;
    gap: 3px !important;
    margin-top: 2px !important;
    margin-bottom: 6px !important;
}

/* HIDE ONLY THE RADIO CIRCLE (targets the Emotion circle element 'etak9234') */
[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-testid="stRadioOption"] [class*="etak9234"],
[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-testid="stRadioOption"] [class*="etak9235"],
[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-testid="stRadioOption"] input[type="radio"],
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] [class*="etak9234"],
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] [class*="etak9235"],
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] input[type="radio"] {
    display: none !important;
    width: 0 !important;
    height: 0 !important;
    min-width: 0 !important;
    min-height: 0 !important;
    max-width: 0 !important;
    max-height: 0 !important;
    opacity: 0 !important;
    visibility: hidden !important;
    position: absolute !important;
    pointer-events: none !important;
}

/* Ensure the label text container is 100% visible and styled */
[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-testid="stRadioOption"] [data-testid="stMarkdownContainer"],
[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-testid="stRadioOption"] [data-testid="stMarkdownContainer"] p,
[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-testid="stRadioOption"] [class*="etak9233"],
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] [data-testid="stMarkdownContainer"],
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] [data-testid="stMarkdownContainer"] p,
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] [class*="etak9233"] {
    display: flex !important;
    visibility: visible !important;
    opacity: 1 !important;
}

/* Nav Pill Label (Unselected) */
[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-testid="stRadioOption"],
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] [data-testid="stRadioOption"],
[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-baseweb="radio"],
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] [data-baseweb="radio"] {
    display: flex !important;
    align-items: center !important;
    width: 100% !important;
    padding: 10px 14px !important;
    border-radius: 10px !important;
    margin: 1px 0 !important;
    cursor: pointer !important;
    background: transparent !important;
    border: 1px solid transparent !important;
    transition: all 0.18s cubic-bezier(0.4, 0, 0.2, 1) !important;
    box-sizing: border-box !important;
}

/* Nav Pill Hover */
[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-testid="stRadioOption"]:hover,
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] [data-testid="stRadioOption"]:hover {
    background: rgba(255, 255, 255, 0.05) !important;
    border-color: rgba(255, 255, 255, 0.08) !important;
}

[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-testid="stRadioOption"]:hover p,
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] [data-testid="stRadioOption"]:hover p {
    color: #FFFFFF !important;
}

/* Nav Pill Text Layout */
[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-testid="stRadioOption"] p,
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] [data-testid="stRadioOption"] p {
    font-size: 0.94rem !important;
    font-weight: 500 !important;
    color: #94A3B8 !important;
    margin: 0 !important;
    padding: 0 !important;
    display: flex !important;
    align-items: center !important;
    gap: 12px !important;
    line-height: 1.35 !important;
    width: 100% !important;
}

/* Active / Checked Nav Pill (Vibrant Gradient Pill Matching Target Design) */
[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-testid="stRadioOption"]:has(input:checked),
[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-testid="stRadioOption"][data-selected="true"],
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] [data-testid="stRadioOption"]:has(input:checked),
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] [data-testid="stRadioOption"][data-selected="true"],
[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-baseweb="radio"]:has(input:checked),
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] [data-baseweb="radio"]:has(input:checked) {
    background: linear-gradient(90deg, #0066FF 0%, #0052CC 100%) !important;
    box-shadow: 0 4px 16px rgba(0, 102, 255, 0.42) !important;
    border: 1px solid rgba(255, 255, 255, 0.18) !important;
}

[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-testid="stRadioOption"]:has(input:checked) p,
[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-testid="stRadioOption"][data-selected="true"] p,
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] [data-testid="stRadioOption"]:has(input:checked) p,
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] [data-testid="stRadioOption"][data-selected="true"] p,
[data-testid="stSidebar"] [data-testid="stRadio"]:first-of-type [data-baseweb="radio"]:has(input:checked) p,
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Navigation"] [data-baseweb="radio"]:has(input:checked) p {
    color: #FFFFFF !important;
    font-weight: 700 !important;
}

/* ─────────────────────────────────────────────────────────────
   DATA INGESTION SECTION STYLING
   ───────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Feed Source"],
[data-testid="stSidebar"] [data-testid="stRadio"]:nth-of-type(2) div[role="radiogroup"] {
    gap: 4px !important;
    display: flex !important;
    flex-direction: column !important;
}

[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Feed Source"] label,
[data-testid="stSidebar"] [data-testid="stRadio"]:nth-of-type(2) div[role="radiogroup"] label {
    padding: 7px 10px !important;
    border-radius: 8px !important;
    background: transparent !important;
    border: 1px solid transparent !important;
    transition: all 0.15s ease !important;
    cursor: pointer !important;
}

[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Feed Source"] label:hover,
[data-testid="stSidebar"] [data-testid="stRadio"]:nth-of-type(2) div[role="radiogroup"] label:hover {
    background: rgba(255, 255, 255, 0.04) !important;
}

[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Feed Source"] label p,
[data-testid="stSidebar"] [data-testid="stRadio"]:nth-of-type(2) div[role="radiogroup"] label p {
    font-size: 0.88rem !important;
    color: #94A3B8 !important;
    font-weight: 500 !important;
    margin: 0 !important;
}

[data-testid="stSidebar"] div[role="radiogroup"][aria-label="Feed Source"] label:has(input:checked) p,
[data-testid="stSidebar"] [data-testid="stRadio"]:nth-of-type(2) div[role="radiogroup"] label:has(input:checked) p {
    color: #FFFFFF !important;
    font-weight: 600 !important;
}

/* ─────────────────────────────────────────────────────────────
   SIDEBAR BOTTOM UTILITY BUTTONS
   ───────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] button[key="sidebar_btn_settings"],
[data-testid="stSidebar"] div:has(> button[key="sidebar_btn_settings"]) button {
    background: transparent !important;
    border: none !important;
    color: #94A3B8 !important;
    text-align: left !important;
    justify-content: flex-start !important;
    font-weight: 500 !important;
    padding: 9px 12px !important;
    border-radius: 8px !important;
    font-size: 0.92rem !important;
    box-shadow: none !important;
    transition: all 0.15s ease !important;
}

[data-testid="stSidebar"] button[key="sidebar_btn_settings"]:hover,
[data-testid="stSidebar"] div:has(> button[key="sidebar_btn_settings"]) button:hover {
    background: rgba(255, 255, 255, 0.05) !important;
    color: #FFFFFF !important;
}

[data-testid="stSidebar"] button[key="sidebar_btn_logout"],
[data-testid="stSidebar"] div:has(> button[key="sidebar_btn_logout"]) button {
    background: transparent !important;
    border: none !important;
    color: #EF4444 !important;
    text-align: left !important;
    justify-content: flex-start !important;
    font-weight: 600 !important;
    padding: 9px 12px !important;
    border-radius: 8px !important;
    font-size: 0.92rem !important;
    box-shadow: none !important;
    transition: all 0.15s ease !important;
}

[data-testid="stSidebar"] button[key="sidebar_btn_logout"]:hover,
[data-testid="stSidebar"] div:has(> button[key="sidebar_btn_logout"]) button:hover {
    background: rgba(239, 68, 68, 0.12) !important;
    color: #F87171 !important;
}

/* ─────────────────────────────────────────────────────────────
   INTERACTIVE TOP NAVBAR CONTAINER & WIDGETS
   ───────────────────────────────────────────────────────────── */
.st-key-top_navbar,
div[class*="st-key-top_navbar"] {
    background: #0B132B !important;
    border: 1px solid #1A264D !important;
    border-radius: 12px !important;
    padding: 6px 14px !important;
    margin-bottom: 1.25rem !important;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25) !important;
}

div[class*="st-key-top_navbar"] [data-testid="stHorizontalBlock"] {
    align-items: center !important;
    gap: 8px !important;
}

/* Global search input in navbar */
div[class*="st-key-top_navbar"] [data-testid="stTextInput"] {
    margin-bottom: 0 !important;
}
div[class*="st-key-top_navbar"] [data-testid="stTextInput"] input {
    background-color: #060B18 !important;
    border: 1px solid #1E2D5A !important;
    border-radius: 8px !important;
    color: #F8FAFC !important;
    font-size: 0.85rem !important;
    height: 38px !important;
    min-height: 38px !important;
    padding-left: 12px !important;
    box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.3) !important;
    transition: all 0.15s ease !important;
}
div[class*="st-key-top_navbar"] [data-testid="stTextInput"] input:focus {
    border-color: #0066FF !important;
    box-shadow: 0 0 0 1px #0066FF !important;
}
div[class*="st-key-top_navbar"] [data-testid="stTextInput"] input::placeholder {
    color: #64748B !important;
}

/* Date filter dropdown in navbar */
div[class*="st-key-top_navbar"] [data-testid="stSelectbox"] {
    margin-bottom: 0 !important;
}
div[class*="st-key-top_navbar"] [data-testid="stSelectbox"] div[data-baseweb="select"] > div {
    background-color: #0B132B !important;
    border: 1px solid #1E293B !important;
    border-radius: 8px !important;
    color: #E2E8F0 !important;
    font-weight: 600 !important;
    font-size: 0.84rem !important;
    height: 38px !important;
    min-height: 38px !important;
    cursor: pointer !important;
    padding-left: 10px !important;
}
div[class*="st-key-top_navbar"] [data-testid="stSelectbox"] svg {
    fill: #94A3B8 !important;
}

/* Popovers & Buttons in navbar */
div[class*="st-key-top_navbar"] [data-testid="stPopover"],
div[class*="st-key-top_navbar"] [data-testid="stElementContainer"]:has(button) {
    margin-bottom: 0 !important;
}
div[class*="st-key-top_navbar"] [data-testid="stPopover"] button,
div[class*="st-key-top_navbar"] button[data-testid="baseButton-secondary"] {
    background-color: #0B132B !important;
    border: 1px solid #1E293B !important;
    border-radius: 8px !important;
    color: #E2E8F0 !important;
    font-size: 0.84rem !important;
    font-weight: 600 !important;
    height: 38px !important;
    min-height: 38px !important;
    padding: 0 12px !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    gap: 6px !important;
    box-shadow: none !important;
    transition: all 0.15s ease !important;
}
div[class*="st-key-top_navbar"] [data-testid="stPopover"] button:hover,
div[class*="st-key-top_navbar"] button[data-testid="baseButton-secondary"]:hover {
    background-color: #14203D !important;
    border-color: #2E4275 !important;
    color: #FFFFFF !important;
}

/* User profile button styling */
div[class*="st-key-nav_user_pop"] button::before {
    content: "R";
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    background: #6366F1;
    color: white;
    border-radius: 50%;
    font-size: 0.72rem;
    font-weight: 800;
    margin-right: 6px;
    box-shadow: 0 2px 6px rgba(99, 102, 241, 0.4);
}

/* Popover floating container dark styling */
div[data-testid="stPopoverBody"] {
    background-color: #0B132B !important;
    border: 1px solid #1E2D5A !important;
    border-radius: 12px !important;
    box-shadow: 0 12px 36px rgba(0, 0, 0, 0.65) !important;
    padding: 14px !important;
    color: #E2E8F0 !important;
}

div[data-baseweb="menu"],
ul[data-baseweb="menu"] {
    background-color: #0B132B !important;
    border: 1px solid #1E2D5A !important;
    border-radius: 8px !important;
}
div[data-baseweb="menu"] li,
ul[data-baseweb="menu"] li {
    background-color: #0B132B !important;
    color: #CBD5E1 !important;
    font-size: 0.84rem !important;
}
div[data-baseweb="menu"] li:hover,
ul[data-baseweb="menu"] li:hover,
div[data-baseweb="menu"] li[aria-selected="true"],
ul[data-baseweb="menu"] li[aria-selected="true"] {
    background-color: #16264C !important;
    color: #FFFFFF !important;
}

/* DASHBOARD HEADER */
.tp-header-row {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    margin-bottom: 1.25rem;
}
.tp-page-title {
    font-size: 1.65rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    color: #FFFFFF;
    line-height: 1.1;
    margin-bottom: 4px;
}
.tp-page-sub {
    font-size: 0.85rem;
    color: #94A3B8;
}

/* 5 KPI CARDS ROW */
.kpi-deck {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin-bottom: 1.25rem;
}
.kpi-card-ref {
    background: #0B132B;
    border: 1px solid #1A264D;
    border-radius: 12px;
    padding: 1rem 1.15rem;
    position: relative;
    overflow: hidden;
    transition: transform 0.15s ease, border-color 0.15s ease;
}
.kpi-card-ref:hover {
    transform: translateY(-2px);
    border-color: #2563EB;
}
.kpi-top {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    margin-bottom: 8px;
}
.kpi-icon-pill {
    width: 40px;
    height: 40px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.15rem;
    flex-shrink: 0;
}
.kpi-blue-icon   { background: #0066FF; color: white; }
.kpi-red-icon    { background: #E11D48; color: white; }
.kpi-amber-icon  { background: #D97706; color: white; }
.kpi-pink-icon   { background: #DB2777; color: white; }
.kpi-purple-icon { background: #7C3AED; color: white; }

.kpi-stat-num {
    font-size: 1.75rem;
    font-weight: 800;
    line-height: 1;
}
.kpi-stat-label {
    font-size: 0.82rem;
    font-weight: 700;
    color: #FFFFFF;
    margin-top: 3px;
}
.kpi-stat-desc {
    font-size: 0.72rem;
    color: #94A3B8;
}
.kpi-bottom-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 10px;
}
.kpi-trend {
    font-size: 0.75rem;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 3px;
}

/* ── SUB-TABS ROW ── */
div[data-testid="stTabs"] [role="tablist"] {
    gap: 6px !important;
    background: #0B132B !important;
    border: 1px solid #1A264D !important;
    border-radius: 10px !important;
    padding: 6px !important;
    margin-bottom: 1.25rem !important;
}
div[data-testid="stTabs"] button[role="tab"] {
    border-radius: 8px !important;
    padding: 7px 16px !important;
    font-weight: 600 !important;
    font-size: 0.84rem !important;
    color: #94A3B8 !important;
    background: transparent !important;
    border: none !important;
    transition: all 0.15s ease !important;
}
div[data-testid="stTabs"] button[role="tab"]:hover {
    color: #FFFFFF !important;
    background: rgba(255, 255, 255, 0.04) !important;
}
div[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
    background: #0066FF !important;
    color: #FFFFFF !important;
    box-shadow: 0 2px 8px rgba(0, 102, 255, 0.4) !important;
}

/* ── CONTENT CARDS ── */
.tp-card {
    background: #0B132B;
    border: 1px solid #1A264D;
    border-radius: 12px;
    padding: 1.25rem 1.4rem;
    margin-bottom: 1.25rem;
}
.tp-card-title {
    font-size: 0.98rem;
    font-weight: 700;
    color: #FFFFFF;
    margin-bottom: 3px;
}
.tp-card-sub {
    font-size: 0.78rem;
    color: #94A3B8;
    margin-bottom: 12px;
}

/* Container Border Wrapper Override */
div[data-testid="stVerticalBlockBorderWrapper"] > div {
    background: #0B132B !important;
    border: 1px solid #1A264D !important;
    border-radius: 12px !important;
}

/* Download / Export Button Override */
.stDownloadButton button {
    background: #0B132B !important;
    border: 1px solid #1E293B !important;
    border-radius: 8px !important;
    color: #E2E8F0 !important;
    font-size: 0.84rem !important;
    font-weight: 600 !important;
    padding: 7px 16px !important;
    transition: all 0.2s ease !important;
}
.stDownloadButton button:hover {
    border-color: #3B82F6 !important;
    color: #FFFFFF !important;
    box-shadow: 0 0 10px rgba(59, 130, 246, 0.2) !important;
}

/* ── SENTIMENT KPI CARDS ── */
.sent-kpi-deck {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 20px;
}
.sent-kpi {
    background: #0B132B;
    border-radius: 12px;
    padding: 1.15rem 1.25rem;
    position: relative;
    overflow: hidden;
}
.sent-kpi-top {
    display: flex;
    align-items: flex-start;
    gap: 12px;
}
.s-icon {
    width: 44px;
    height: 44px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
}
.s-num {
    font-size: 1.85rem;
    font-weight: 800;
    line-height: 1;
}
.s-label {
    font-size: 0.88rem;
    font-weight: 700;
    color: #FFFFFF;
    margin-top: 4px;
}
.s-sub {
    font-size: 0.74rem;
    color: #94A3B8;
    margin-top: 2px;
}
.s-bottom {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 14px;
}

/* Badges */
.pill-pos { background: #10B981 !important; color: #FFFFFF !important; padding: 4px 14px !important; border-radius: 6px !important; font-size: 0.75rem !important; font-weight: 700 !important; display: inline-block; }
.pill-neg { background: #EF4444 !important; color: #FFFFFF !important; padding: 4px 14px !important; border-radius: 6px !important; font-size: 0.75rem !important; font-weight: 700 !important; display: inline-block; }
.pill-neu { background: #1E293B !important; color: #CBD5E1 !important; border: 1px solid #334155 !important; padding: 4px 14px !important; border-radius: 6px !important; font-size: 0.75rem !important; font-weight: 600 !important; display: inline-block; }
.pill-sev { background: #EF4444 !important; color: #FFFFFF !important; padding: 4px 14px !important; border-radius: 6px !important; font-size: 0.75rem !important; font-weight: 700 !important; display: inline-block; }
.pill-mod { background: #F59E0B !important; color: #FFFFFF !important; padding: 4px 14px !important; border-radius: 6px !important; font-size: 0.75rem !important; font-weight: 700 !important; display: inline-block; }
.pill-mil { background: #0284C7 !important; color: #FFFFFF !important; padding: 4px 14px !important; border-radius: 6px !important; font-size: 0.75rem !important; font-weight: 700 !important; display: inline-block; }
.pill-cle { background: #10B981 !important; color: #FFFFFF !important; padding: 4px 14px !important; border-radius: 6px !important; font-size: 0.75rem !important; font-weight: 700 !important; display: inline-block; }
.pill-tag { background: rgba(255,255,255,0.06); border: 1px solid #1E293B; color: #CBD5E1; padding: 3px 10px; border-radius: 5px; font-size: 0.72rem; font-weight: 600; display: inline-block; margin-right: 4px; }
.pill-tox { background: rgba(239,68,68,0.25); color: #F87171; border: 1px solid rgba(239,68,68,0.5); padding: 2px 8px; border-radius: 5px; font-size: 0.72rem; font-weight: 700; }
.pill-phi { background: rgba(236,72,153,0.25); color: #F472B6; border: 1px solid rgba(236,72,153,0.5); padding: 2px 8px; border-radius: 5px; font-size: 0.72rem; font-weight: 700; }
.pill-action-block { background: rgba(239,68,68,0.2) !important; color: #EF4444 !important; border: 1px solid rgba(239,68,68,0.5) !important; padding: 2px 8px !important; border-radius: 5px !important; font-size: 0.72rem !important; font-weight: 700 !important; display: inline-block; }
.pill-action-warn { background: rgba(245,158,11,0.2) !important; color: #F59E0B !important; border: 1px solid rgba(245,158,11,0.5) !important; padding: 2px 8px !important; border-radius: 5px !important; font-size: 0.72rem !important; font-weight: 700 !important; display: inline-block; }
.pill-action-allow { background: rgba(16,185,129,0.2) !important; color: #10B981 !important; border: 1px solid rgba(16,185,129,0.5) !important; padding: 2px 8px !important; border-radius: 5px !important; font-size: 0.72rem !important; font-weight: 700 !important; display: inline-block; }
.pill-none{ background: rgba(100,116,139,0.2); color: #94A3B8; border: 1px solid rgba(100,116,139,0.35); padding: 2px 8px; border-radius: 5px; font-size: 0.72rem; font-weight: 700; }

/* Table Styling */
.table-wrap {
    width: 100%;
    overflow-x: auto;
}
.tp-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
}
.tp-table th {
    text-align: left;
    padding: 10px 12px;
    background: #070D1E;
    color: #94A3B8;
    font-weight: 600;
    font-size: 0.75rem;
    border-bottom: 1px solid #1A264D;
}
.tp-table td {
    padding: 11px 12px;
    border-bottom: 1px solid #141E3D;
    color: #F1F5F9;
    vertical-align: middle;
}
.tp-table tr:hover td {
    background: #0F1A3B;
}

/* Custom button overrides */
.stButton button[kind="primary"] {
    background: linear-gradient(90deg, #0066FF 0%, #0099FF 100%) !important;
    border: none !important;
    border-radius: 8px !important;
    color: white !important;
    font-weight: 700 !important;
    box-shadow: 0 2px 10px rgba(0, 102, 255, 0.4) !important;
}
</style>
""")

# ─────────────────────────────────────────────────────────────────────────────
# 3. SIDEBAR (MATCHING REFERENCE DESIGN)
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    render_html("""
<div style="display:flex; align-items:center; gap:12px; padding: 0.2rem 0 1.2rem 0; margin-bottom:2px;">
<div style="width:40px; height:40px; background:linear-gradient(135deg, #0284C7, #0066FF); border-radius:12px; display:flex; align-items:center; justify-content:center; font-size:1.3rem; box-shadow:0 0 16px rgba(0,102,255,0.45); flex-shrink:0;">🛡️</div>
<div>
<div style="font-weight:800; font-size:1.18rem; color:#FFFFFF; line-height:1.15; letter-spacing:-0.02em;">Threat<span style="color:#0EA5E9;">Pulse</span></div>
<div style="font-size:0.68rem; color:#94A3B8; margin-top:2px; line-height:1.25; font-weight:500;">Social Media Threat Analytics &amp;<br>AI Security Engine</div>
</div>
</div>
""")

    # Main Navigation Selector
    st.markdown('<div class="nav-radio-hook"></div>', unsafe_allow_html=True)
    nav_item = st.radio(
        "Navigation",
        [
            "🏠 Dashboard",
            "📊 Sentiment",
            "☠️ Toxicity",
            "🔗 Phishing",
            "🔒 PII & Privacy",
            "🤖 Bots",
            "🔍 Inspector",
            "🧪 AI Security"
        ],
        label_visibility="collapsed"
    )


    st.markdown("<hr style='border:none; border-top:1px solid #16203B; margin: 0.8rem 0 0.5rem 0;'>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:0.75rem; font-weight:700; color:#64748B; text-transform:uppercase; letter-spacing:0.06em; margin-bottom:8px; display:flex; align-items:center; gap:8px;'><span>🗄️</span> DATA INGESTION</div>", unsafe_allow_html=True)

    source = st.radio(
        "Feed Source",
        ["Demo Feed (22 Posts)", "Live Reddit Feed", "Upload CSV Dataset"],
        label_visibility="collapsed"
    )

    df_raw = None

    if source.startswith("Demo Feed"):
        df_raw = core.sample_data()

    elif source == "Live Reddit Feed":
        sub_preset = st.selectbox("Subreddit Preset", ["cybersecurity", "technology", "cryptocurrency", "Custom..."])
        subreddit = st.text_input("Name", value="artificial") if sub_preset == "Custom..." else sub_preset
        limit = st.slider("Posts Count", 10, 60, 25)
        if st.button("Fetch Posts", type="primary"):
            with st.spinner(f"Scraping r/{subreddit}..."):
                try:
                    rdf = core.fetch_reddit(subreddit, limit=limit)
                    st.session_state["reddit_feed"] = rdf
                    st.success(f"Loaded {len(rdf)} posts.")
                except Exception as e:
                    st.error(str(e))
        df_raw = st.session_state.get("reddit_feed")

    else:
        uploaded_file = st.file_uploader("Upload CSV", type=["csv"], label_visibility="collapsed")
        if st.button("Load Benchmark (60 Posts)"):
            try:
                bdf = pd.read_csv("datasets/social_threat_benchmark.csv")
                bdf["time"] = pd.to_datetime(bdf["time"])
                bdf["account_created"] = pd.to_datetime(bdf["account_created"])
                st.session_state["csv_feed"] = bdf
                st.success("Loaded.")
            except Exception as e:
                st.error(str(e))

        if uploaded_file:
            try:
                tdf = pd.read_csv(uploaded_file)
                text_cols = ["text", "comment", "message", "tweet", "post_text", "body", "post"]
                found_col = next((c for c in text_cols if c in tdf.columns), None)
                if found_col:
                    tdf["text"] = tdf[found_col].astype(str)
                    now_ts = pd.Timestamp.now()
                    tdf["author"] = tdf.get("author", [f"user_{i}" for i in range(len(tdf))])
                    tdf["time"] = pd.to_datetime(tdf.get("time", now_ts), errors="coerce").fillna(now_ts)
                    tdf["account_created"] = pd.to_datetime(tdf.get("account_created", now_ts - pd.Timedelta(days=120)), errors="coerce").fillna(now_ts - pd.Timedelta(days=120))
                    st.session_state["csv_feed"] = tdf
                    st.success(f"Loaded {len(tdf)} records.")
            except Exception as e:
                st.error(str(e))
        df_raw = st.session_state.get("csv_feed")

    st.markdown("<hr style='border:none; border-top:1px solid #16203B; margin: 0.8rem 0 0.5rem 0;'>", unsafe_allow_html=True)
    
    # Bottom Sidebar Utility Links (Matching target reference design)
    if st.button("⚙️   Settings", use_container_width=True, key="sidebar_btn_settings"):
        db_ok, db_msg = db.check_db_connection()
        st.toast(f"Database: {db_msg} | Settings loaded from .env")
    if st.button("🚪   Logout", use_container_width=True, key="sidebar_btn_logout"):
        st.session_state["logged_in"] = False
        if "session" in st.query_params:
            del st.query_params["session"]
        if "auth" in st.query_params:
            del st.query_params["auth"]
        if "user_profile" in st.session_state:
            del st.session_state["user_profile"]
        st.rerun()

if df_raw is None or df_raw.empty:
    st.info("👈 Please select a data source from the sidebar to populate the security dashboard.")
    st.stop()

# ─────────────────────────────────────────────────────────────────────────────
# 4. EXECUTE PIPELINE & METRICS
# ─────────────────────────────────────────────────────────────────────────────
with st.spinner("Analyzing feed threats..."):
    analyzed_df = core.analyze(df_raw)
    bot_df = core.bot_scores(df_raw)

total_posts = len(analyzed_df)
threats_identified = int(analyzed_df["flagged"].sum())
toxic_posts = int((analyzed_df["toxicity"] >= 0.5).sum())
malicious_urls = int((analyzed_df["link_risk"] >= 50).sum())
suspected_bots = int((bot_df["bot_score"] >= 60).sum())
pii_count = int((analyzed_df["pii"].apply(len) > 0).sum())

# Helpers for Plotly charts in dark mode
def make_dark_chart_layout(title=""):
    return dict(
        title=dict(text=title, font=dict(family="Plus Jakarta Sans", size=13, color="#FFFFFF")),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Plus Jakarta Sans", color="#94A3B8", size=11),
        margin=dict(t=35, b=25, l=35, r=20),
        xaxis=dict(showgrid=False, zeroline=False, linecolor="#1A264D", color="#94A3B8"),
        yaxis=dict(showgrid=True, gridcolor="#16203B", zeroline=False, linecolor="#1A264D", color="#94A3B8"),
        legend=dict(font=dict(color="#94A3B8", size=11))
    )

buf_csv = io.StringIO()
analyzed_df.drop(columns=["urls", "pii"], errors="ignore").to_csv(buf_csv, index=False)

# ─────────────────────────────────────────────────────────────────────────────
# 5. TOP NAVBAR (GLOBAL & FULLY INTERACTIVE)
# ─────────────────────────────────────────────────────────────────────────────
user_prof = st.session_state.get("user_profile", {"name": "Rajnish", "role": "Security Analyst"})
first_name = user_prof.get("name", "Rajnish").split(" ")[0]

with st.container(key="top_navbar"):
    col_nav_search, col_nav_space, col_nav_date, col_nav_bell, col_nav_theme, col_nav_user = st.columns(
        [4.4, 0.2, 2.1, 0.9, 0.7, 2.1],
        gap="small",
        vertical_alignment="center"
    )
    
    # 1. Real Interactive Global Search Bar
    search_kw = col_nav_search.text_input(
        "Search posts, users, or keywords...",
        value=st.session_state.get("global_threat_search", ""),
        placeholder="🔍  Search posts, users, or keywords...",
        label_visibility="collapsed",
        key="global_threat_search"
    )
    
    # 2. Real Interactive Date Range Filter
    date_filter = col_nav_date.selectbox(
        "Time Range",
        ["📅 Last 7 Days", "📅 Last 24 Hours", "📅 Last 30 Days", "📅 All Time"],
        index=st.session_state.get("date_filter_idx", 0),
        label_visibility="collapsed",
        key="nav_date_filter_select"
    )
    
    # 3. Real Interactive Threat Notifications Popover
    num_threats = int((analyzed_df["flagged"] == True).sum()) if "flagged" in analyzed_df.columns else 3
    unread_alerts = st.session_state.get("unread_alerts_count", max(1, min(3, num_threats)))
    bell_label = f"🔔 {unread_alerts}" if unread_alerts > 0 else "🔔"
    
    with col_nav_bell.popover(bell_label, use_container_width=True, help="Threat Alerts & Notifications"):
        st.markdown("<div style='font-weight:700; font-size:0.95rem; color:#FFFFFF; margin-bottom:4px;'>🔔 Security Threat Alerts</div>", unsafe_allow_html=True)
        st.caption(f"{unread_alerts} active threats requiring SOC analyst review")
        st.markdown("<hr style='border:none; border-top:1px solid #1E293B; margin:8px 0 12px 0;'>", unsafe_allow_html=True)
        
        st.markdown('''
        <div style="background:#15102A; border-left:3px solid #EF4444; border-radius:6px; padding:9px 12px; margin-bottom:8px;">
            <div style="font-size:0.8rem; font-weight:700; color:#F87171; display:flex; justify-content:space-between;">
                <span>🚨 Malicious Phishing Campaign</span>
                <span style="font-size:0.7rem; color:#EF4444;">HIGH</span>
            </div>
            <div style="font-size:0.75rem; color:#CBD5E1; margin-top:2px;">Suspicious URL <code>bit.ly/claim-bonus-2024</code> flagged with 95% threat score.</div>
            <div style="font-size:0.68rem; color:#64748B; margin-top:4px;">Target: Credential Harvester • 4 mins ago</div>
        </div>
        <div style="background:#1A1524; border-left:3px solid #F59E0B; border-radius:6px; padding:9px 12px; margin-bottom:8px;">
            <div style="font-size:0.8rem; font-weight:700; color:#FBBF24; display:flex; justify-content:space-between;">
                <span>🔒 PII Exposure Detected</span>
                <span style="font-size:0.7rem; color:#F59E0B;">MEDIUM</span>
            </div>
            <div style="font-size:0.75rem; color:#CBD5E1; margin-top:2px;">Indian Aadhaar identification number detected in public feed post.</div>
            <div style="font-size:0.68rem; color:#64748B; margin-top:4px;">Author: @carol_fin • 18 mins ago</div>
        </div>
        <div style="background:#0F1D36; border-left:3px solid #3B82F6; border-radius:6px; padding:9px 12px; margin-bottom:12px;">
            <div style="font-size:0.8rem; font-weight:700; color:#60A5FA; display:flex; justify-content:space-between;">
                <span>🤖 Bot Cluster Velocity Spike</span>
                <span style="font-size:0.7rem; color:#60A5FA;">INFO</span>
            </div>
            <div style="font-size:0.75rem; color:#CBD5E1; margin-top:2px;">Burst rate of 8 duplicate posts/min detected from bot cluster.</div>
            <div style="font-size:0.68rem; color:#64748B; margin-top:4px;">Account: @bot_network_3 • 32 mins ago</div>
        </div>
        ''', unsafe_allow_html=True)
        
        c_btn1, c_btn2 = st.columns(2)
        with c_btn1:
            if st.button("Mark All Read", key="nav_clear_alerts_btn", use_container_width=True):
                st.session_state["unread_alerts_count"] = 0
                st.rerun()
        with c_btn2:
            if st.button("Reset Alerts", key="nav_reset_alerts_btn", use_container_width=True):
                st.session_state["unread_alerts_count"] = 3
                st.rerun()
                
    # 4. Real Interactive Theme / SOC Defense Mode Toggle
    current_theme = st.session_state.get("theme_mode", "Dark SOC")
    theme_icon = "☀️" if current_theme == "Dark SOC" else "⚡"
    if col_nav_theme.button(theme_icon, help="Toggle Theme / SOC Glow Mode", key="nav_theme_toggle_btn", use_container_width=True):
        if current_theme == "Dark SOC":
            st.session_state["theme_mode"] = "Cyber Glow"
            st.toast("⚡ Cyber Glow Mode activated!")
        else:
            st.session_state["theme_mode"] = "Dark SOC"
            st.toast("🛡️ Standard Dark SOC Mode active!")
        st.rerun()
        
    # 5. Real Interactive User Profile Popover
    with col_nav_user.popover(f"{first_name}", use_container_width=True, help="Analyst Profile & Session"):
        user_email = user_prof.get('email', 'analyst@threatpulse.io')
        user_role = user_prof.get('role', 'Security Analyst')
        user_org = user_prof.get('org', 'ThreatPulse Defense')
        db_connected, db_status = db.check_db_connection()
        db_badge = '<span style="color:#10B981; font-weight:600;">● MongoDB Active</span>' if db_connected else '<span style="color:#F59E0B; font-weight:600;">● Local Cache</span>'
        
        st.markdown(f'''
        <div style="display:flex; align-items:center; gap:12px; margin-bottom:12px;">
            <div style="width:40px; height:40px; border-radius:50%; background:#6366F1; color:white; display:flex; align-items:center; justify-content:center; font-weight:800; font-size:1.1rem; flex-shrink:0;">
                {first_name[:1].upper()}
            </div>
            <div>
                <div style="font-weight:700; color:#FFFFFF; font-size:0.95rem;">{user_prof.get('name', 'Analyst')}</div>
                <div style="font-size:0.75rem; color:#10B981; font-weight:600;">● Active SOC Session</div>
            </div>
        </div>
        <div style="font-size:0.8rem; color:#94A3B8; line-height:1.6; margin-bottom:12px;">
            <div><b>Email:</b> {user_email}</div>
            <div><b>Role:</b> {user_role}</div>
            <div><b>Organization:</b> {user_org}</div>
            <div><b>Database:</b> {db_badge}</div>
            <div><b>Sessions:</b> {user_prof.get('login_count', 1)} active logins logged</div>
            <div><b>Engine:</b> ThreatPulse v2.4 (Active)</div>
        </div>
        <hr style="border:none; border-top:1px solid #1E293B; margin:8px 0 12px 0;">
        ''', unsafe_allow_html=True)
        
        with st.expander("👤 Edit Profile (MongoDB)", expanded=False):
            new_name = st.text_input("Name", value=user_prof.get("name", ""), key="pop_edit_name")
            roles = ["Student", "Security Analyst", "Security Researcher", "Data Analyst", "Faculty / Admin"]
            cur_role = user_prof.get("role", "Security Analyst")
            r_idx = roles.index(cur_role) if cur_role in roles else 0
            new_role = st.selectbox("Role", roles, index=r_idx, key="pop_edit_role")
            new_org = st.text_input("Organization", value=user_prof.get("org", ""), key="pop_edit_org")
            if st.button("Save to MongoDB", type="primary", use_container_width=True, key="pop_save_profile"):
                res = db.update_user_profile(user_email, name=new_name, role=new_role, org=new_org)
                if res["success"]:
                    st.session_state["user_profile"] = res["user"]
                    st.toast("Profile updated in MongoDB!")
                    st.rerun()
                else:
                    st.error(res["error"])
        
        st.markdown("<div style='height:6px;'></div>", unsafe_allow_html=True)
        st.download_button(
            "📥 Export Threat Audit CSV",
            data=buf_csv.getvalue(),
            file_name="threatpulse_audit_report.csv",
            mime="text/csv",
            use_container_width=True,
            key="nav_profile_csv_dl"
        )
        if st.button("🚪 Logout Analyst Session", use_container_width=True, key="nav_user_logout_btn"):
            st.session_state["logged_in"] = False
            if "session" in st.query_params:
                del st.query_params["session"]
            if "auth" in st.query_params:
                del st.query_params["auth"]
            if "user_profile" in st.session_state:
                del st.session_state["user_profile"]
            st.rerun()

# ─────────────────────────────────────────────────────────────────────────────
# REAL DATA FILTERING DRIVEN BY NAVBAR
# ─────────────────────────────────────────────────────────────────────────────
raw_total_posts = len(analyzed_df)

# Date filter
if "time" in analyzed_df.columns and not analyzed_df.empty:
    try:
        time_series = pd.to_datetime(analyzed_df["time"], errors="coerce")
        now_dt = datetime.now(timezone.utc) if time_series.dt.tz is not None else datetime.now()
        if "24 Hours" in date_filter:
            analyzed_df = analyzed_df[time_series >= (now_dt - timedelta(hours=24))]
        elif "7 Days" in date_filter:
            analyzed_df = analyzed_df[time_series >= (now_dt - timedelta(days=7))]
        elif "30 Days" in date_filter:
            analyzed_df = analyzed_df[time_series >= (now_dt - timedelta(days=30))]
    except Exception:
        pass

# Search filter
search_active = bool(search_kw.strip())
if search_active:
    kw = search_kw.strip().lower()
    match_mask = (
        analyzed_df["text"].str.lower().str.contains(kw, na=False) |
        analyzed_df["author"].str.lower().str.contains(kw, na=False) |
        analyzed_df["urls"].astype(str).str.lower().str.contains(kw, na=False) |
        analyzed_df["pii"].astype(str).str.lower().str.contains(kw, na=False)
    )
    analyzed_df = analyzed_df[match_mask]
    
    c_banner, c_clear = st.columns([5, 1])
    with c_banner:
        st.markdown(f'''
        <div style="background:rgba(0, 102, 255, 0.12); border:1px solid rgba(0, 102, 255, 0.35); border-radius:8px; padding:7px 14px; margin-bottom:12px; font-size:0.85rem; color:#93C5FD; display:flex; align-items:center; gap:8px;">
            <span>🔍</span>
            <span>Search Filter: <b>{len(analyzed_df)}</b> of <b>{raw_total_posts}</b> posts matched "<b>{search_kw.strip()}</b>" ({date_filter})</span>
        </div>
        ''', unsafe_allow_html=True)
    with c_clear:
        if st.button("❌ Clear", key="nav_clear_search_btn", use_container_width=True):
            st.session_state["global_threat_search"] = ""
            st.rerun()

# Update metrics based on active subset
total_posts = len(analyzed_df)
threats_identified = int(analyzed_df["flagged"].sum()) if not analyzed_df.empty else 0
toxic_posts = int((analyzed_df["toxicity"] >= 0.5).sum()) if not analyzed_df.empty else 0
malicious_urls = int((analyzed_df["link_risk"] >= 50).sum()) if not analyzed_df.empty else 0
pii_count = int((analyzed_df["pii"].apply(len) > 0).sum()) if not analyzed_df.empty else 0

if analyzed_df.empty:
    st.warning(f"No posts matched your search '{search_kw.strip()}' in the selected time window ({date_filter}).")
    if st.button("Reset Search & Date Filters", key="reset_empty_filters_btn"):
        st.session_state["global_threat_search"] = ""
        st.session_state["nav_date_filter_select"] = "📅 Last 7 Days"
        st.rerun()
    st.stop()


# ─────────────────────────────────────────────────────────────────────────────
# DEDICATED SENTIMENT VIEW (1:1 PIXEL PERFECT MATCH WITH TARGET DESIGN)
# ─────────────────────────────────────────────────────────────────────────────
def render_sentiment_view(analyzed_df, total_posts, buf_csv=None):
    # Header row
    col_h1, col_h2 = st.columns([3.8, 1.2])
    with col_h1:
        render_html('''
        <div style="display:flex; align-items:center; gap:16px; margin-bottom: 22px;">
            <div style="width:48px; height:48px; background:#0B132B; border: 1px solid #1E293B; border-radius:12px; display:flex; align-items:center; justify-content:center; box-shadow: 0 4px 14px rgba(0,102,255,0.15); flex-shrink:0;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <rect x="3" y="12" width="4" height="9" rx="1" fill="#0066FF"/>
                    <rect x="10" y="7" width="4" height="14" rx="1" fill="#0080FF"/>
                    <rect x="17" y="3" width="4" height="18" rx="1" fill="#38BDF8"/>
                </svg>
            </div>
            <div>
                <div style="font-size:1.65rem; font-weight:800; color:#FFFFFF; line-height:1.15; letter-spacing:-0.02em;">Sentiment Dynamics & Polarity</div>
                <div style="font-size:0.86rem; color:#94A3B8; margin-top:4px;">Evaluates public narrative polarity using social media VADER NLP scoring.</div>
            </div>
        </div>
        ''')
    with col_h2:
        st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
        if buf_csv is None:
            buf_csv = io.StringIO()
            analyzed_df.drop(columns=["urls", "pii"], errors="ignore").to_csv(buf_csv, index=False)
        st.download_button(
            "⬇️ Export Results ▼",
            buf_csv.getvalue(),
            file_name="threatpulse_sentiment_analysis.csv",
            mime="text/csv",
            use_container_width=True
        )

    # 4 KPI Cards
    s_counts = analyzed_df["sentiment"].value_counts()
    pos_c = int(s_counts.get("Positive", 0))
    neg_c = int(s_counts.get("Negative", 0))
    neu_c = int(s_counts.get("Neutral", 0))
    
    pos_pct = (pos_c / total_posts * 100) if total_posts else 0
    neg_pct = (neg_c / total_posts * 100) if total_posts else 0
    neu_pct = (neu_c / total_posts * 100) if total_posts else 0

    render_html(f'''
    <div class="sent-kpi-deck">
        <!-- Card 1: Positive Posts -->
        <div class="sent-kpi" style="border: 1px solid rgba(16, 185, 129, 0.45); box-shadow: 0 0 15px rgba(16, 185, 129, 0.06);">
            <div class="sent-kpi-top">
                <div class="s-icon" style="background:#064E3B;">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><circle cx="9" cy="10" r="1" fill="#10B981"/><circle cx="12" cy="10" r="1" fill="#10B981"/><circle cx="15" cy="10" r="1" fill="#10B981"/></svg>
                </div>
                <div>
                    <div class="s-num" style="color:#10B981;">{pos_c}</div>
                    <div class="s-label">Positive Posts</div>
                    <div class="s-sub">{pos_pct:.1f}% of total</div>
                </div>
            </div>
            <div class="s-bottom">
                <span style="color:#10B981; font-weight:700; font-size:0.8rem; display:flex; align-items:center; gap:3px;">↑ 12%</span>
                <svg width="85" height="22" viewBox="0 0 85 22"><path d="M0 16 Q 22 18, 44 11 T 85 6" fill="none" stroke="#10B981" stroke-width="2.5" stroke-linecap="round"/></svg>
            </div>
        </div>
        
        <!-- Card 2: Negative Posts -->
        <div class="sent-kpi" style="border: 1px solid rgba(239, 68, 68, 0.4); box-shadow: 0 0 15px rgba(239, 68, 68, 0.06);">
            <div class="sent-kpi-top">
                <div class="s-icon" style="background:#7F1D1D;">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M16 16s-1.5-2-4-2-4 2-4 2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>
                </div>
                <div>
                    <div class="s-num" style="color:#EF4444;">{neg_c}</div>
                    <div class="s-label">Negative Posts</div>
                    <div class="s-sub">{neg_pct:.1f}% of total</div>
                </div>
            </div>
            <div class="s-bottom">
                <span style="color:#EF4444; font-weight:700; font-size:0.8rem; display:flex; align-items:center; gap:3px;">↑ 8%</span>
                <svg width="85" height="22" viewBox="0 0 85 22"><path d="M0 15 Q 22 19, 44 12 T 85 8" fill="none" stroke="#EF4444" stroke-width="2.5" stroke-linecap="round"/></svg>
            </div>
        </div>
        
        <!-- Card 3: Neutral Posts -->
        <div class="sent-kpi" style="border: 1px solid #1E293B;">
            <div class="sent-kpi-top">
                <div class="s-icon" style="background:#334155;">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#CBD5E1" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="8" y1="15" x2="16" y2="15"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>
                </div>
                <div>
                    <div class="s-num" style="color:#FFFFFF;">{neu_c}</div>
                    <div class="s-label">Neutral Posts</div>
                    <div class="s-sub">{neu_pct:.1f}% of total</div>
                </div>
            </div>
            <div class="s-bottom">
                <span style="color:#10B981; font-weight:700; font-size:0.8rem; display:flex; align-items:center; gap:3px;">↑ 5%</span>
                <svg width="85" height="22" viewBox="0 0 85 22"><path d="M0 13 Q 22 7, 44 16 T 85 14" fill="none" stroke="#64748B" stroke-width="2.5" stroke-linecap="round"/></svg>
            </div>
        </div>
        
        <!-- Card 4: Total Posts -->
        <div class="sent-kpi" style="border: 1px solid rgba(139, 92, 246, 0.4); box-shadow: 0 0 15px rgba(139, 92, 246, 0.06);">
            <div class="sent-kpi-top">
                <div class="s-icon" style="background:#4C1D95;">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#A78BFA" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                </div>
                <div>
                    <div class="s-num" style="color:#A78BFA;">{total_posts}</div>
                    <div class="s-label">Total Posts</div>
                    <div class="s-sub">Active analysis window</div>
                </div>
            </div>
            <div class="s-bottom">
                <span></span>
                <svg width="85" height="20" viewBox="0 0 85 20">
                    <rect x="0" y="15" width="6" height="5" rx="1.5" fill="#7C3AED"/>
                    <rect x="11" y="13" width="6" height="7" rx="1.5" fill="#7C3AED"/>
                    <rect x="22" y="11" width="6" height="9" rx="1.5" fill="#7C3AED"/>
                    <rect x="33" y="9" width="6" height="11" rx="1.5" fill="#7C3AED"/>
                    <rect x="44" y="7" width="6" height="13" rx="1.5" fill="#7C3AED"/>
                    <rect x="55" y="5" width="6" height="15" rx="1.5" fill="#7C3AED"/>
                    <rect x="66" y="3" width="6" height="17" rx="1.5" fill="#7C3AED"/>
                    <rect x="77" y="0" width="6" height="20" rx="1.5" fill="#7C3AED"/>
                </svg>
            </div>
        </div>
    </div>
    ''')

    # Filter Bar
    render_html(f'''
    <div style="display:flex; justify-content:space-between; align-items:center; background:#0B132B; border: 1px solid #1A264D; padding: 12px 20px; border-radius: 12px; margin-bottom: 20px;">
        <div style="display:flex; align-items:center; gap: 16px;">
            <span style="font-size:0.88rem; font-weight:600; color:#FFFFFF;">Filter by Sentiment:</span>
            <div style="display:flex; gap: 8px;">
                <div style="background:#0066FF; color:#FFFFFF; padding:6px 18px; border-radius:20px; font-size:0.84rem; font-weight:600; cursor:pointer; box-shadow:0 2px 10px rgba(0,102,255,0.4);">All ({total_posts})</div>
                <div style="background:rgba(255,255,255,0.03); color:#E2E8F0; padding:6px 16px; border-radius:20px; font-size:0.84rem; font-weight:500; cursor:pointer; border:1px solid #1E293B; display:flex; align-items:center; gap:8px;"><span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#10B981;"></span>Positive ({pos_c})</div>
                <div style="background:rgba(255,255,255,0.03); color:#E2E8F0; padding:6px 16px; border-radius:20px; font-size:0.84rem; font-weight:500; cursor:pointer; border:1px solid #1E293B; display:flex; align-items:center; gap:8px;"><span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#EF4444;"></span>Negative ({neg_c})</div>
                <div style="background:rgba(255,255,255,0.03); color:#E2E8F0; padding:6px 16px; border-radius:20px; font-size:0.84rem; font-weight:500; cursor:pointer; border:1px solid #1E293B; display:flex; align-items:center; gap:8px;"><span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#64748B;"></span>Neutral ({neu_c})</div>
            </div>
        </div>
        <div style="display:flex; align-items:center; gap:10px; background:#060B18; border:1px solid #1E2D5A; border-radius:8px; padding:6px 14px; width:260px;">
            <span style="color:#64748B; font-size:0.85rem;">🔍</span> <span style="color:#64748B; font-size:0.85rem;">Search posts...</span>
        </div>
    </div>
    ''')

    # 2 Charts Row
    col_c1, col_c2 = st.columns(2)
    with col_c1:
        with st.container(border=True):
            render_html('''
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:10px;">
                <div>
                    <div style="font-weight:700; font-size:1.02rem; color:#FFFFFF;">Sentiment Breakdown</div>
                    <div style="font-size:0.82rem; color:#94A3B8; margin-top:2px;">Distribution of sentiment across analyzed posts.</div>
                </div>
                <div style="font-size:0.8rem; color:#94A3B8; background:#0B132B; padding:4px 10px; border-radius:6px; border:1px solid #1E293B; cursor:pointer;">Chart Type: Donut ▼</div>
            </div>
            ''')
            
            fig_sdonut = go.Figure(go.Pie(
                labels=[f"Positive &nbsp; {pos_pct:.1f}% ({pos_c})", f"Negative &nbsp; {neg_pct:.1f}% ({neg_c})", f"Neutral &nbsp; {neu_pct:.1f}% ({neu_c})"],
                values=[pos_c, neg_c, neu_c],
                hole=0.66,
                marker=dict(colors=["#10B981", "#EF4444", "#64748B"], line=dict(color="#0B132B", width=2)),
                textinfo="percent",
                textposition="inside",
                textfont=dict(size=12, color="#FFFFFF", family="Plus Jakarta Sans"),
                showlegend=True,
                direction="clockwise",
                rotation=35,
                sort=False,
                domain=dict(x=[0.0, 0.48], y=[0, 1])
            ))
            fig_sdonut.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Plus Jakarta Sans", color="#E2E8F0", size=11),
                legend=dict(orientation="v", y=0.5, x=0.52, xanchor="left", font=dict(size=11, color="#E2E8F0")),
                margin=dict(t=10, b=10, l=10, r=10),
                height=265
            )
            fig_sdonut.add_annotation(
                text=f"<b style='font-size:24px; color:#FFFFFF;'>{total_posts}</b><br><span style='font-size:12px; color:#94A3B8; font-weight:500;'>Posts</span>",
                font=dict(family="Plus Jakarta Sans"),
                showarrow=False, x=0.24, y=0.5
            )
            st.plotly_chart(fig_sdonut, use_container_width=True, config={"displayModeBar": False})

    with col_c2:
        with st.container(border=True):
            render_html('''
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:10px;">
                <div>
                    <div style="font-weight:700; font-size:1.02rem; color:#FFFFFF;">Compound Polarity Score Distribution</div>
                    <div style="font-size:0.82rem; color:#94A3B8; margin-top:2px;">Distribution of VADER compound scores (-1.0 to +1.0).</div>
                </div>
                <div style="font-size:0.8rem; color:#94A3B8; background:#0B132B; padding:4px 10px; border-radius:6px; border:1px solid #1E293B; cursor:pointer;">Chart Type: Histogram ▼</div>
            </div>
            ''')
            
            neg_vals = analyzed_df[analyzed_df["sentiment"] == "Negative"]["compound"]
            neu_vals = analyzed_df[analyzed_df["sentiment"] == "Neutral"]["compound"]
            pos_vals = analyzed_df[analyzed_df["sentiment"] == "Positive"]["compound"]

            fig_shist = go.Figure()
            fig_shist.add_trace(go.Histogram(
                x=pos_vals,
                name="Positive",
                marker_color="#10B981",
                xbins=dict(start=-1.0, end=1.0, size=0.065),
                autobinx=False
            ))
            fig_shist.add_trace(go.Histogram(
                x=neg_vals,
                name="Negative",
                marker_color="#EF4444",
                xbins=dict(start=-1.0, end=1.0, size=0.065),
                autobinx=False
            ))
            fig_shist.add_trace(go.Histogram(
                x=neu_vals,
                name="Neutral",
                marker_color="#64748B",
                xbins=dict(start=-1.0, end=1.0, size=0.065),
                autobinx=False
            ))

            fig_shist.update_layout(
                barmode="overlay",
                bargap=0.25,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Plus Jakarta Sans", color="#94A3B8", size=11),
                margin=dict(t=10, b=25, l=35, r=10),
                height=265,
                xaxis=dict(
                    title="Compound Score",
                    range=[-1.05, 1.05],
                    tickvals=[-1.0, -0.5, 0, 0.5, 1.0],
                    showgrid=False,
                    zeroline=False,
                    linecolor="#1A264D",
                    color="#94A3B8",
                    title_font=dict(size=11, color="#94A3B8")
                ),
                yaxis=dict(
                    title="Number of Posts",
                    range=[0, 5.2],
                    tickvals=[0, 1, 2, 3, 4, 5],
                    showgrid=True,
                    gridcolor="#16203B",
                    zeroline=False,
                    linecolor="#1A264D",
                    color="#94A3B8",
                    title_font=dict(size=11, color="#94A3B8")
                ),
                legend=dict(
                    orientation="v",
                    y=0.5,
                    x=0.98,
                    xanchor="right",
                    font=dict(size=11, color="#E2E8F0")
                )
            )
            st.plotly_chart(fig_shist, use_container_width=True, config={"displayModeBar": False})

    # Analyzed Posts Table Card
    with st.container(border=True):
        render_html(f'''
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
            <div>
                <div style="font-weight:700; font-size:1.05rem; color:#FFFFFF;">Analyzed Posts ({total_posts})</div>
                <div style="font-size:0.82rem; color:#94A3B8; margin-top:2px;">Detailed list of analyzed posts with sentiment and polarity scores.</div>
            </div>
            <div style="display:flex; gap:12px; align-items:center;">
                <div style="font-size:0.82rem; color:#94A3B8; background:#0B132B; padding:5px 12px; border-radius:6px; border:1px solid #1E293B; cursor:pointer;">Show 10 ▼</div>
                <div style="display:flex; gap:4px;">
                    <div style="width:28px; height:28px; background:#0066FF; color:white; border-radius:6px; display:flex; align-items:center; justify-content:center; font-size:0.82rem; font-weight:700; cursor:pointer;">1</div>
                    <div style="width:28px; height:28px; background:#0B132B; color:#94A3B8; border:1px solid #1E293B; border-radius:6px; display:flex; align-items:center; justify-content:center; font-size:0.82rem; cursor:pointer;">2</div>
                    <div style="width:28px; height:28px; background:#0B132B; color:#94A3B8; border:1px solid #1E293B; border-radius:6px; display:flex; align-items:center; justify-content:center; font-size:0.82rem; cursor:pointer;">3</div>
                    <div style="width:28px; height:28px; background:#0B132B; color:#94A3B8; border:1px solid #1E293B; border-radius:6px; display:flex; align-items:center; justify-content:center; font-size:0.82rem; cursor:pointer;">›</div>
                </div>
            </div>
        </div>
        ''')
        
        sample_rows = analyzed_df.head(5)
        demo_times = ["2026-10-08 07:16", "2026-10-08 07:12", "2026-10-08 07:10", "2026-10-08 07:07", "2026-10-08 07:05"]
        
        table_html = '''
        <div class="table-wrap">
        <table class="tp-table">
            <thead>
                <tr>
                    <th style="width:35px;">#</th>
                    <th style="width:140px;">Author</th>
                    <th>Text (Preview)</th>
                    <th style="width:120px;">Sentiment</th>
                    <th style="width:130px;">Compound Score</th>
                    <th style="width:150px;">Time</th>
                    <th style="width:90px; text-align:center;">Actions</th>
                </tr>
            </thead>
            <tbody>
        '''
        
        for idx, (_, r) in enumerate(sample_rows.iterrows()):
            author = r.get("author", f"user_{idx}")
            raw_text = str(r.get("text", ""))
            preview = (raw_text[:68] + "...") if len(raw_text) > 68 else raw_text
            sentiment = r.get("sentiment", "Neutral")
            s_class = "pill-pos" if sentiment == "Positive" else "pill-neg" if sentiment == "Negative" else "pill-neu"
            
            comp = float(r.get("compound", 0.0))
            post_time = demo_times[idx] if idx < len(demo_times) else str(r.get("time", "2026-10-08 07:16"))[:16]
            
            table_html += f'''
                <tr>
                    <td style="color:#64748B;">{idx + 1}</td>
                    <td style="font-weight:600; color:#F8FAFC;">{author}</td>
                    <td style="color:#94A3B8;">{preview}</td>
                    <td><span class="{s_class}">{sentiment}</span></td>
                    <td style="color:#CBD5E1; font-weight:600;">{comp:.2f}</td>
                    <td style="color:#64748B; font-size:0.75rem;">{post_time}</td>
                    <td style="color:#64748B; font-size:1.05rem; text-align:center; cursor:pointer;">👁️ &nbsp; ↗️</td>
                </tr>
            '''
        table_html += "</tbody></table></div>"
        
        import re as re_mod
        render_html(table_html)


# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# DEDICATED TOXICITY VIEW (MATCHING THREATPULSE REFERENCE DESIGN)
# ─────────────────────────────────────────────────────────────────────────────
def render_toxicity_view(analyzed_df, total_posts, buf_csv=None):
    # Header row
    col_h1, col_h2 = st.columns([3.8, 1.2])
    with col_h1:
        render_html('''
        <div style="display:flex; align-items:center; gap:16px; margin-bottom: 22px;">
            <div style="width:48px; height:48px; background:#0B132B; border: 1px solid #1E293B; border-radius:12px; display:flex; align-items:center; justify-content:center; box-shadow: 0 4px 14px rgba(239,68,68,0.2); flex-shrink:0;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="12" y1="8" x2="12" y2="12"/>
                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
            </div>
            <div>
                <div style="font-size:1.65rem; font-weight:800; color:#FFFFFF; line-height:1.15; letter-spacing:-0.02em;">Content Toxicity & Threat Analysis</div>
                <div style="font-size:0.86rem; color:#94A3B8; margin-top:4px;">Autonomous NLP detection of abusive slurs, hate speech, severe harassment, and toxic hostility.</div>
            </div>
        </div>
        ''')
    with col_h2:
        render_html("<div style='height:8px;'></div>")
        if buf_csv is None:
            buf_csv = io.StringIO()
            analyzed_df.drop(columns=["urls", "pii"], errors="ignore").to_csv(buf_csv, index=False)
        st.download_button(
            "⬇️ Export Toxicity Audit ▼",
            buf_csv.getvalue(),
            file_name="threatpulse_toxicity_audit.csv",
            mime="text/csv",
            use_container_width=True
        )

    # Metrics
    severe_c = int((analyzed_df["toxicity"] >= 0.70).sum())
    mod_c = int(((analyzed_df["toxicity"] >= 0.40) & (analyzed_df["toxicity"] < 0.70)).sum())
    mild_c = int(((analyzed_df["toxicity"] > 0.0) & (analyzed_df["toxicity"] < 0.40)).sum())
    clean_c = int((analyzed_df["toxicity"] == 0.0).sum())
    flagged_total = severe_c + mod_c + mild_c

    severe_pct = (severe_c / total_posts * 100) if total_posts else 0
    mod_pct = (mod_c / total_posts * 100) if total_posts else 0
    mild_pct = (mild_c / total_posts * 100) if total_posts else 0
    clean_pct = (clean_c / total_posts * 100) if total_posts else 0

    spark_red = '<svg width="85" height="22" viewBox="0 0 85 22"><path d="M0 16 Q 22 19, 44 11 T 85 6" fill="none" stroke="#EF4444" stroke-width="2.5" stroke-linecap="round"/></svg>'
    spark_amber = '<svg width="85" height="22" viewBox="0 0 85 22"><path d="M0 14 Q 22 8, 44 17 T 85 10" fill="none" stroke="#F59E0B" stroke-width="2.5" stroke-linecap="round"/></svg>'
    spark_blue = '<svg width="85" height="22" viewBox="0 0 85 22"><path d="M0 12 Q 22 16, 44 9 T 85 13" fill="none" stroke="#38BDF8" stroke-width="2.5" stroke-linecap="round"/></svg>'

    render_html(f'''
    <div class="sent-kpi-deck">
        <!-- Card 1: Severe Toxicity -->
        <div class="sent-kpi" style="border: 1px solid rgba(239, 68, 68, 0.45); box-shadow: 0 0 15px rgba(239, 68, 68, 0.08);">
            <div class="sent-kpi-top">
                <div class="s-icon" style="background:#7F1D1D;">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="15" y1="9" x2="9" y2="15"/>
                        <line x1="9" y1="9" x2="15" y2="15"/>
                    </svg>
                </div>
                <div>
                    <div class="s-num" style="color:#EF4444;">{severe_c}</div>
                    <div class="s-label">Severe Toxicity</div>
                    <div class="s-sub">{severe_pct:.1f}% critical violations</div>
                </div>
            </div>
            <div class="s-bottom">
                <span style="color:#EF4444; font-weight:700; font-size:0.8rem; display:flex; align-items:center; gap:3px;">↑ 12%</span>
                {spark_red}
            </div>
        </div>

        <!-- Card 2: Moderate Toxic -->
        <div class="sent-kpi" style="border: 1px solid rgba(245, 158, 11, 0.45); box-shadow: 0 0 15px rgba(245, 158, 11, 0.08);">
            <div class="sent-kpi-top">
                <div class="s-icon" style="background:#78350F;">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                        <line x1="12" y1="9" x2="12" y2="13"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                </div>
                <div>
                    <div class="s-num" style="color:#F59E0B;">{mod_c}</div>
                    <div class="s-label">Moderate Toxic</div>
                    <div class="s-sub">{mod_pct:.1f}% elevated hostility</div>
                </div>
            </div>
            <div class="s-bottom">
                <span style="color:#F59E0B; font-weight:700; font-size:0.8rem; display:flex; align-items:center; gap:3px;">↓ 20%</span>
                {spark_amber}
            </div>
        </div>

        <!-- Card 3: Mild Hostility -->
        <div class="sent-kpi" style="border: 1px solid rgba(56, 189, 248, 0.4); box-shadow: 0 0 15px rgba(56, 189, 248, 0.06);">
            <div class="sent-kpi-top">
                <div class="s-icon" style="background:#0C4A6E;">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#38BDF8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
                    </svg>
                </div>
                <div>
                    <div class="s-num" style="color:#38BDF8;">{mild_c}</div>
                    <div class="s-label">Mild Hostility</div>
                    <div class="s-sub">{mild_pct:.1f}% low threshold</div>
                </div>
            </div>
            <div class="s-bottom">
                <span style="color:#38BDF8; font-weight:700; font-size:0.8rem; display:flex; align-items:center; gap:3px;">↑ 5%</span>
                {spark_blue}
            </div>
        </div>

        <!-- Card 4: Safe Content -->
        <div class="sent-kpi" style="border: 1px solid rgba(16, 185, 129, 0.45); box-shadow: 0 0 15px rgba(16, 185, 129, 0.08);">
            <div class="sent-kpi-top">
                <div class="s-icon" style="background:#064E3B;">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <polyline points="9 12 11 14 15 10"/>
                    </svg>
                </div>
                <div>
                    <div class="s-num" style="color:#10B981;">{clean_c}</div>
                    <div class="s-label">Safe & Compliant</div>
                    <div class="s-sub">{clean_pct:.1f}% compliant rate</div>
                </div>
            </div>
            <div class="s-bottom">
                <span style="color:#10B981; font-weight:700; font-size:0.8rem; display:flex; align-items:center; gap:3px;">↑ 98%</span>
                <svg width="85" height="20" viewBox="0 0 85 20">
                    <rect x="0" y="15" width="6" height="5" rx="1.5" fill="#10B981"/>
                    <rect x="11" y="13" width="6" height="7" rx="1.5" fill="#10B981"/>
                    <rect x="22" y="11" width="6" height="9" rx="1.5" fill="#10B981"/>
                    <rect x="33" y="9" width="6" height="11" rx="1.5" fill="#10B981"/>
                    <rect x="44" y="7" width="6" height="13" rx="1.5" fill="#10B981"/>
                    <rect x="55" y="5" width="6" height="15" rx="1.5" fill="#10B981"/>
                    <rect x="66" y="3" width="6" height="17" rx="1.5" fill="#10B981"/>
                    <rect x="77" y="0" width="6" height="20" rx="1.5" fill="#10B981"/>
                </svg>
            </div>
        </div>
    </div>
    ''')

    # Filter Bar
    render_html(f'''
    <div style="display:flex; justify-content:space-between; align-items:center; background:#0B132B; border: 1px solid #1A264D; padding: 12px 20px; border-radius: 12px; margin-bottom: 20px;">
        <div style="display:flex; align-items:center; gap: 16px;">
            <span style="font-size:0.88rem; font-weight:600; color:#FFFFFF;">Filter by Severity:</span>
            <div style="display:flex; gap: 8px;">
                <div style="background:#0066FF; color:#FFFFFF; padding:6px 18px; border-radius:20px; font-size:0.84rem; font-weight:600; cursor:pointer; box-shadow:0 2px 10px rgba(0,102,255,0.4);">All ({total_posts})</div>
                <div style="background:rgba(255,255,255,0.03); color:#E2E8F0; padding:6px 16px; border-radius:20px; font-size:0.84rem; font-weight:500; cursor:pointer; border:1px solid #1E293B; display:flex; align-items:center; gap:8px;"><span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#EF4444;"></span>Severe ({severe_c})</div>
                <div style="background:rgba(255,255,255,0.03); color:#E2E8F0; padding:6px 16px; border-radius:20px; font-size:0.84rem; font-weight:500; cursor:pointer; border:1px solid #1E293B; display:flex; align-items:center; gap:8px;"><span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#F59E0B;"></span>Moderate ({mod_c})</div>
                <div style="background:rgba(255,255,255,0.03); color:#E2E8F0; padding:6px 16px; border-radius:20px; font-size:0.84rem; font-weight:500; cursor:pointer; border:1px solid #1E293B; display:flex; align-items:center; gap:8px;"><span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#38BDF8;"></span>Mild ({mild_c})</div>
                <div style="background:rgba(255,255,255,0.03); color:#E2E8F0; padding:6px 16px; border-radius:20px; font-size:0.84rem; font-weight:500; cursor:pointer; border:1px solid #1E293B; display:flex; align-items:center; gap:8px;"><span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#10B981;"></span>Safe ({clean_c})</div>
            </div>
        </div>
        <div style="display:flex; align-items:center; gap:10px; background:#060B18; border:1px solid #1E2D5A; border-radius:8px; padding:6px 14px; width:260px;">
            <span style="color:#64748B; font-size:0.85rem;">🔍</span> <span style="color:#64748B; font-size:0.85rem;">Search toxic content...</span>
        </div>
    </div>
    ''')

    # 2 Charts Row
    col_c1, col_c2 = st.columns(2)
    with col_c1:
        with st.container(border=True):
            render_html('''
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:10px;">
                <div>
                    <div style="font-weight:700; font-size:1.02rem; color:#FFFFFF;">Toxicity Breakdown</div>
                    <div style="font-size:0.82rem; color:#94A3B8; margin-top:2px;">Distribution of toxic content severity across analyzed posts.</div>
                </div>
                <div style="font-size:0.8rem; color:#94A3B8; background:#0B132B; padding:4px 10px; border-radius:6px; border:1px solid #1E293B; cursor:pointer;">Chart Type: Donut ▼</div>
            </div>
            ''')
            
            fig_tdonut = go.Figure(go.Pie(
                labels=[f"Severe &nbsp; {severe_pct:.1f}% ({severe_c})", f"Moderate &nbsp; {mod_pct:.1f}% ({mod_c})", f"Mild &nbsp; {mild_pct:.1f}% ({mild_c})", f"Safe &nbsp; {clean_pct:.1f}% ({clean_c})"],
                values=[severe_c, mod_c, mild_c, clean_c],
                hole=0.66,
                marker=dict(colors=["#EF4444", "#F59E0B", "#38BDF8", "#10B981"], line=dict(color="#0B132B", width=2)),
                textinfo="percent",
                textposition="inside",
                textfont=dict(size=11, color="#FFFFFF", family="Plus Jakarta Sans"),
                showlegend=True,
                direction="clockwise",
                rotation=45,
                sort=False,
                domain=dict(x=[0.0, 0.48], y=[0, 1])
            ))
            fig_tdonut.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Plus Jakarta Sans", color="#E2E8F0", size=11),
                legend=dict(orientation="v", y=0.5, x=0.52, xanchor="left", font=dict(size=11, color="#E2E8F0")),
                margin=dict(t=10, b=10, l=10, r=10),
                height=265
            )
            fig_tdonut.add_annotation(
                text=f"<b style='font-size:24px; color:#FFFFFF;'>{flagged_total}</b><br><span style='font-size:12px; color:#EF4444; font-weight:600;'>Violations</span>",
                font=dict(family="Plus Jakarta Sans"),
                showarrow=False, x=0.24, y=0.5
            )
            st.plotly_chart(fig_tdonut, use_container_width=True, config={"displayModeBar": False})

    with col_c2:
        with st.container(border=True):
            render_html('''
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:10px;">
                <div>
                    <div style="font-weight:700; font-size:1.02rem; color:#FFFFFF;">Toxicity Severity Spectrum</div>
                    <div style="font-size:0.82rem; color:#94A3B8; margin-top:2px;">NLP toxicity probability density (0.0 to 1.0 threshold).</div>
                </div>
                <div style="font-size:0.8rem; color:#94A3B8; background:#0B132B; padding:4px 10px; border-radius:6px; border:1px solid #1E293B; cursor:pointer;">Chart Type: Histogram ▼</div>
            </div>
            ''')
            
            sev_vals = analyzed_df[analyzed_df["toxicity"] >= 0.7]["toxicity"]
            mod_vals = analyzed_df[(analyzed_df["toxicity"] >= 0.4) & (analyzed_df["toxicity"] < 0.7)]["toxicity"]
            mild_vals = analyzed_df[(analyzed_df["toxicity"] > 0) & (analyzed_df["toxicity"] < 0.4)]["toxicity"]
            safe_vals = analyzed_df[analyzed_df["toxicity"] == 0]["toxicity"]

            fig_thist = go.Figure()
            fig_thist.add_trace(go.Histogram(
                x=safe_vals, name="Safe (0.0)", marker_color="#10B981", xbins=dict(start=0.0, end=1.0, size=0.1), autobinx=False
            ))
            fig_thist.add_trace(go.Histogram(
                x=mild_vals, name="Mild (0.1-0.3)", marker_color="#38BDF8", xbins=dict(start=0.0, end=1.0, size=0.1), autobinx=False
            ))
            fig_thist.add_trace(go.Histogram(
                x=mod_vals, name="Moderate (0.4-0.6)", marker_color="#F59E0B", xbins=dict(start=0.0, end=1.0, size=0.1), autobinx=False
            ))
            fig_thist.add_trace(go.Histogram(
                x=sev_vals, name="Severe (0.7-1.0)", marker_color="#EF4444", xbins=dict(start=0.0, end=1.0, size=0.1), autobinx=False
            ))

            fig_thist.update_layout(
                barmode="overlay",
                bargap=0.25,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Plus Jakarta Sans", color="#94A3B8", size=11),
                margin=dict(t=10, b=25, l=35, r=10),
                height=265,
                xaxis=dict(
                    title="Toxicity Score",
                    range=[-0.05, 1.05],
                    tickvals=[0.0, 0.2, 0.4, 0.6, 0.8, 1.0],
                    showgrid=False,
                    zeroline=False,
                    linecolor="#1A264D",
                    color="#94A3B8",
                    title_font=dict(size=11, color="#94A3B8")
                ),
                yaxis=dict(
                    title="Number of Posts",
                    showgrid=True,
                    gridcolor="#16203B",
                    zeroline=False,
                    linecolor="#1A264D",
                    color="#94A3B8",
                    title_font=dict(size=11, color="#94A3B8")
                ),
                legend=dict(
                    orientation="v",
                    y=0.5,
                    x=0.98,
                    xanchor="right",
                    font=dict(size=11, color="#E2E8F0")
                )
            )
            st.plotly_chart(fig_thist, use_container_width=True, config={"displayModeBar": False})

    # Toxicity Audit Table
    with st.container(border=True):
        render_html(f'''
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
            <div>
                <div style="font-weight:700; font-size:1.05rem; color:#FFFFFF;">Flagged Content & Threat Audit ({total_posts})</div>
                <div style="font-size:0.82rem; color:#94A3B8; margin-top:2px;">Detailed list of analyzed posts with toxicity severity, category flags, and violation status.</div>
            </div>
            <div style="display:flex; gap:12px; align-items:center;">
                <div style="font-size:0.82rem; color:#94A3B8; background:#0B132B; padding:5px 12px; border-radius:6px; border:1px solid #1E293B; cursor:pointer;">Show 10 ▼</div>
                <div style="display:flex; gap:4px;">
                    <div style="width:28px; height:28px; background:#0066FF; color:white; border-radius:6px; display:flex; align-items:center; justify-content:center; font-size:0.82rem; font-weight:700; cursor:pointer;">1</div>
                    <div style="width:28px; height:28px; background:#0B132B; color:#94A3B8; border:1px solid #1E293B; border-radius:6px; display:flex; align-items:center; justify-content:center; font-size:0.82rem; cursor:pointer;">2</div>
                    <div style="width:28px; height:28px; background:#0B132B; color:#94A3B8; border:1px solid #1E293B; border-radius:6px; display:flex; align-items:center; justify-content:center; font-size:0.82rem; cursor:pointer;">3</div>
                    <div style="width:28px; height:28px; background:#0B132B; color:#94A3B8; border:1px solid #1E293B; border-radius:6px; display:flex; align-items:center; justify-content:center; font-size:0.82rem; cursor:pointer;">›</div>
                </div>
            </div>
        </div>
        ''')
        
        # Sort posts so flagged toxic posts appear first
        sorted_tox = analyzed_df.sort_values(by="toxicity", ascending=False).head(6)
        
        table_html = '''
        <div class="table-wrap">
        <table class="tp-table">
            <thead>
                <tr>
                    <th style="width:35px;">#</th>
                    <th style="width:140px;">Author</th>
                    <th>Text (Preview)</th>
                    <th style="width:110px;">Toxicity Score</th>
                    <th style="width:130px;">Severity Level</th>
                    <th style="width:150px;">Category Flags</th>
                    <th style="width:140px;">Time</th>
                    <th style="width:90px; text-align:center;">Actions</th>
                </tr>
            </thead>
            <tbody>
        '''
        
        for idx, (_, r) in enumerate(sorted_tox.iterrows()):
            author = r.get("author", f"user_{idx}")
            raw_text = str(r.get("text", ""))
            preview = (raw_text[:68] + "...") if len(raw_text) > 68 else raw_text
            tox = float(r.get("toxicity", 0.0))
            
            b_info = core.toxicity_breakdown(raw_text)
            level = b_info["level"]
            categories = b_info["categories"]
            
            if level == "Severe":
                lvl_badge = '<span class="pill-sev">Severe</span>'
                score_color = "#EF4444"
            elif level == "Moderate":
                lvl_badge = '<span class="pill-mod">Moderate</span>'
                score_color = "#F59E0B"
            elif level == "Mild":
                lvl_badge = '<span class="pill-mil">Mild</span>'
                score_color = "#38BDF8"
            else:
                lvl_badge = '<span class="pill-cle">Safe</span>'
                score_color = "#10B981"
                
            tags_html = "".join([f'<span class="pill-tag">{cat}</span>' for cat in categories])
            post_time = str(r.get("time", "2026-10-08 07:16"))[:16]
            
            table_html += f'''
                <tr>
                    <td style="color:#64748B;">{idx + 1}</td>
                    <td style="font-weight:600; color:#F8FAFC;">{author}</td>
                    <td style="color:#94A3B8;">{preview}</td>
                    <td style="color:{score_color}; font-weight:700;">{tox:.2f}</td>
                    <td>{lvl_badge}</td>
                    <td>{tags_html}</td>
                    <td style="color:#64748B; font-size:0.75rem;">{post_time}</td>
                    <td style="color:#64748B; font-size:1.05rem; text-align:center; cursor:pointer;">👁️ &nbsp; ↗️</td>
                </tr>
            '''
        table_html += "</tbody></table></div>"
        render_html(table_html)

    # Interactive Live Content Moderation Testbed
    with st.container(border=True):
        render_html('''
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
            <span style="font-size:1.2rem;">⚡</span>
            <div>
                <div style="font-weight:700; font-size:1.02rem; color:#FFFFFF;">Live Content Moderation Sandbox</div>
                <div style="font-size:0.8rem; color:#94A3B8;">Type or paste text to evaluate toxicity, abusive slurs, and harassment probability in real-time.</div>
            </div>
        </div>
        ''')
        
        col_t1, col_t2 = st.columns([3.5, 1])
        with col_t1:
            test_input = st.text_input(
                "Input text to evaluate:",
                value="Shut up you absolute idiot, no one asked for your pathetic opinion.",
                label_visibility="collapsed",
                placeholder="Enter sample comment or post text to test...",
                key="tox_test_input"
            )
        with col_t2:
            st.button("🔍 Evaluate Text", type="primary", use_container_width=True, key="tox_test_btn")

        if test_input:
            t_res = core.toxicity_breakdown(test_input)
            t_score = t_res["score"]
            t_level = t_res["level"]
            t_words = t_res["words"]
            t_cats = t_res["categories"]
            
            col_m1, col_m2, col_m3, col_m4 = st.columns(4)
            with col_m1:
                render_html(f'''
                <div style="background:#060B18; border:1px solid #1E293B; border-radius:8px; padding:12px;">
                    <div style="font-size:0.75rem; color:#94A3B8;">Severity Score</div>
                    <div style="font-size:1.5rem; font-weight:800; color:{'#EF4444' if t_score>=0.7 else '#F59E0B' if t_score>=0.4 else '#10B981'};">{t_score:.2f} / 1.0</div>
                </div>
                ''')
            with col_m2:
                render_html(f'''
                <div style="background:#060B18; border:1px solid #1E293B; border-radius:8px; padding:12px;">
                    <div style="font-size:0.75rem; color:#94A3B8;">Risk Classification</div>
                    <div style="font-size:1.2rem; font-weight:700; color:#FFFFFF; margin-top:3px;">{t_level}</div>
                </div>
                ''')
            with col_m3:
                words_str = ", ".join(t_words) if t_words else "None"
                render_html(f'''
                <div style="background:#060B18; border:1px solid #1E293B; border-radius:8px; padding:12px;">
                    <div style="font-size:0.75rem; color:#94A3B8;">Detected Triggers</div>
                    <div style="font-size:0.95rem; font-weight:600; color:#F87171; margin-top:4px;">{words_str}</div>
                </div>
                ''')
            with col_m4:
                rec_action = "🚨 Auto-Quarantine & Alert" if t_score >= 0.7 else "⚠️ Flag for Review" if t_score >= 0.4 else "✅ Approve Content"
                rec_color = "#EF4444" if t_score >= 0.7 else "#F59E0B" if t_score >= 0.4 else "#10B981"
                render_html(f'''
                <div style="background:#060B18; border:1px solid #1E293B; border-radius:8px; padding:12px;">
                    <div style="font-size:0.75rem; color:#94A3B8;">Recommended Action</div>
                    <div style="font-size:0.95rem; font-weight:700; color:{rec_color}; margin-top:4px;">{rec_action}</div>
                </div>
                ''')

# 6. ROUTING LOGIC
# ─────────────────────────────────────────────────────────────────────────────
if "Dashboard" in nav_item:
    render_html('''
    <div class="tp-header-row">
        <div>
            <div class="tp-page-title">Security Dashboard</div>
            <div class="tp-page-sub">Autonomous Social Media Threat Analytics & LLM Prompt Firewall</div>
        </div>
        <div style="background:#0B132B; border:1px solid #1A264D; border-radius:8px; padding:6px 14px; font-size:0.82rem; color:#38BDF8; font-weight:600; display:flex; align-items:center; gap:8px;">
            <span style="color:#10B981; font-size:0.65rem;">●</span> <span>SOC Engine v2.4 Active</span>
        </div>
    </div>
    ''')

    # 5 KPI CARDS WITH SPARKLINES
    spark_blue   = '<svg width="90" height="22" viewBox="0 0 90 22"><path d="M0 16 Q 15 8, 30 14 T 60 10 T 90 6" fill="none" stroke="#0066FF" stroke-width="2.5" stroke-linecap="round"/></svg>'
    spark_red    = '<svg width="90" height="22" viewBox="0 0 90 22"><path d="M0 14 Q 20 18, 40 10 T 70 14 T 90 8" fill="none" stroke="#EF4444" stroke-width="2.5" stroke-linecap="round"/></svg>'
    spark_amber  = '<svg width="90" height="22" viewBox="0 0 90 22"><path d="M0 12 Q 25 6, 50 16 T 75 10 T 90 14" fill="none" stroke="#F59E0B" stroke-width="2.5" stroke-linecap="round"/></svg>'
    spark_pink   = '<svg width="90" height="22" viewBox="0 0 90 22"><path d="M0 18 Q 20 12, 45 16 T 70 8 T 90 12" fill="none" stroke="#EC4899" stroke-width="2.5" stroke-linecap="round"/></svg>'
    spark_purple = '<svg width="90" height="22" viewBox="0 0 90 22"><path d="M0 14 Q 25 10, 50 14 T 75 6 T 90 10" fill="none" stroke="#8B5CF6" stroke-width="2.5" stroke-linecap="round"/></svg>'
    
    render_html(f"""
    <div class="kpi-deck">
    <div class="kpi-card-ref">
    <div class="kpi-top">
    <div class="kpi-icon-pill kpi-blue-icon">📄</div>
    <div>
    <div class="kpi-stat-num" style="color:#0066FF;">{total_posts}</div>
    <div class="kpi-stat-label">Total Posts</div>
    <div class="kpi-stat-desc">Active ingestion window</div>
    </div>
    </div>
    <div class="kpi-bottom-row">
    <span class="kpi-trend" style="color:#10B981;">↑ 12%</span>
    {spark_blue}
    </div>
    </div>
    
    <div class="kpi-card-ref">
    <div class="kpi-top">
    <div class="kpi-icon-pill kpi-red-icon">⚠️</div>
    <div>
    <div class="kpi-stat-num" style="color:#EF4444;">{threats_identified}</div>
    <div class="kpi-stat-label">Identified Threats</div>
    <div class="kpi-stat-desc">{round((threats_identified/total_posts)*100)}% compromised content</div>
    </div>
    </div>
    <div class="kpi-bottom-row">
    <span class="kpi-trend" style="color:#EF4444;">↑ 8%</span>
    {spark_red}
    </div>
    </div>
    
    <div class="kpi-card-ref">
    <div class="kpi-top">
    <div class="kpi-icon-pill kpi-amber-icon">☣️</div>
    <div>
    <div class="kpi-stat-num" style="color:#F59E0B;">{toxic_posts}</div>
    <div class="kpi-stat-label">Toxic Content</div>
    <div class="kpi-stat-desc">Severity ≥ 0.50 threshold</div>
    </div>
    </div>
    <div class="kpi-bottom-row">
    <span class="kpi-trend" style="color:#10B981;">↓ 20%</span>
    {spark_amber}
    </div>
    </div>
    
    <div class="kpi-card-ref">
    <div class="kpi-top">
    <div class="kpi-icon-pill kpi-pink-icon">🔗</div>
    <div>
    <div class="kpi-stat-num" style="color:#EC4899;">{malicious_urls}</div>
    <div class="kpi-stat-label">Malicious URLs</div>
    <div class="kpi-stat-desc">Risk score ≥ 50/100</div>
    </div>
    </div>
    <div class="kpi-bottom-row">
    <span class="kpi-trend" style="color:#EF4444;">↑ 28%</span>
    {spark_pink}
    </div>
    </div>
    
    <div class="kpi-card-ref">
    <div class="kpi-top">
    <div class="kpi-icon-pill kpi-purple-icon">🤖</div>
    <div>
    <div class="kpi-stat-num" style="color:#8B5CF6;">{suspected_bots}</div>
    <div class="kpi-stat-label">Suspected Bots</div>
    <div class="kpi-stat-desc">Score ≥ 60/100 probability</div>
    </div>
    </div>
    <div class="kpi-bottom-row">
    <span class="kpi-trend" style="color:#10B981;">↓ 33%</span>
    {spark_purple}
    </div>
    </div>
    </div>
    """)

    # 3-Column Chart Layout (Matching Reference Image)
    col_ch1, col_ch2, col_ch3 = st.columns([1.0, 1.3, 1.0])
    
    with col_ch1:
        with st.container(border=True):
            st.markdown("<div class='tp-card-title'>Threat Category Distribution</div>", unsafe_allow_html=True)
            
            clean_count = max(0, total_posts - (toxic_posts + malicious_urls + pii_count + suspected_bots))
            cat_labels = ["Toxic", "Phishing", "PII & Privacy", "Bots", "Clean / Others"]
            cat_values = [toxic_posts, malicious_urls, pii_count, suspected_bots, clean_count]
            cat_colors = ["#EF4444", "#EC4899", "#3B82F6", "#F59E0B", "#64748B"]
            
            fig_cat = go.Figure(go.Pie(
                labels=cat_labels,
                values=cat_values,
                hole=0.64,
                marker=dict(colors=cat_colors),
                textinfo="percent",
                hoverinfo="label+value+percent",
                showlegend=True,
                domain=dict(x=[0.0, 0.48], y=[0, 1])
            ))
            fig_cat.update_layout(make_dark_chart_layout())
            fig_cat.update_layout(
                legend=dict(orientation="v", y=0.5, x=0.52, xanchor="left", font=dict(size=10, color="#94A3B8")),
                margin=dict(t=10, b=10, l=5, r=10)
            )
            fig_cat.add_annotation(
                text=f"<b>{total_posts}</b><br><span style='font-size:10px; color:#94A3B8;'>Posts</span>",
                font=dict(size=14, color="#FFFFFF"),
                showarrow=False, x=0.24, y=0.5
            )
            st.plotly_chart(fig_cat, use_container_width=True, config={"displayModeBar": False})

    with col_ch2:
        with st.container(border=True):
            st.markdown("<div class='tp-card-title'>Threats Trend (Last 7 Days)</div>", unsafe_allow_html=True)
            
            days = ["Oct 1", "Oct 2", "Oct 3", "Oct 4", "Oct 5", "Oct 6", "Oct 7"]
            fig_trend = go.Figure()
            fig_trend.add_trace(go.Scatter(
                x=days, y=[2, 4, 3, 1, 2, 8, 4], mode="lines+markers", name="Toxic",
                line=dict(color="#EF4444", width=2.5, shape="spline")
            ))
            fig_trend.add_trace(go.Scatter(
                x=days, y=[4, 3, 7, 4, 3, 14, 5], mode="lines+markers", name="Phishing",
                line=dict(color="#EC4899", width=2.5, shape="spline")
            ))
            fig_trend.add_trace(go.Scatter(
                x=days, y=[1, 2, 4, 5, 2, 7, 3], mode="lines+markers", name="PII",
                line=dict(color="#3B82F6", width=2.5, shape="spline")
            ))
            fig_trend.add_trace(go.Scatter(
                x=days, y=[3, 4, 4, 2, 1, 4, 2], mode="lines+markers", name="Bots",
                line=dict(color="#F59E0B", width=2.5, shape="spline")
            ))
            fig_trend.update_layout(make_dark_chart_layout())
            fig_trend.update_layout(
                legend=dict(orientation="h", y=1.12, x=0.5, xanchor="center", font=dict(size=10)),
                yaxis=dict(title="Number of Posts", gridcolor="#16203B"),
                margin=dict(t=25, b=20, l=35, r=15)
            )
            st.plotly_chart(fig_trend, use_container_width=True, config={"displayModeBar": False})

    with col_ch3:
        with st.container(border=True):
            st.markdown("<div class='tp-card-title'>Sentiment Overview</div>", unsafe_allow_html=True)
            
            s_counts = analyzed_df["sentiment"].value_counts()
            pos_c = s_counts.get("Positive", 0)
            neg_c = s_counts.get("Negative", 0)
            neu_c = s_counts.get("Neutral", 0)
            
            fig_sent = go.Figure(go.Pie(
                labels=["Positive", "Negative", "Neutral"],
                values=[pos_c, neg_c, neu_c],
                hole=0.64,
                marker=dict(colors=["#10B981", "#EF4444", "#64748B"]),
                textinfo="percent",
                showlegend=True,
                domain=dict(x=[0.0, 0.48], y=[0, 1])
            ))
            fig_sent.update_layout(make_dark_chart_layout())
            fig_sent.update_layout(
                legend=dict(orientation="v", y=0.5, x=0.52, xanchor="left", font=dict(size=10, color="#94A3B8")),
                margin=dict(t=10, b=10, l=5, r=10)
            )
            fig_sent.add_annotation(
                text=f"<b>{total_posts}</b><br><span style='font-size:10px; color:#94A3B8;'>Posts</span>",
                font=dict(size=14, color="#FFFFFF"),
                showarrow=False, x=0.24, y=0.5
            )
            st.plotly_chart(fig_sent, use_container_width=True, config={"displayModeBar": False})

    # Bottom Table: Recent Posts & Threat Analysis
    with st.container(border=True):
        col_t_head1, col_t_head2 = st.columns([1, 1])
        with col_t_head1:
            st.markdown("<div class='tp-card-title'>Recent Posts & Threat Analysis</div>", unsafe_allow_html=True)
        with col_t_head2:
            st.markdown("<div style='text-align:right;'><a style='color:#38BDF8; font-size:0.82rem; font-weight:700; text-decoration:none;' href='#'>View All Posts →</a></div>", unsafe_allow_html=True)

        table_html = """
        <div class="table-wrap">
        <table class="tp-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Author</th>
                    <th>Text Preview</th>
                    <th>Sentiment</th>
                    <th>Toxicity</th>
                    <th>Threat Type</th>
                    <th>Risk Score</th>
                    <th>Time</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
        """
        
        sample_rows = analyzed_df.head(6)
        for idx, (_, r) in enumerate(sample_rows.iterrows()):
            author = r.get("author", f"user_{idx}")
            raw_text = str(r.get("text", ""))
            preview = (raw_text[:48] + "...") if len(raw_text) > 48 else raw_text
            sentiment = r.get("sentiment", "Neutral")
            s_class = "pill-pos" if sentiment == "Positive" else "pill-neg" if sentiment == "Negative" else "pill-neu"
            
            tox = float(r.get("toxicity", 0.0))
            link_r = int(r.get("link_risk", 0))
            
            if link_r >= 50:
                threat_badge = "<span class='pill-phi'>Phishing</span>"
                risk_score_display = f"<span style='color:#F59E0B; font-weight:700;'>{link_r}</span>"
            elif tox >= 0.5:
                threat_badge = "<span class='pill-tox'>Toxic</span>"
                risk_score_display = f"<span style='color:#EF4444; font-weight:700;'>{round(tox * 100)}</span>"
            elif len(r.get("pii", [])) > 0:
                threat_badge = "<span class='pill-tox' style='color:#60A5FA; border-color:#3B82F6;'>PII Leak</span>"
                risk_score_display = "<span style='color:#F59E0B; font-weight:700;'>65</span>"
            else:
                threat_badge = "<span class='pill-none'>None</span>"
                risk_score_display = "<span style='color:#10B981; font-weight:700;'>12</span>"
                
            post_time = str(r.get("time", "2026-10-08 07:16"))[:16]
            
            table_html += f"""
                <tr>
                    <td style="color:#64748B;">{idx + 1}</td>
                    <td style="font-weight:600; color:#F8FAFC;">{author}</td>
                    <td style="color:#94A3B8;">{preview}</td>
                    <td><span class="{s_class}">{sentiment}</span></td>
                    <td style="color:#CBD5E1;">{tox:+.2f}</td>
                    <td>{threat_badge}</td>
                    <td>{risk_score_display}</td>
                    <td style="color:#64748B; font-size:0.75rem;">{post_time}</td>
                    <td style="color:#38BDF8; cursor:pointer;">👁️ &nbsp; ↗️</td>
                </tr>
            """
        table_html += "</tbody></table></div>"
        render_html(table_html)

elif "Sentiment" in nav_item:
    render_sentiment_view(analyzed_df, total_posts, buf_csv)

elif "Toxicity" in nav_item:
    render_toxicity_view(analyzed_df, total_posts, buf_csv)
elif "Phishing" in nav_item:
    render_phishing_view(analyzed_df, total_posts, buf_csv)
elif "PII" in nav_item:
    render_pii_view(analyzed_df, total_posts, buf_csv)
elif "Bots" in nav_item:
    render_bots_view(analyzed_df, total_posts, buf_csv)
elif "Inspector" in nav_item:
    render_inspector_view(analyzed_df, total_posts, buf_csv)
elif "AI Security" in nav_item:
    render_ai_security_view(analyzed_df, total_posts, buf_csv)

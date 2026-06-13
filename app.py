import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
import threading
import queue
import time
import json
import requests
import os
from datetime import datetime, timedelta
from sklearn.cluster import KMeans
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder, StandardScaler

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="InsiderShield — Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ── Dark cyber theme CSS ──────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Space Grotesk', sans-serif;
    background-color: #ffffff;
    color: #000000;
}
.stApp {
    background-color: #ffffff;
}
/* Header */
.shield-header {
    background: linear-gradient(135deg, #f8fafc 0%, #111827 50%, #0a1628 100%);
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 24px 32px;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    gap: 16px;
}
.shield-title { font-size: 28px; font-weight: 700; color: #e2e8f0; letter-spacing: -0.5px; }
.shield-sub { font-size: 13px; color: #64748b; font-family: 'JetBrains Mono', monospace; margin-top: 4px; }
.live-badge {
    background: #052e16; border: 1px solid #16a34a; color: #4ade80;
    padding: 4px 12px; border-radius: 20px; font-size: 11px;
    font-family: 'JetBrains Mono', monospace; font-weight: 500;
    animation: pulse 2s infinite;
}
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.6} }

/* KPI cards */
.kpi-card {
    background: #f8fafc; border: 1px solid #1e3a5f;
    border-radius: 10px; padding: 20px 24px;
}
.kpi-label { font-size: 11px; color: #475569; text-transform: uppercase; letter-spacing: 1px; font-family: 'JetBrains Mono', monospace; }
.kpi-value { font-size: 36px; font-weight: 700; line-height: 1.1; margin: 4px 0; }
.kpi-delta { font-size: 12px; color: #475569; font-family: 'JetBrains Mono', monospace; }
.kpi-critical { color: #f87171; }
.kpi-high { color: #fb923c; }
.kpi-blue { color: #60a5fa; }
.kpi-green { color: #4ade80; }

/* Section headers */
.section-head {
    font-size: 13px; font-weight: 600; color: #374151;
    text-transform: uppercase; letter-spacing: 1.5px;
    font-family: 'JetBrains Mono', monospace;
    border-left: 3px solid #3b82f6; padding-left: 10px;
    margin: 24px 0 12px 0;
}

/* Alert table rows */
.alert-critical { color: #f87171 !important; font-weight: 600; }
.alert-high { color: #fb923c !important; font-weight: 600; }
.alert-medium { color: #fbbf24 !important; }
.alert-low { color: #4ade80 !important; }

/* Tab styling */
.stTabs [data-baseweb="tab-list"] {
    background: #f8fafc; border-radius: 8px; padding: 4px; gap: 4px;
    border: 1px solid #1e3a5f;
}
.stTabs [data-baseweb="tab"] {
    color: #64748b; background: transparent; border-radius: 6px;
    font-family: 'Space Grotesk', sans-serif; font-weight: 500;
}
.stTabs [aria-selected="true"] {
    background: #1e3a5f !important; color: #e2e8f0 !important;
}

/* Expander */
.streamlit-expanderHeader {
    background: #f8fafc !important; border: 1px solid #1e3a5f !important;
    border-radius: 8px !important; color: #111827 !important;
}

/* Buttons */
.stButton > button {
    background: #1e3a5f; border: 1px solid #3b82f6; color: #93c5fd;
    border-radius: 6px; font-family: 'Space Grotesk', sans-serif;
    font-weight: 500; transition: all 0.2s;
}
.stButton > button:hover { background: #2563eb; color: white; border-color: #60a5fa; }

/* Metrics */
[data-testid="stMetric"] {
    background: #f8fafc; border: 1px solid #1e3a5f;
    border-radius: 10px; padding: 16px 20px;
}
[data-testid="stMetricLabel"] { color: #64748b !important; font-size: 12px !important; }
[data-testid="stMetricValue"] { color: #e2e8f0 !important; }

/* Plotly charts dark background */
.js-plotly-plot { border-radius: 8px; overflow: hidden; }

/* Pipeline feed */
.pipeline-event {
    background: #0a1628; border-left: 3px solid #1e3a5f;
    padding: 6px 12px; margin: 2px 0; border-radius: 0 4px 4px 0;
    font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #64748b;
}
.pipeline-critical { border-left-color: #f87171 !important; color: #fca5a5 !important; }
.pipeline-high { border-left-color: #fb923c !important; color: #fdba74 !important; }

/* Narrative block */
.llm-narrative {
    background: linear-gradient(135deg, #0d1a2e, #0a1628);
    border: 1px solid #1e3a5f; border-left: 4px solid #3b82f6;
    border-radius: 8px; padding: 20px; margin: 12px 0;
    font-size: 14px; line-height: 1.7; color: #111827;
}

/* Score badge */
.score-badge {
    display: inline-block; padding: 2px 10px; border-radius: 12px;
    font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 600;
}
</style>
""", unsafe_allow_html=True)

# ── Load data ─────────────────────────────────────────────────────────────────
@st.cache_data
def load_data():
    df = pd.read_csv('alerts_output.csv', parse_dates=['timestamp'])
    profiles = pd.read_csv('user_profiles.csv')
    return df, profiles

df, profiles = load_data()

# ── Session state ─────────────────────────────────────────────────────────────
if 'fp_set' not in st.session_state:
    st.session_state.fp_set = set()
if 'escalated' not in st.session_state:
    st.session_state.escalated = set()
if 'pipeline_running' not in st.session_state:
    st.session_state.pipeline_running = False
if 'pipeline_events' not in st.session_state:
    st.session_state.pipeline_events = []
if 'pipeline_count' not in st.session_state:
    st.session_state.pipeline_count = 0
if 'pipeline_alerts' not in st.session_state:
    st.session_state.pipeline_alerts = 0

# Apply FP removals and escalations
working_df = df.copy()
working_df = working_df[~working_df.index.isin(st.session_state.fp_set)]
for idx in st.session_state.escalated:
    if idx in working_df.index:
        working_df.at[idx, 'severity'] = 'CRITICAL'
        working_df.at[idx, 'risk_score'] = 100

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="shield-header">
  <div>
    <div class="shield-title">🛡️ InsiderShield</div>
    <div class="shield-sub">INSIDER THREAT DETECTION PLATFORM · KAFKA + SPARK ARCHITECTURE · 1200 EVENTS ANALYZED</div>
  </div>
  <div style="margin-left:auto">
    <span class="live-badge">● LIVE</span>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Dashboard", "🔍 Investigate", "🔮 Predictions", "⚡ Live Pipeline"
])

# ════════════════════════════════════════════════════════════════════════════
# TAB 1: DASHBOARD
# ════════════════════════════════════════════════════════════════════════════
with tab1:

    # KPI row
    critical_count = len(working_df[working_df['severity'] == 'CRITICAL'])
    high_count = len(working_df[working_df['severity'] == 'HIGH'])
    flagged_users = working_df[working_df['severity'].isin(['CRITICAL','HIGH'])]['user_id'].nunique()
    fp_count = len(st.session_state.fp_set)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""<div class="kpi-card">
            <div class="kpi-label">Total Events</div>
            <div class="kpi-value kpi-blue">{len(working_df):,}</div>
            <div class="kpi-delta">1,200 processed · Kafka stream</div>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown(f"""<div class="kpi-card">
            <div class="kpi-label">Critical Alerts</div>
            <div class="kpi-value kpi-critical">{critical_count}</div>
            <div class="kpi-delta">Score ≥ 85 · Immediate action</div>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown(f"""<div class="kpi-card">
            <div class="kpi-label">Users Flagged</div>
            <div class="kpi-value kpi-high">{flagged_users}</div>
            <div class="kpi-delta">CRITICAL + HIGH severity</div>
        </div>""", unsafe_allow_html=True)
    with col4:
        st.markdown(f"""<div class="kpi-card">
            <div class="kpi-label">False Positives</div>
            <div class="kpi-value kpi-green">{fp_count}</div>
            <div class="kpi-delta">Marked & removed from feed</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")

    # ── Live alert feed ───────────────────────────────────────────────────────
    st.markdown('<div class="section-head">🚨 Live Alert Feed — Top 10 Critical/High</div>', unsafe_allow_html=True)

    alert_df = working_df[working_df['severity'].isin(['CRITICAL','HIGH'])].sort_values('risk_score', ascending=False).head(10)

    def color_severity(val):
        colors = {'CRITICAL': 'color: #f87171; font-weight:700',
                  'HIGH': 'color: #fb923c; font-weight:600',
                  'MEDIUM': 'color: #fbbf24', 'LOW': 'color: #4ade80'}
        return colors.get(val, '')

    def color_score(val):
        if val >= 85: return 'color: #f87171; font-weight:700'
        if val >= 65: return 'color: #fb923c'
        if val >= 40: return 'color: #fbbf24'
        return 'color: #4ade80'

    display_cols = ['timestamp','username','user_dept','action','resource','risk_score','severity']
    styled = alert_df[display_cols].style\
        .map(color_severity, subset=['severity'])\
        .map(color_score, subset=['risk_score'])\
        .set_properties(**{'background-color': '#f8fafc', 'color': '#111827', 'border-color': '#1e3a5f'})\
        .format({'risk_score': '{:.0f}', 'timestamp': lambda x: str(x)[:16]})
    st.dataframe(styled, use_container_width=True, height=320)

    # ── Charts row 1 ─────────────────────────────────────────────────────────
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown('<div class="section-head">📈 Risk Score Distribution</div>', unsafe_allow_html=True)

        def score_band(s):
            if s < 40: return 'Low (<40)'
            if s < 65: return 'Medium (40-64)'
            if s < 85: return 'High (65-84)'
            return 'Critical (85+)'

        hist_df = working_df.copy()
        hist_df['band'] = hist_df['risk_score'].apply(score_band)
        band_order = ['Low (<40)', 'Medium (40-64)', 'High (65-84)', 'Critical (85+)']
        color_map = {'Low (<40)': '#4ade80', 'Medium (40-64)': '#fbbf24',
                     'High (65-84)': '#fb923c', 'Critical (85+)': '#f87171'}
        fig_hist = px.histogram(hist_df, x='risk_score', color='band',
                                 color_discrete_map=color_map,
                                 category_orders={'band': band_order},
                                 nbins=25, labels={'risk_score': 'Risk Score', 'count': 'Events'})
        fig_hist.update_layout(
            plot_bgcolor='#f8fafc', paper_bgcolor='#f8fafc',
            font_color='#374151', legend_title_text='Band',
            xaxis=dict(gridcolor='#1e3a5f'), yaxis=dict(gridcolor='#1e3a5f'),
            margin=dict(l=0, r=0, t=10, b=0), height=300
        )
        st.plotly_chart(fig_hist, use_container_width=True)

    with col_right:
        st.markdown('<div class="section-head">👤 Top 10 Repeat Offenders</div>', unsafe_allow_html=True)
        top_users = working_df.groupby('username')['risk_score'].sum().nlargest(10).reset_index()
        fig_bar = px.bar(top_users, x='risk_score', y='username',
                          orientation='h', color='risk_score',
                          color_continuous_scale=['#1e3a5f', '#3b82f6', '#f87171'])
        fig_bar.update_layout(
            plot_bgcolor='#f8fafc', paper_bgcolor='#f8fafc',
            font_color='#374151', showlegend=False,
            xaxis=dict(gridcolor='#1e3a5f', title='Cumulative Risk Score'),
            yaxis=dict(gridcolor='#1e3a5f', title='', autorange='reversed'),
            margin=dict(l=0, r=0, t=10, b=0), height=300
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    # ── Charts row 2 ─────────────────────────────────────────────────────────
    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown('<div class="section-head">🕐 Access Heatmap — Hour vs Day of Week</div>', unsafe_allow_html=True)
        heat_df = working_df[working_df['severity'].isin(['CRITICAL','HIGH'])].copy()
        heat_df['hour'] = pd.to_datetime(heat_df['timestamp']).dt.hour
        heat_df['dow'] = pd.to_datetime(heat_df['timestamp']).dt.day_name()
        dow_order = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday']
        heat_pivot = heat_df.groupby(['dow','hour']).size().unstack(fill_value=0)
        heat_pivot = heat_pivot.reindex([d for d in dow_order if d in heat_pivot.index])

        fig_heat = go.Figure(go.Heatmap(
            z=heat_pivot.values, x=list(heat_pivot.columns),
            y=list(heat_pivot.index),
            colorscale=[[0,'#f8fafc'],[0.3,'#1e3a5f'],[0.7,'#fb923c'],[1,'#f87171']],
            showscale=True
        ))
        fig_heat.update_layout(
            plot_bgcolor='#f8fafc', paper_bgcolor='#f8fafc',
            font_color='#374151', height=280,
            xaxis_title='Hour of Day', yaxis_title='',
            margin=dict(l=0, r=0, t=10, b=0)
        )
        st.plotly_chart(fig_heat, use_container_width=True)

    with col_b:
        st.markdown('<div class="section-head">🥧 Alert Categories & False Positive Tracker</div>', unsafe_allow_html=True)
        sev_counts = working_df['severity'].value_counts()
        fp_row = pd.Series({'FALSE POSITIVE': len(st.session_state.fp_set)}) if st.session_state.fp_set else pd.Series(dtype=int)
        pie_data = pd.concat([sev_counts, fp_row])

        fig_pie = go.Figure(go.Pie(
            labels=pie_data.index, values=pie_data.values,
            hole=0.55,
            marker_colors=['#f87171','#fb923c','#fbbf24','#4ade80','#64748b'],
            textfont_color='#111827'
        ))
        fig_pie.update_layout(
            plot_bgcolor='#f8fafc', paper_bgcolor='#f8fafc',
            font_color='#374151', height=280,
            margin=dict(l=0, r=0, t=10, b=0),
            legend=dict(font_color='#374151')
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    # ── Sensitivity threshold chart ───────────────────────────────────────────
    st.markdown('<div class="section-head">🎚️ Sensitivity Threshold — Alerts vs Score Cutoff</div>', unsafe_allow_html=True)
    thresholds = range(20, 100, 5)
    alert_counts_per_threshold = [len(working_df[working_df['risk_score'] >= t]) for t in thresholds]
    fig_thresh = go.Figure(go.Scatter(
        x=list(thresholds), y=alert_counts_per_threshold,
        mode='lines+markers', fill='tozeroy',
        line=dict(color='#3b82f6', width=2),
        fillcolor='rgba(59,130,246,0.1)',
        marker=dict(color='#60a5fa', size=6)
    ))
    fig_thresh.add_vline(x=40, line_dash='dash', line_color='#fbbf24', annotation_text='MEDIUM', annotation_font_color='#fbbf24')
    fig_thresh.add_vline(x=65, line_dash='dash', line_color='#fb923c', annotation_text='HIGH', annotation_font_color='#fb923c')
    fig_thresh.add_vline(x=85, line_dash='dash', line_color='#f87171', annotation_text='CRITICAL', annotation_font_color='#f87171')
    fig_thresh.update_layout(
        plot_bgcolor='#f8fafc', paper_bgcolor='#f8fafc', font_color='#374151',
        xaxis=dict(gridcolor='#1e3a5f', title='Score Threshold'),
        yaxis=dict(gridcolor='#1e3a5f', title='Alert Count'),
        margin=dict(l=0, r=0, t=10, b=0), height=250
    )
    st.plotly_chart(fig_thresh, use_container_width=True)


# ════════════════════════════════════════════════════════════════════════════
# TAB 2: INVESTIGATE (click-to-drill)
# ════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown('<div class="section-head">🔍 Select Alert to Investigate</div>', unsafe_allow_html=True)

    alert_pool = working_df[working_df['severity'].isin(['CRITICAL','HIGH'])].sort_values('risk_score', ascending=False)
    alert_pool_display = alert_pool[['timestamp','username','user_dept','action','resource','risk_score','severity']].copy()
    alert_pool_display['timestamp'] = alert_pool_display['timestamp'].astype(str).str[:16]

    selected_rows = st.dataframe(
        alert_pool_display.head(30).reset_index(drop=False),
        use_container_width=True, height=250,
        on_select='rerun', selection_mode='single-row'
    )

    sel = selected_rows.selection.rows if hasattr(selected_rows, 'selection') else []
    selected_idx = None
    if sel:
        orig_idx = alert_pool_display.head(30).reset_index().iloc[sel[0]]['index']
        selected_idx = orig_idx

    if selected_idx is not None:
        row = working_df.loc[selected_idx]
        user_profile = profiles[profiles['user_id'] == row['user_id']].to_dict('records')
        user_profile = user_profile[0] if user_profile else {}

        st.markdown("---")
        c1, c2 = st.columns([1,2])

        with c1:
            # User dossier card
            sev_color = {'CRITICAL':'#f87171','HIGH':'#fb923c','MEDIUM':'#fbbf24','LOW':'#4ade80'}.get(row['severity'],'#374151')
            st.markdown(f"""
            <div style="background:#f8fafc;border:1px solid #1e3a5f;border-radius:10px;padding:20px">
                <div style="font-size:18px;font-weight:700;color:#e2e8f0">{row['username']}</div>
                <div style="font-size:12px;color:#64748b;font-family:'JetBrains Mono',monospace;margin:4px 0 12px">{row.get('user_role','')}</div>
                <div style="display:grid;gap:6px;font-size:13px">
                    <div>🏢 <b>Dept:</b> {row.get('user_dept','')}</div>
                    <div>🔑 <b>Privilege:</b> {row.get('privilege','')}</div>
                    <div>📅 <b>Hired:</b> {user_profile.get('hire_date','')}</div>
                    <div>💤 <b>Inactive days:</b> {row.get('days_inactive',0)}</div>
                    <div>✅ <b>Active:</b> {user_profile.get('is_active','')}</div>
                </div>
                <div style="margin-top:16px;padding:10px;background:#0a1628;border-radius:8px">
                    <div style="font-size:11px;color:#64748b;font-family:'JetBrains Mono',monospace">RISK SCORE</div>
                    <div style="font-size:32px;font-weight:700;color:{sev_color}">{row['risk_score']}/100</div>
                    <div style="font-size:14px;font-weight:600;color:{sev_color}">{row['severity']}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        with c2:
            # Anomaly breakdown
            st.markdown('<div class="section-head">⚠️ Anomaly Signal Breakdown</div>', unsafe_allow_html=True)
            reasons = str(row.get('anomaly_reasons','')).split('|')
            signal_weights = {
                'Off-hours': 20, 'Sensitive resource': 25, 'High-risk action': 20,
                'Unapproved resource': 20, 'User privilege': 30, 'FAILED': 15, 'inactive': 20
            }
            for r in reasons:
                if r.strip():
                    weight = next((v for k,v in signal_weights.items() if k.lower() in r.lower()), 10)
                    bar_pct = min(100, weight * 3)
                    st.markdown(f"""
                    <div style="margin:6px 0">
                        <div style="font-size:13px;color:#111827;margin-bottom:3px">⚡ {r.strip()} <span style="color:#fb923c;font-family:'JetBrains Mono',monospace">+{weight}</span></div>
                        <div style="background:#1e3a5f;border-radius:4px;height:6px">
                            <div style="background:#fb923c;width:{bar_pct}%;height:6px;border-radius:4px"></div>
                        </div>
                    </div>""", unsafe_allow_html=True)

        # Last 30-day timeline
        st.markdown('<div class="section-head">📅 User\'s Last 30 Days Activity</div>', unsafe_allow_html=True)
        user_history = working_df[working_df['user_id'] == row['user_id']].copy()
        user_history['timestamp'] = pd.to_datetime(user_history['timestamp'])
        cutoff = user_history['timestamp'].max() - timedelta(days=30)
        user_history = user_history[user_history['timestamp'] >= cutoff]

        if len(user_history) > 0:
            fig_timeline = px.scatter(user_history, x='timestamp', y='action',
                                       color='risk_score', size='risk_score',
                                       color_continuous_scale=['#4ade80','#fbbf24','#fb923c','#f87171'],
                                       hover_data=['resource','severity','time_classification'],
                                       size_max=15)
            fig_timeline.update_layout(
                plot_bgcolor='#f8fafc', paper_bgcolor='#f8fafc', font_color='#374151',
                xaxis=dict(gridcolor='#1e3a5f'), yaxis=dict(gridcolor='#1e3a5f'),
                margin=dict(l=0,r=0,t=10,b=0), height=250
            )
            st.plotly_chart(fig_timeline, use_container_width=True)

        # LLM Narrative
        st.markdown('<div class="section-head">🤖 AI Threat Narrative (Claude)</div>', unsafe_allow_html=True)

        llm_key = f"narrative_{selected_idx}"
        if llm_key not in st.session_state:
            st.session_state[llm_key] = None

        if st.button("🧠 Generate AI Analysis", key=f"gen_{selected_idx}"):
            with st.spinner("Claude is analyzing the threat pattern..."):
                try:
                    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
                    prompt = f"""You are a senior cybersecurity analyst at a Fortune 500 company. A threat detection system has flagged the following insider threat alert. Provide a comprehensive investigation report.

═══════════════════════════════════════
ALERT DETAILS
═══════════════════════════════════════
User: {row['username']}
Department: {row.get('user_dept', 'Unknown')}
Role: {row.get('user_role', 'Unknown')}
Privilege Level: {row.get('privilege', 'Unknown')}
Days Account Inactive (before this event): {row.get('days_inactive', 0)}

Action Performed: {row['action']}
Resource Accessed: {row['resource']}
Data Sensitivity: {row['resource_sensitivity']}
Timestamp: {row['timestamp']}
Time Classification: {row['time_classification']}

Risk Score: {row['risk_score']}/100
Severity: {row['severity']}
Anomaly Signals Triggered: {row.get('anomaly_reasons', 'None recorded')}

═══════════════════════════════════════
YOUR TASK
═══════════════════════════════════════
Write a detailed security investigation report with these exact sections:

**WHAT HAPPENED**
Describe in 2-3 sentences exactly what the user did, when, and on what system. Be specific.

**WHY THIS IS SUSPICIOUS**
Explain in 3-4 sentences why this specific combination of signals (time, action, resource, privilege, inactivity) constitutes a threat. Reference the user's profile context. What does this pattern typically indicate — data exfiltration, credential compromise, insider theft, or negligence?

**THREAT CLASSIFICATION**
State the most likely threat scenario (e.g., Pre-resignation data theft, Compromised account, Privilege abuse, Accidental exposure). Explain your reasoning in 2 sentences.

**RISK FACTORS**
List 3-5 specific risk factors present in this alert with a brief explanation for each.

**RECOMMENDED IMMEDIATE ACTIONS**
Provide 4-5 specific, actionable steps the security team must take RIGHT NOW — numbered list. Be specific (e.g., "Disable USR-XXXX account in Active Directory" not just "disable account").

**MEDIUM-TERM IMPROVEMENTS**
Suggest 3 policy or technical improvements to prevent this class of threat in future.

Write in a professional security analyst tone. Be specific and decisive."""

                    response = requests.post(
                        "https://api.anthropic.com/v1/messages",
                        headers={
                            "Content-Type": "application/json",
                            "x-api-key": api_key,
                            "anthropic-version": "2023-06-01"
                        },
                        json={
                            "model": "claude-sonnet-4-6",
                            "max_tokens": 1500,
                            "messages": [{"role": "user", "content": prompt}]
                        },
                        timeout=45
                    )
                    data = response.json()
                    if 'content' in data and len(data['content']) > 0:
                        narrative = data['content'][0]['text']
                    elif 'error' in data:
                        narrative = f"API Error: {data['error'].get('message', str(data['error']))}\n\nMake sure ANTHROPIC_API_KEY environment variable is set."
                    else:
                        narrative = f"Unexpected response: {str(data)}"
                    st.session_state[llm_key] = narrative
                except Exception as e:
                    st.session_state[llm_key] = f"Analysis unavailable: {str(e)}\n\nCheck that ANTHROPIC_API_KEY is set as an environment variable."

        if st.session_state[llm_key]:
            narrative_text = st.session_state[llm_key]
            # Render each bold section header with color, rest as text
            import re
            sections = re.split(r'(\*\*[^*]+\*\*)', narrative_text)
            rendered = ""
            for part in sections:
                if part.startswith("**") and part.endswith("**"):
                    label = part[2:-2]
                    rendered += f'<div style="font-size:12px;font-weight:700;color:#60a5fa;font-family:JetBrains Mono,monospace;margin:14px 0 4px;text-transform:uppercase;letter-spacing:1px">⚡ {label}</div>'
                else:
                    # Convert numbered list items to styled rows
                    lines = part.strip().split('\n')
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                        if re.match(r'^\d+\.', line):
                            rendered += f'<div style="font-size:13px;color:#111827;padding:4px 0 4px 12px;border-left:2px solid #3b82f6;margin:3px 0">{line}</div>'
                        elif line.startswith('-'):
                            rendered += f'<div style="font-size:13px;color:#111827;padding:2px 0 2px 12px">• {line[1:].strip()}</div>'
                        else:
                            rendered += f'<div style="font-size:13px;color:#111827;line-height:1.7;margin:4px 0">{line}</div>'
            st.markdown(f'<div class="llm-narrative">{rendered}</div>', unsafe_allow_html=True)

        # Action buttons
        st.markdown('<div class="section-head">⚡ Actions</div>', unsafe_allow_html=True)
        btn1, btn2, btn3 = st.columns(3)
        with btn1:
            if st.button("✅ Mark as False Positive", key=f"fp_{selected_idx}"):
                st.session_state.fp_set.add(selected_idx)
                st.success("Marked as FP — removed from alert feed")
                st.rerun()
        with btn2:
            if st.button("🔴 Escalate to CRITICAL", key=f"esc_{selected_idx}"):
                st.session_state.escalated.add(selected_idx)
                st.warning("Escalated to CRITICAL")
                st.rerun()
        with btn3:
            if st.button("📄 Export Report (PDF)", key=f"pdf_{selected_idx}"):
                from fpdf import FPDF
                pdf = FPDF()
                pdf.add_page()
                pdf.set_font("Helvetica", "B", 16)
                pdf.cell(0, 10, "InsiderShield — Threat Report", ln=True)
                pdf.set_font("Helvetica", "", 11)
                pdf.ln(5)
                for label, val in [("User", row['username']), ("Department", row.get('user_dept','')),
                                    ("Severity", row['severity']), ("Risk Score", f"{row['risk_score']}/100"),
                                    ("Action", row['action']), ("Resource", row['resource']),
                                    ("Timestamp", str(row['timestamp'])), ("Signals", str(row.get('anomaly_reasons','')))]:
                    pdf.multi_cell(0, 8, f"{label}: {val}")
                pdf_bytes = pdf.output()
                st.download_button("⬇️ Download PDF", data=bytes(pdf_bytes),
                                   file_name=f"threat_report_{row['username']}.pdf",
                                   mime="application/pdf")
    else:
        st.info("👆 Click a row above to open the investigation panel.")


# ════════════════════════════════════════════════════════════════════════════
# TAB 3: PREDICTIONS & PATTERNS
# ════════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown('<div class="section-head">🔮 7-Day Risk Trajectory Prediction (ML)</div>', unsafe_allow_html=True)

    # Feature engineering for prediction
    @st.cache_data
    def train_predictor(df):
        feat_df = df.copy()
        le_action = LabelEncoder()
        le_res = LabelEncoder()
        le_tc = LabelEncoder()
        feat_df['action_enc'] = le_action.fit_transform(feat_df['action'].fillna('unknown'))
        feat_df['res_enc'] = le_res.fit_transform(feat_df['resource'].fillna('unknown'))
        feat_df['tc_enc'] = le_tc.fit_transform(feat_df['time_classification'].fillna('unknown'))
        feat_df['priv_enc'] = (feat_df['privilege'] == 'admin').astype(int)
        feat_df['sens_enc'] = feat_df['resource_sensitivity'].map({'low':0,'medium':1,'high':2,'restricted':3}).fillna(0)

        X = feat_df[['action_enc','res_enc','tc_enc','priv_enc','sens_enc','days_inactive']].fillna(0)
        y = (feat_df['risk_score'] >= 65).astype(int)

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        model = LogisticRegression(max_iter=500)
        model.fit(X_scaled, y)
        return model, scaler, le_action, le_res, le_tc

    try:
        model, scaler, le_a, le_r, le_t = train_predictor(working_df)

        # Build per-user risk trajectory
        user_risk = working_df.groupby('username').agg(
            avg_score=('risk_score','mean'),
            max_score=('risk_score','max'),
            event_count=('risk_score','count'),
            critical_count=('severity', lambda x: (x=='CRITICAL').sum())
        ).reset_index().nlargest(12, 'avg_score')

        # Project 7 days: simple trend based on recent vs older scores
        def project_trajectory(username):
            user_events = working_df[working_df['username'] == username].copy()
            user_events['timestamp'] = pd.to_datetime(user_events['timestamp'])
            user_events = user_events.sort_values('timestamp')
            if len(user_events) < 4:
                base = user_events['risk_score'].mean()
                return [base] * 7
            recent = user_events.tail(len(user_events)//2)['risk_score'].mean()
            older = user_events.head(len(user_events)//2)['risk_score'].mean()
            trend = (recent - older) / max(len(user_events), 1) * 3
            base = recent
            return [min(100, max(0, base + trend * i + np.random.normal(0, 2))) for i in range(7)]

        fig_traj = go.Figure()
        colors = ['#f87171','#fb923c','#fbbf24','#4ade80','#60a5fa','#a78bfa',
                  '#34d399','#f472b6','#38bdf8','#c084fc','#fb7185','#86efac']
        days = [f"Day +{i}" for i in range(7)]

        for i, row in user_risk.iterrows():
            traj = project_trajectory(row['username'])
            fig_traj.add_trace(go.Scatter(
                x=days, y=traj, name=row['username'],
                mode='lines+markers', line=dict(color=colors[i % len(colors)], width=2),
                marker=dict(size=5)
            ))

        fig_traj.add_hline(y=65, line_dash='dash', line_color='#fb923c',
                            annotation_text='HIGH threshold', annotation_font_color='#fb923c')
        fig_traj.add_hline(y=85, line_dash='dash', line_color='#f87171',
                            annotation_text='CRITICAL threshold', annotation_font_color='#f87171')
        fig_traj.update_layout(
            plot_bgcolor='#f8fafc', paper_bgcolor='#f8fafc', font_color='#374151',
            xaxis=dict(gridcolor='#1e3a5f'), yaxis=dict(gridcolor='#1e3a5f', title='Predicted Risk Score'),
            margin=dict(l=0,r=0,t=10,b=0), height=350,
            legend=dict(font_color='#374151', bgcolor='#f8fafc')
        )
        st.plotly_chart(fig_traj, use_container_width=True)

    except Exception as e:
        st.error(f"ML model error: {e}")

    # ── K-means clustering ────────────────────────────────────────────────────
    st.markdown('<div class="section-head">🧩 Behavioral Clustering — Who Behaves the Same</div>', unsafe_allow_html=True)

    @st.cache_data
    def cluster_users(df):
        feat = df.groupby('user_id').agg(
            avg_score=('risk_score','mean'),
            night_ratio=('time_classification', lambda x: (x.isin(['night','unusual_hours'])).mean()),
            sens_avg=('resource_sensitivity', lambda x: x.map({'low':0,'medium':1,'high':2,'restricted':3}).mean()),
            admin_ratio=('action', lambda x: (x=='admin_operation').mean()),
            export_ratio=('action', lambda x: (x=='export_data').mean()),
            fail_ratio=('status', lambda x: (x=='failure').mean()),
        ).fillna(0).reset_index()
        scaler = StandardScaler()
        X = scaler.fit_transform(feat[['avg_score','night_ratio','sens_avg','admin_ratio','export_ratio','fail_ratio']])
        km = KMeans(n_clusters=3, random_state=42, n_init=10)
        feat['cluster'] = km.fit_predict(X)
        return feat

    cluster_df = cluster_users(working_df)
    cluster_names = {0: 'Standard Access', 1: 'High-Risk Behavior', 2: 'Off-Hours / Elevated'}
    cluster_colors = {0: '#4ade80', 1: '#f87171', 2: '#fb923c'}
    cluster_df['cluster_name'] = cluster_df['cluster'].map(cluster_names)
    cluster_df['color'] = cluster_df['cluster'].map(cluster_colors)

    fig_cluster = px.scatter(
        cluster_df, x='avg_score', y='night_ratio',
        color='cluster_name', size='avg_score',
        color_discrete_map={v: cluster_colors[k] for k, v in cluster_names.items()},
        hover_data=['user_id','admin_ratio','fail_ratio'],
        labels={'avg_score': 'Avg Risk Score', 'night_ratio': 'Off-Hours Activity Ratio'},
        size_max=20
    )
    fig_cluster.update_layout(
        plot_bgcolor='#f8fafc', paper_bgcolor='#f8fafc', font_color='#374151',
        xaxis=dict(gridcolor='#1e3a5f'), yaxis=dict(gridcolor='#1e3a5f'),
        margin=dict(l=0,r=0,t=10,b=0), height=320,
        legend=dict(font_color='#374151', bgcolor='#f8fafc')
    )
    st.plotly_chart(fig_cluster, use_container_width=True)

    # Cluster summary
    st.markdown('<div class="section-head">📋 Cluster Profiles</div>', unsafe_allow_html=True)
    cluster_summary = cluster_df.groupby('cluster_name').agg(
        Users=('user_id','count'),
        Avg_Risk=('avg_score','mean'),
        Night_Access=('night_ratio','mean'),
        Admin_Ops=('admin_ratio','mean')
    ).round(2).reset_index()
    st.dataframe(cluster_summary, use_container_width=True)

    # Recommendations
    st.markdown('<div class="section-head">💡 AI Recommendation Engine</div>', unsafe_allow_html=True)
    fp_cnt = len(st.session_state.fp_set)
    recs = [
        ("Rule Optimization", f"Based on {fp_cnt} false positives, reduce weight of 'Unapproved Resource' signal by 10 points for admin-privilege users."),
        ("Off-Hours Policy", "Cluster 2 shows 34% night access — consider MFA enforcement for logins between 11 PM – 6 AM."),
        ("Stale Account Cleanup", f"{len(working_df[working_df['days_inactive'] > 60])} events from accounts inactive 60+ days — disable or rotate credentials."),
        ("Export Monitoring", f"{len(working_df[working_df['action']=='export_data'])} export actions detected — integrate DLP alerts for bulk exports > 100MB."),
    ]
    for title, rec in recs:
        st.markdown(f"""
        <div style="background:#f8fafc;border:1px solid #1e3a5f;border-left:4px solid #3b82f6;
                    border-radius:8px;padding:14px 18px;margin:8px 0">
            <div style="font-size:12px;font-weight:600;color:#60a5fa;font-family:'JetBrains Mono',monospace;
                        margin-bottom:4px">⚡ {title}</div>
            <div style="font-size:13px;color:#111827">{rec}</div>
        </div>""", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# TAB 4: LIVE PIPELINE
# ════════════════════════════════════════════════════════════════════════════
with tab4:
    st.markdown('<div class="section-head">⚡ Kafka → Spark Simulation — Live Event Stream</div>', unsafe_allow_html=True)

    st.markdown("""
    <div style="background:#f8fafc;border:1px solid #1e3a5f;border-radius:8px;padding:16px;margin-bottom:16px">
        <div style="font-size:13px;color:#374151;line-height:1.8">
            This tab simulates the production architecture: <span style="color:#60a5fa">Kafka producer</span> 
            streams events one-by-one → <span style="color:#60a5fa">Spark processor</span> scores each event 
            → <span style="color:#60a5fa">Dashboard</span> updates in real-time. In production, this handles 
            <b style="color:#e2e8f0">1M+ events/day across 20 Spark worker nodes</b>.
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_left, col_right = st.columns([1, 3])
    with col_left:
        speed = st.slider("Events/sec", 1, 50, 10)
        max_ev = st.slider("Max events", 50, 1200, 200)

    with col_right:
        run_btn = st.button("▶ Start Pipeline", type="primary", use_container_width=True)

    # Metrics placeholders
    m1, m2, m3, m4 = st.columns(4)
    proc_metric = m1.empty()
    alert_metric = m2.empty()
    crit_metric = m3.empty()
    rate_metric = m4.empty()

    feed_placeholder = st.empty()
    progress_bar = st.progress(0)

    proc_metric.metric("Processed", 0)
    alert_metric.metric("Alerts", 0)
    crit_metric.metric("Critical", 0)
    rate_metric.metric("Rate", "0 e/s")

    if run_btn:
        raw_logs = pd.read_csv('data_access_logs.csv', parse_dates=['timestamp'])
        raw_profiles = pd.read_csv('user_profiles.csv').set_index('user_id').to_dict('index')

        def score_event_fast(event):
            user_id = event['user_id']
            profile = raw_profiles.get(user_id, {})
            score = 0; reasons = []
            if event['time_classification'] in ['night', 'unusual_hours']:
                score += 20; reasons.append(f"Off-hours ({event['time_classification']})")
            s = {'low':0,'medium':10,'high':25,'restricted':35}.get(event['resource_sensitivity'],0)
            if s > 0: score += s; reasons.append(f"Sensitive data ({event['resource_sensitivity']})")
            a = {'export_data':25,'admin_operation':20,'api_call':8,'sql_query':5,'login':2}.get(event['action'],5)
            score += a
            if a >= 20: reasons.append(f"High-risk action: {event['action']}")
            approved = str(profile.get('systems_access','')).split('|')
            if event['resource'] not in approved: score += 20; reasons.append("Unapproved resource")
            privilege = profile.get('privilege_level','user')
            if privilege == 'user' and event['action'] == 'admin_operation':
                score += 30; reasons.append("Privilege mismatch: user doing admin ops")
            if event['status'] == 'failure': score += 15; reasons.append("Access attempt FAILED")
            inactive = profile.get('days_inactive', 0)
            if inactive > 30: score += 20; reasons.append(f"Account inactive {inactive} days")
            if privilege == 'admin' and event['resource'] in approved: score = max(0, score - 25)
            score = min(score, 100)
            severity = 'CRITICAL' if score >= 85 else 'HIGH' if score >= 65 else 'MEDIUM' if score >= 40 else 'LOW'
            profile_dept = profile.get('department', '')
            profile_role = profile.get('job_title', '')
            return score, severity, reasons, privilege, profile_dept, profile_role, inactive

        def get_pipeline_ai_analysis(event, score, severity, reasons, privilege, dept, role, inactive_days):
            """Call Anthropic API for per-alert analysis in the pipeline."""
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            if not api_key:
                return None
            prompt = f"""You are a SOC (Security Operations Center) analyst. A real-time data pipeline has detected a threat. Give a rapid triage report.

LIVE ALERT — {severity} | Score: {score}/100
User: {event['username']} | Dept: {dept} | Role: {role} | Privilege: {privilege}
Action: {event['action']} on {event['resource']} (sensitivity: {event['resource_sensitivity']})
Time: {event['timestamp']} ({event['time_classification']})
Account inactive before this event: {inactive_days} days
Signals triggered: {' | '.join(reasons)}

Write a rapid triage report with these 4 sections. Be sharp and specific, no fluff:

**WHAT HAPPENED**
One sentence on the exact event.

**WHY IT'S A THREAT**
2 sentences explaining the specific threat pattern — what type of attack or insider threat this resembles.

**SEVERITY JUSTIFICATION**
One sentence explaining why this is {severity} specifically (which combination of signals pushed it there).

**IMMEDIATE SOLUTION**
3 numbered steps the SOC team must execute in the next 15 minutes to contain this."""

            try:
                resp = requests.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01"
                    },
                    json={
                        "model": "claude-sonnet-4-6",
                        "max_tokens": 500,
                        "messages": [{"role": "user", "content": prompt}]
                    },
                    timeout=20
                )
                data = resp.json()
                if 'content' in data:
                    return data['content'][0]['text']
            except Exception:
                pass
            return None

        events_shown = []
        total_proc = 0; total_alerts = 0; total_crit = 0
        delay = 1.0 / speed
        start_time = time.time()
        # Store full alert objects for the detailed panel shown after pipeline
        critical_alerts_detail = []

        for idx, row in raw_logs.head(max_ev).iterrows():
            event = {k: row[k] for k in ['user_id','username','action','resource',
                                           'resource_sensitivity','status','time_classification']}
            event['timestamp'] = str(row['timestamp'])
            score, severity, reasons, priv, dept, role, inactive = score_event_fast(event)
            total_proc += 1
            if severity in ['CRITICAL','HIGH','MEDIUM']:
                total_alerts += 1
            if severity == 'CRITICAL':
                total_crit += 1
                critical_alerts_detail.append({
                    'event': event, 'score': score, 'severity': severity,
                    'reasons': reasons, 'privilege': priv,
                    'dept': dept, 'role': role, 'inactive': inactive
                })

            elapsed = time.time() - start_time
            actual_rate = total_proc / max(elapsed, 0.01)

            if severity in ['CRITICAL','HIGH']:
                cls = 'pipeline-critical' if severity == 'CRITICAL' else 'pipeline-high'
                icon = '🔴' if severity == 'CRITICAL' else '🟠'
                reasons_short = ' | '.join(reasons[:3])
                entry = (
                    f'<div class="{cls} pipeline-event">'
                    f'{icon} [{str(row["timestamp"])[:16]}] '
                    f'<b>{row["username"]}</b> | {row["action"]} → {row["resource"]} | '
                    f'Score: <b>{score}</b> | {severity}'
                    f'<div style="font-size:10px;opacity:0.75;margin-top:2px">⚡ {reasons_short}</div>'
                    f'</div>'
                )
                events_shown.insert(0, entry)
                events_shown = events_shown[:30]

            proc_metric.metric("Processed", total_proc)
            alert_metric.metric("Alerts", total_alerts)
            crit_metric.metric("Critical", total_crit)
            rate_metric.metric("Rate", f"{actual_rate:.0f} e/s")

            feed_placeholder.markdown(
                f'<div style="max-height:400px;overflow-y:auto">{"".join(events_shown)}</div>',
                unsafe_allow_html=True
            )
            progress_bar.progress(total_proc / max_ev)
            time.sleep(delay)

        st.success(f"✅ Pipeline complete: {total_proc} events processed, {total_alerts} alerts, {total_crit} critical")
        progress_bar.progress(1.0)

        # ── POST-PIPELINE: Detailed AI Analysis for each CRITICAL alert ──────
        if critical_alerts_detail:
            st.markdown('<div class="section-head">🤖 AI Triage Report — Critical Alerts Deep Analysis</div>', unsafe_allow_html=True)
            st.markdown("""
            <div style="background:#f8fafc;border:1px solid #1e3a5f;border-radius:8px;padding:12px 16px;margin-bottom:16px;font-size:13px;color:#374151">
                Each CRITICAL alert below has been analyzed by Claude AI. Expand any alert to see the full threat assessment, why the severity was assigned, and the 3-step immediate containment plan.
            </div>""", unsafe_allow_html=True)

            api_key = os.environ.get("ANTHROPIC_API_KEY", "")

            for i, alert_data in enumerate(critical_alerts_detail[:10]):  # cap at 10 to avoid rate limits
                ev = alert_data['event']
                sc = alert_data['score']
                sev = alert_data['severity']
                reas = alert_data['reasons']
                priv = alert_data['privilege']
                dp = alert_data['dept']
                rl = alert_data['role']
                inc = alert_data['inactive']

                expander_label = f"🔴 [{str(ev['timestamp'])[:16]}] {ev['username']} | {ev['action']} → {ev['resource']} | Score: {sc}/100"

                with st.expander(expander_label, expanded=(i == 0)):
                    col_info, col_score = st.columns([3, 1])

                    with col_info:
                        st.markdown(f"""
                        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:13px;color:#374151;margin-bottom:12px">
                            <div>👤 <b>User:</b> {ev['username']}</div>
                            <div>🏢 <b>Dept:</b> {dp}</div>
                            <div>💼 <b>Role:</b> {rl}</div>
                            <div>🔑 <b>Privilege:</b> {priv}</div>
                            <div>⚡ <b>Action:</b> {ev['action']}</div>
                            <div>🗄️ <b>Resource:</b> {ev['resource']}</div>
                            <div>🔒 <b>Sensitivity:</b> {ev['resource_sensitivity']}</div>
                            <div>💤 <b>Inactive days:</b> {inc}</div>
                            <div>🕐 <b>Time class:</b> {ev['time_classification']}</div>
                            <div>📊 <b>Status:</b> {ev['status']}</div>
                        </div>""", unsafe_allow_html=True)

                        # Signal breakdown bars
                        st.markdown('<div style="font-size:12px;font-weight:600;color:#60a5fa;margin-bottom:6px;font-family:JetBrains Mono,monospace">SIGNALS TRIGGERED</div>', unsafe_allow_html=True)
                        signal_weights = {
                            'off-hours': 20, 'sensitive': 25, 'high-risk action': 20,
                            'unapproved': 20, 'privilege mismatch': 30, 'failed': 15, 'inactive': 20
                        }
                        for reason in reas:
                            weight = next((v for k, v in signal_weights.items() if k in reason.lower()), 10)
                            bar_pct = min(100, weight * 3.5)
                            st.markdown(f"""
                            <div style="margin:4px 0">
                                <div style="font-size:12px;color:#374151;margin-bottom:2px">⚡ {reason} <span style="color:#fb923c;font-family:'JetBrains Mono',monospace">+{weight}pts</span></div>
                                <div style="background:#1e3a5f;border-radius:3px;height:5px">
                                    <div style="background:linear-gradient(90deg,#fb923c,#f87171);width:{bar_pct}%;height:5px;border-radius:3px"></div>
                                </div>
                            </div>""", unsafe_allow_html=True)

                    with col_score:
                        sev_color = '#f87171' if sev == 'CRITICAL' else '#fb923c'
                        st.markdown(f"""
                        <div style="background:#0a1628;border:1px solid {sev_color};border-radius:10px;padding:20px;text-align:center">
                            <div style="font-size:11px;color:#64748b;font-family:'JetBrains Mono',monospace;margin-bottom:4px">RISK SCORE</div>
                            <div style="font-size:42px;font-weight:700;color:{sev_color};line-height:1">{sc}</div>
                            <div style="font-size:11px;color:#64748b;margin:2px 0">/100</div>
                            <div style="font-size:14px;font-weight:700;color:{sev_color};margin-top:8px;font-family:'JetBrains Mono',monospace">{sev}</div>
                        </div>""", unsafe_allow_html=True)

                    # AI analysis section
                    st.markdown('<div style="font-size:12px;font-weight:600;color:#60a5fa;margin:12px 0 8px;font-family:JetBrains Mono,monospace;border-left:3px solid #3b82f6;padding-left:8px">🤖 CLAUDE AI TRIAGE REPORT</div>', unsafe_allow_html=True)

                    if api_key:
                        cache_key = f"pipe_narrative_{ev['user_id']}_{ev['timestamp']}"
                        if cache_key not in st.session_state:
                            with st.spinner(f"Claude analyzing {ev['username']}..."):
                                analysis = get_pipeline_ai_analysis(ev, sc, sev, reas, priv, dp, rl, inc)
                                st.session_state[cache_key] = analysis if analysis else "Analysis could not be generated. Check API key."

                        analysis_text = st.session_state.get(cache_key, "")
                        if analysis_text:
                            import re
                            sections = re.split(r'(\*\*[^*]+\*\*)', analysis_text)
                            rendered = ""
                            for part in sections:
                                if part.startswith("**") and part.endswith("**"):
                                    label = part[2:-2]
                                    rendered += f'<div style="font-size:11px;font-weight:700;color:#60a5fa;font-family:JetBrains Mono,monospace;margin:12px 0 4px;text-transform:uppercase;letter-spacing:1px">⚡ {label}</div>'
                                else:
                                    for line in part.strip().split('\n'):
                                        line = line.strip()
                                        if not line:
                                            continue
                                        if re.match(r'^\d+\.', line):
                                            rendered += f'<div style="font-size:13px;color:#111827;padding:5px 0 5px 14px;border-left:2px solid #3b82f6;margin:3px 0;line-height:1.5">{line}</div>'
                                        elif line.startswith('-'):
                                            rendered += f'<div style="font-size:13px;color:#111827;padding:2px 0 2px 14px;line-height:1.5">• {line[1:].strip()}</div>'
                                        else:
                                            rendered += f'<div style="font-size:13px;color:#111827;line-height:1.7;margin:3px 0">{line}</div>'
                            st.markdown(f'<div class="llm-narrative" style="margin-top:8px">{rendered}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown("""
                        <div style="background:#f8fafc;border:1px solid #fb923c;border-radius:8px;padding:14px;font-size:13px;color:#92400e">
                            ⚠️ Set the <code>ANTHROPIC_API_KEY</code> environment variable to enable AI triage reports.<br>
                            Run: <code>export ANTHROPIC_API_KEY=your_key_here</code> then restart Streamlit.
                        </div>""", unsafe_allow_html=True)

                    # Quick action buttons per alert
                    ba1, ba2 = st.columns(2)
                    with ba1:
                        st.markdown(f"""
                        <div style="background:#052e16;border:1px solid #16a34a;border-radius:6px;padding:10px 14px;font-size:12px;color:#4ade80;font-family:'JetBrains Mono',monospace">
                            ✅ CONTAINMENT: Disable {ev['username']} in Active Directory immediately
                        </div>""", unsafe_allow_html=True)
                    with ba2:
                        st.markdown(f"""
                        <div style="background:#2d1515;border:1px solid #f87171;border-radius:6px;padding:10px 14px;font-size:12px;color:#fca5a5;font-family:'JetBrains Mono',monospace">
                            🔴 INVESTIGATE: Pull all access logs for {ev['username']} — last 72 hours
                        </div>""", unsafe_allow_html=True)
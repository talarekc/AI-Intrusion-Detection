import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import random

# Page setup
st.set_page_config(page_title="AI Threat Detection Dashboard", layout="wide", initial_sidebar_state="expanded")

# Custom CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    .stApp {
        background-color: #0a0e17;
    }

    header[data-testid="stHeader"] {
        background-color: #0a0e17;
    }

    section[data-testid="stSidebar"] {
        background-color: #111827;
        border-right: 1px solid #1e293b;
    }

    section[data-testid="stSidebar"] .stMarkdown p,
    section[data-testid="stSidebar"] .stMarkdown label,
    section[data-testid="stSidebar"] span {
        color: #94a3b8 !important;
    }

    .main-header {
        font-family: 'Inter', sans-serif;
        font-size: 2rem;
        font-weight: 700;
        color: #f1f5f9;
        margin-bottom: 0.25rem;
    }

    .sub-header {
        font-family: 'Inter', sans-serif;
        font-size: 0.95rem;
        color: #64748b;
        margin-bottom: 2rem;
    }

    .metric-card {
        background: linear-gradient(135deg, #111827, #1e293b);
        border: 1px solid #1e293b;
        border-radius: 12px;
        padding: 1.25rem;
        text-align: center;
    }

    .metric-value {
        font-family: 'Inter', sans-serif;
        font-size: 2rem;
        font-weight: 700;
        margin: 0.25rem 0;
    }

    .metric-label {
        font-family: 'Inter', sans-serif;
        font-size: 0.8rem;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    .blue { color: #3b82f6; }
    .red { color: #ef4444; }
    .green { color: #22c55e; }
    .yellow { color: #eab308; }

    .section-title {
        font-family: 'Inter', sans-serif;
        font-size: 1.1rem;
        font-weight: 600;
        color: #e2e8f0;
        margin: 1.5rem 0 0.75rem 0;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid #1e293b;
    }

    .severity-critical {
        background: #991b1b;
        color: #fca5a5;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
    }

    .severity-warning {
        background: #92400e;
        color: #fde68a;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
    }

    .severity-low {
        background: #14532d;
        color: #86efac;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid #1e293b;
        border-radius: 12px;
        overflow: hidden;
    }

    .stPlotlyChart {
        background: #111827;
        border: 1px solid #1e293b;
        border-radius: 12px;
        padding: 0.5rem;
    }

    .live-dot {
        display: inline-block;
        width: 8px;
        height: 8px;
        background: #22c55e;
        border-radius: 50%;
        margin-right: 6px;
        animation: pulse 2s infinite;
    }

    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.3; }
    }

    /* Fix all dark-on-dark text issues */
    .stApp, .stApp p, .stApp span, .stApp label, .stApp div {
        color: #e2e8f0;
    }

    /* Sidebar text */
    section[data-testid="stSidebar"] * {
        color: #94a3b8 !important;
    }

    /* Multiselect tags */
    span[data-baseweb="tag"] {
        background-color: #1e3a5f !important;
        color: #93c5fd !important;
    }

    span[data-baseweb="tag"] span {
        color: #93c5fd !important;
    }

    /* Slider text */
    div[data-testid="stSlider"] p,
    div[data-testid="stSlider"] div {
        color: #94a3b8 !important;
    }

    /* Multiselect dropdown */
    div[data-baseweb="popover"] li {
        color: #e2e8f0 !important;
        background-color: #1e293b !important;
    }

    div[data-baseweb="popover"] li:hover {
        background-color: #334155 !important;
    }

    /* Input fields */
    div[data-baseweb="select"] > div {
        background-color: #1e293b !important;
        border-color: #334155 !important;
        color: #e2e8f0 !important;
    }

    /* Dataframe */
    div[data-testid="stDataFrame"] * {
        color: #e2e8f0 !important;
    }

    /* Metric labels if using st.metric */
    div[data-testid="stMetric"] label,
    div[data-testid="stMetric"] div {
        color: #e2e8f0 !important;
    }

    /* Expander text */
    details summary span {
        color: #e2e8f0 !important;
    }
</style>
""", unsafe_allow_html=True)

# Generate fake data
random.seed(42)
attack_types = ["Benign", "Port Scan", "Brute Force", "DDoS", "Web Attack"]
severity_map = {"Port Scan": "Low", "Brute Force": "Critical", "DDoS": "Critical", "Web Attack": "Warning", "Benign": "None"}
data = []
for i in range(300):
    timestamp = datetime.now() - timedelta(minutes=random.randint(1, 1440))
    attack = random.choices(attack_types, weights=[50, 15, 15, 10, 10])[0]
    confidence = round(random.uniform(0.7, 0.99), 2) if attack != "Benign" else round(random.uniform(0.88, 0.99), 2)
    src_ip = f"192.168.1.{random.randint(1, 254)}"
    dst_ip = f"10.0.0.{random.randint(1, 50)}"
    src_port = random.choice([22, 80, 443, 445, 3389, 8080, random.randint(1024, 65535)])
    data.append({
        "Timestamp": timestamp,
        "Source IP": src_ip,
        "Src Port": src_port,
        "Destination IP": dst_ip,
        "Classification": attack,
        "Severity": severity_map[attack],
        "Confidence": confidence
    })

df = pd.DataFrame(data).sort_values("Timestamp", ascending=False).reset_index(drop=True)

# Sidebar
with st.sidebar:
    st.markdown("### Filters")
    st.markdown("---")
    selected_types = st.multiselect("Attack Type", attack_types, default=attack_types)
    min_confidence = st.slider("Min Confidence", 0.0, 1.0, 0.7)
    severity_filter = st.multiselect("Severity", ["Critical", "Warning", "Low", "None"], default=["Critical", "Warning", "Low", "None"])
    st.markdown("---")
    st.markdown("##### Model Info")
    st.markdown("""
    <div style='color: #64748b; font-size: 0.8rem; line-height: 1.6;'>
    Model: Random Forest<br>
    Dataset: CICIDS2017<br>
    F1 Score: 0.94<br>
    Status: <span class='live-dot'></span><span style='color: #22c55e;'>Active</span>
    </div>
    """, unsafe_allow_html=True)

# Apply filters
filtered = df[
    (df["Classification"].isin(selected_types)) &
    (df["Confidence"] >= min_confidence) &
    (df["Severity"].isin(severity_filter))
]

threats = filtered[filtered["Classification"] != "Benign"]

# Header
st.markdown('<div class="main-header">AI Threat Detection Dashboard</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header"><span class="live-dot"></span>Monitoring network traffic in real time</div>', unsafe_allow_html=True)

# Metric cards
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Total Events</div>
        <div class="metric-value blue">{len(filtered)}</div>
    </div>""", unsafe_allow_html=True)
with col2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Threats Detected</div>
        <div class="metric-value red">{len(threats)}</div>
    </div>""", unsafe_allow_html=True)
with col3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Benign Traffic</div>
        <div class="metric-value green">{len(filtered) - len(threats)}</div>
    </div>""", unsafe_allow_html=True)
with col4:
    avg_conf = f"{threats['Confidence'].mean():.0%}" if len(threats) > 0 else "N/A"
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">Avg Threat Confidence</div>
        <div class="metric-value yellow">{avg_conf}</div>
    </div>""", unsafe_allow_html=True)

st.markdown("")

# Charts
left, right = st.columns(2)

chart_layout = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter", color="#94a3b8"),
    margin=dict(l=20, r=20, t=40, b=20),
    legend=dict(font=dict(size=11, color="#e2e8f0")),
)

color_map = {
    "Port Scan": "#3b82f6",
    "Brute Force": "#ef4444",
    "DDoS": "#f97316",
    "Web Attack": "#a855f7"
}

with left:
    st.markdown('<div class="section-title">Threats by Type</div>', unsafe_allow_html=True)
    type_counts = threats["Classification"].value_counts().reset_index()
    type_counts.columns = ["Attack Type", "Count"]
    fig1 = px.bar(
        type_counts, x="Attack Type", y="Count",
        color="Attack Type",
        color_discrete_map=color_map
    )
    fig1.update_layout(**chart_layout, showlegend=False)
    fig1.update_traces(marker_line_width=0)
    fig1.update_xaxes(gridcolor="#1e293b")
    fig1.update_yaxes(gridcolor="#1e293b")
    st.plotly_chart(fig1, use_container_width=True, config={"displayModeBar": False})

with right:
    st.markdown('<div class="section-title">Threat Distribution</div>', unsafe_allow_html=True)
    fig2 = px.pie(
        type_counts, values="Count", names="Attack Type",
        color="Attack Type",
        color_discrete_map=color_map,
        hole=0.45
    )
    fig2.update_layout(**chart_layout)
    fig2.update_traces(textfont_color="#e2e8f0", textinfo="percent+label")
    st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})

# Timeline chart
st.markdown('<div class="section-title">Threat Activity (Last 24 Hours)</div>', unsafe_allow_html=True)
threats_timeline = threats.copy()
threats_timeline["Hour"] = threats_timeline["Timestamp"].dt.floor("h")
hourly = threats_timeline.groupby(["Hour", "Classification"]).size().reset_index(name="Count")
fig3 = px.area(
    hourly, x="Hour", y="Count", color="Classification",
    color_discrete_map=color_map
)
fig3.update_layout(**chart_layout, height=300)
fig3.update_xaxes(gridcolor="#1e293b")
fig3.update_yaxes(gridcolor="#1e293b")
st.plotly_chart(fig3, use_container_width=True, config={"displayModeBar": False})

# Alert log
st.markdown('<div class="section-title">Alert Log</div>', unsafe_allow_html=True)
display_df = filtered[filtered["Classification"] != "Benign"][["Timestamp", "Source IP", "Src Port", "Destination IP", "Classification", "Severity", "Confidence"]].head(50)
st.dataframe(
    display_df.style.format({"Confidence": "{:.0%}", "Timestamp": lambda x: x.strftime("%Y-%m-%d %H:%M")}),
    use_container_width=True,
    height=600
)

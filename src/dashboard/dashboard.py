import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import plotly.express as px
import json
import os
from datetime import datetime, timedelta

# Page setup
st.set_page_config(page_title="AI Threat Detection Dashboard", layout="wide", initial_sidebar_state="expanded")

# NOTE: no st_autorefresh - it reloads the whole page (causes a black flash).
# The map/log/summary update live inside the iframe. The charts below re-read
# alert_history.json whenever the page reruns for any reason (e.g. a filter
# change), and there is a manual "Refresh charts" button next to them.

# Custom CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    .stApp { background-color: #0a0e17; }
    header[data-testid="stHeader"] { background-color: #0a0e17; }
    section[data-testid="stSidebar"] { background-color: #111827; border-right: 1px solid #1e293b; }
    section[data-testid="stSidebar"] .stMarkdown p,
    section[data-testid="stSidebar"] .stMarkdown label,
    section[data-testid="stSidebar"] span { color: #94a3b8 !important; }

    .main-header { font-family: 'Inter', sans-serif; font-size: 2rem; font-weight: 700; color: #f1f5f9; margin-bottom: 0.25rem; }
    .sub-header { font-family: 'Inter', sans-serif; font-size: 0.95rem; color: #64748b; margin-bottom: 2rem; }

    .metric-card { background: linear-gradient(135deg, #111827, #1e293b); border: 1px solid #1e293b; border-radius: 12px; padding: 1.25rem; text-align: center; }
    .metric-value { font-family: 'Inter', sans-serif; font-size: 2rem; font-weight: 700; margin: 0.25rem 0; }
    .metric-label { font-family: 'Inter', sans-serif; font-size: 0.8rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }

    .blue { color: #3b82f6; }
    .red { color: #ef4444; }
    .green { color: #22c55e; }
    .yellow { color: #eab308; }

    .section-title { font-family: 'Inter', sans-serif; font-size: 1.1rem; font-weight: 600; color: #e2e8f0; margin: 1.5rem 0 0.75rem 0; padding-bottom: 0.5rem; border-bottom: 1px solid #1e293b; }

    div[data-testid="stDataFrame"] { border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; }
    .stPlotlyChart { background: #111827; border: 1px solid #1e293b; border-radius: 12px; padding: 0.5rem; }

    .live-dot { display: inline-block; width: 8px; height: 8px; background: #22c55e; border-radius: 50%; margin-right: 6px; animation: pulse 2s infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }

    .stApp, .stApp p, .stApp span, .stApp label, .stApp div { color: #e2e8f0; }
    section[data-testid="stSidebar"] * { color: #94a3b8 !important; }
    span[data-baseweb="tag"] { background-color: #1e3a5f !important; color: #93c5fd !important; }
    span[data-baseweb="tag"] span { color: #93c5fd !important; }
    div[data-testid="stSlider"] p, div[data-testid="stSlider"] div { color: #94a3b8 !important; }
    div[data-baseweb="popover"] li { color: #e2e8f0 !important; background-color: #1e293b !important; }
    div[data-baseweb="popover"] li:hover { background-color: #334155 !important; }
    div[data-baseweb="select"] > div { background-color: #1e293b !important; border-color: #334155 !important; color: #e2e8f0 !important; }
    div[data-testid="stDataFrame"] * { color: #e2e8f0 !important; }
    div[data-testid="stMetric"] label, div[data-testid="stMetric"] div { color: #e2e8f0 !important; }
    details summary span { color: #e2e8f0 !important; }
    .block-container { max-width: 1400px !important; margin-left: auto !important; margin-right: auto !important; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# CONFIG - update these paths if needed
# ---------------------------------------------------------------------------


MODEL_INFO = {
    "name": "Random Forest",
    "dataset": "CICIDS2017",
    "f1_score": 0.9999,
    "classes": ["BENIGN", "DDoS", "Port Scan", "Brute Force", "Web Attack"],
}

# ---------------------------------------------------------------------------
# CAPTURED THREATS - the ENTIRE dashboard is driven by the real attacks captured
# by capture.py and saved to alert_history.json. There is no mock/CSV data: the
# metric cards, charts, alert log and map all reflect the simulated attacks you
# actually run, and the Clear log button empties everything.
# ---------------------------------------------------------------------------

ALERT_HISTORY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alert_history.json")

# Clear-log state lives in session_state so the button (rendered later, next to
# the map) can wipe everything on the SAME run, before any data is loaded below.
clear_log = st.session_state.pop("do_clear_log", False)
if clear_log:
    # Wipe the saved alert history AND the current live events, so a scan that is
    # still in flight can't immediately re-populate the log after clearing.
    for _p in (
        ALERT_HISTORY_PATH,
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_events.json"),
    ):
        try:
            if os.path.exists(_p):
                os.remove(_p)
        except OSError:
            pass

_captured_rows = []
if not clear_log and os.path.exists(ALERT_HISTORY_PATH):
    try:
        with open(ALERT_HISTORY_PATH, "r") as f:
            _captured_rows = json.load(f)
    except (json.JSONDecodeError, IOError):
        _captured_rows = []

captured = pd.DataFrame(_captured_rows, columns=["time", "ts", "srcIp", "dstIp", "attack", "confidence"])
if not captured.empty:
    captured = captured.rename(columns={"attack": "Classification", "confidence": "Confidence"})
    captured["Timestamp"] = pd.to_datetime(captured["ts"], errors="coerce")
    captured["Confidence"] = pd.to_numeric(captured["Confidence"], errors="coerce").fillna(0.0)
else:
    captured = pd.DataFrame(columns=["Classification", "Confidence", "Timestamp", "srcIp", "dstIp"])

# Attack types the model can report (used for the filter list and chart colors).
ATTACK_CLASSES = ["DDoS", "Port Scan", "Brute Force", "Web Attack"]

# ---------------------------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("### Filters")
    st.markdown("---")
    selected_types = st.multiselect("Attack Type", ATTACK_CLASSES, default=ATTACK_CLASSES)
    min_confidence = st.slider("Min Confidence", 0.0, 1.0, 0.7)
    st.markdown("---")
    st.markdown("##### Model Info")
    f1_display = f"{MODEL_INFO['f1_score']:.4f}" if MODEL_INFO["f1_score"] is not None else "Pending"
    st.markdown(f"""
    <div style='color: #64748b; font-size: 0.8rem; line-height: 1.6;'>
    Model: {MODEL_INFO['name']}<br>
    Dataset: {MODEL_INFO['dataset']}<br>
    F1 Score: {f1_display}<br>
    Status: <span class='live-dot'></span><span style='color: #22c55e;'>Active</span>
    </div>
    """, unsafe_allow_html=True)

# Apply the sidebar filters to the captured attacks.
captured_threats = captured[
    captured["Classification"].isin(selected_types)
    & (captured["Confidence"] >= min_confidence)
    & (captured["Classification"] != "BENIGN")
]

# ---------------------------------------------------------------------------
# HEADER
# ---------------------------------------------------------------------------

st.markdown('<div class="main-header">AI Threat Detection Dashboard</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header"><span class="live-dot"></span>Monitoring network traffic in real time</div>', unsafe_allow_html=True)

# NOTE: the four summary cards (Threats Detected / Attack Types / Attacking
# Sources / Avg Threat Confidence) now live INSIDE the live map iframe, just
# above the alert log, so they update live and stay exactly 1:1 with the log.

# ---------------------------------------------------------------------------
# CHART CONFIG
# ---------------------------------------------------------------------------

chart_layout = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter", color="#94a3b8"),
    margin=dict(l=20, r=20, t=40, b=20),
    legend=dict(font=dict(size=11, color="#e2e8f0")),
)

color_map = {
    "BENIGN":      "#22c55e",
    "DDoS":        "#ef4444",
    "Port Scan":   "#3b82f6",
    "Brute Force": "#f97316",
    "Web Attack":  "#a855f7",
}

# ---------------------------------------------------------------------------
# LIVE MAP - driven by live capture (capture.py)
# ---------------------------------------------------------------------------

_title_col, _btn_col = st.columns([4, 1], vertical_alignment="center")
with _title_col:
    st.markdown('<div class="section-title" style="margin:0;border:none;padding:0;">Live Traffic Map</div>', unsafe_allow_html=True)
with _btn_col:
    # Set a flag and rerun; the handler at the top of the script does the actual
    # wipe before any data is loaded, so metrics, charts, log and map all clear.
    if st.button("🗑 Clear log", use_container_width=True):
        st.session_state["do_clear_log"] = True
        st.rerun()

# Read live events written by capture.py - empty when no attack is running
LIVE_EVENTS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_events.json")
map_events = []
if os.path.exists(LIVE_EVENTS_PATH):
    try:
        with open(LIVE_EVENTS_PATH, "r") as f:
            raw = json.load(f)
        map_events = [
            {
                "srcIp":      e.get("srcIp", "0.0.0.0"),
                "dstIp":      e.get("dstIp", "0.0.0.0"),
                "attack":     e.get("attack", "Unknown"),
                "confidence": round(float(e.get("confidence", 0)), 3),
            }
            for e in raw if e.get("attack") != "BENIGN"
        ]
    except (json.JSONDecodeError, IOError):
        map_events = []

# Load the saved alert history to seed the map iframe's log on first render.
# From here on, the iframe itself appends new alerts and POSTs them back to
# serve_events.py (no Streamlit reruns), so the map can stay live without the
# page reloading. We just read + apply the rolling 24h window here.
alert_history = []
if not clear_log and os.path.exists(ALERT_HISTORY_PATH):
    try:
        with open(ALERT_HISTORY_PATH, "r") as f:
            alert_history = json.load(f)
    except (json.JSONDecodeError, IOError):
        alert_history = []

# Rolling 24-hour window: drop alerts older than a day. The table only shows the
# time (no date), so keeping older rows would be ambiguous. Rows without a "ts"
# are from before this change; keep them so nothing is wiped unexpectedly.
cutoff = (datetime.now() - timedelta(hours=24)).isoformat(timespec="seconds")
alert_history = [a for a in alert_history if a.get("ts", cutoff) >= cutoff]

try:
    with open(ALERT_HISTORY_PATH, "w") as f:
        json.dump(alert_history, f)
except IOError:
    pass

# The map still animates the *current* events; the alert log shows full history.
map_events_json = json.dumps(map_events)
alert_history_json = json.dumps(alert_history)
# Tell the iframe to start empty AND overwrite disk when Clear log was pressed,
# so the still-running old iframe can't re-POST the old log back.
clear_log_js = "true" if clear_log else "false"
# Nonce only changes on a CLEAR, forcing Streamlit to remount a fresh iframe so
# the old poll loop can't keep the log alive. It must NOT depend on the live
# history length, or the iframe would remount on every refresh and reset the map
# view. A persistent counter keeps the HTML stable between clears.
if clear_log:
    st.session_state["clear_nonce"] = st.session_state.get("clear_nonce", 0) + 1
iframe_nonce = st.session_state.get("clear_nonce", 0)

LIVE_MAP_HTML = f"""
<!DOCTYPE html>
<!-- nonce:{iframe_nonce} -->
<html>
<head>
<meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://unpkg.com/deck.gl@8.9.36/dist.min.js"></script>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0a0e17; font-family: 'Inter', sans-serif; color: #e2e8f0; display: flex; flex-direction: column; height: 100vh; }}
  #status {{ color: #64748b; font-size: 0.82rem; padding: 6px 10px; flex-shrink: 0; }}
  .dot {{ display: inline-block; width: 8px; height: 8px; background: #22c55e; border-radius: 50%; margin-right: 6px; animation: blink 2s infinite; }}
  @keyframes blink {{ 0%,100% {{ opacity: 1 }} 50% {{ opacity: 0.3 }} }}
  #map-wrap {{ position: relative; flex: 1; min-height: 0; }}
  #live-map {{ width: 100%; height: 100%; }}
  .legend {{ position: absolute; top: 10px; right: 10px; background: rgba(15,20,30,0.85); padding: 10px 14px; border-radius: 6px; font-size: 0.78rem; z-index: 10; border: 1px solid #1e293b; }}
  .legend-row {{ font-size:0.7rem;color:#475569;margin-bottom:6px;text-transform:uppercase;letter-spacing:0.05em; }}
  .legend-item {{ display: flex; align-items: center; margin-bottom: 5px; }}
  .legend-item:last-child {{ margin-bottom: 0; }}
  .legend-box {{ width: 16px; height: 3px; margin-right: 8px; border-radius: 1px; }}
  #summary-bar {{ display: flex; gap: 10px; padding: 8px 10px; flex-shrink: 0; background: #0a0e17; border-top: 1px solid #1e293b; }}
  .summary-card {{ flex: 1; background: linear-gradient(135deg, #111827, #1e293b); border: 1px solid #1e293b; border-radius: 10px; padding: 8px 12px; text-align: center; }}
  .summary-value {{ font-size: 1.5rem; font-weight: 700; line-height: 1.1; }}
  .summary-label {{ font-size: 0.62rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 2px; }}
  #alert-panel {{ flex-shrink: 0; height: 215px; background: #0d1117; border-top: 1px solid #1e293b; display: flex; flex-direction: column; overflow: hidden; }}
  #alert-panel-header {{ display: flex; justify-content: space-between; align-items: center; padding: 5px 12px; border-bottom: 1px solid #1e293b; flex-shrink: 0; }}
  #alert-panel-header .title {{ font-size: 0.75rem; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.06em; }}
  #alert-count {{ font-size: 0.72rem; color: #475569; }}
  #alert-scroll {{ overflow-y: auto; overflow-x: auto; flex: 1; }}
  #alert-table {{ width: 100%; border-collapse: collapse; font-size: 0.74rem; }}
  #alert-table thead th {{ position: sticky; top: 0; z-index: 2; background: #111827; color: #475569; text-transform: uppercase; font-size: 0.63rem; letter-spacing: 0.05em; padding: 3px 10px; text-align: left; border-bottom: 1px solid #1e293b; white-space: nowrap; }}
  #alert-table td {{ padding: 3px 10px; color: #cbd5e1; border-bottom: 1px solid rgba(30,41,59,0.4); white-space: nowrap; }}
  #alert-table tr:hover td {{ background: rgba(30,41,59,0.4); }}
  @keyframes rowIn {{
    from {{ opacity: 0; transform: translateY(8px); background: rgba(239,68,68,0.15); }}
    to   {{ opacity: 1; transform: translateY(0);   background: transparent; }}
  }}
  /* Animate the cells, not the <tr>: transforms on table rows are unreliable across browsers.
     No "forwards" so the cells return to their natural state (no lingering transform, which
     would otherwise paint the row on top of the sticky header). */
  .row-new td {{ animation: rowIn 0.45s ease-out; }}
</style>
</head>
<body>
  <div id="status"><span class="dot"></span>Live monitoring | <span id="count">0</span> packets in flight</div>
  <div id="map-wrap">
    <div id="live-map"></div>
    <div class="legend">
      <div class="legend-row">Model Output</div>
      <div class="legend-item"><div class="legend-box" style="background:#ef4444;"></div> DDoS</div>
      <div class="legend-item"><div class="legend-box" style="background:#3b82f6;"></div> Port Scan</div>
      <div class="legend-item"><div class="legend-box" style="background:#f97316;"></div> Brute Force</div>
      <div class="legend-item"><div class="legend-box" style="background:#a855f7;"></div> Web Attack</div>
      <div class="legend-item"><div class="legend-box" style="background:#22c55e;"></div> BENIGN</div>
      <div class="legend-item"><div class="legend-box" style="background:#ffffff;width:10px;height:10px;border-radius:50%;"></div> Target (SHU)</div>
    </div>
  </div>
  <div id="summary-bar">
    <div class="summary-card"><div class="summary-value" style="color:#ef4444;" id="sum-threats">0</div><div class="summary-label">Threats Detected</div></div>
    <div class="summary-card"><div class="summary-value" style="color:#3b82f6;" id="sum-types">0</div><div class="summary-label">Attack Types</div></div>
    <div class="summary-card"><div class="summary-value" style="color:#eab308;" id="sum-sources">0</div><div class="summary-label">Attacking Sources</div></div>
    <div class="summary-card"><div class="summary-value" style="color:#22c55e;" id="sum-conf">N/A</div><div class="summary-label">Avg Threat Confidence</div></div>
  </div>
  <div id="alert-panel">
    <div id="alert-panel-header">
      <span class="title">Real-Time Alert Log</span>
      <span id="alert-count">0 threats detected</span>
    </div>
    <div id="alert-scroll">
      <table id="alert-table">
        <thead><tr><th>Time</th><th>Source IP</th><th>Dest IP</th><th>Classification</th><th>Confidence</th></tr></thead>
        <tbody id="alert-tbody"><tr><td colspan="5" style="color:#475569;text-align:center;padding:16px;">Waiting for live threats. Run capture.py to begin monitoring.</td></tr></tbody>
      </table>
    </div>
  </div>
<script>
  const MODEL_EVENTS = {map_events_json};

  const COLOR_MAP = {{
    "BENIGN":      [34,  197, 94],
    "DDoS":        [239, 68,  68],
    "Port Scan":   [59,  130, 246],
    "Brute Force": [249, 115, 22],
    "Web Attack":  [168, 85,  247],
  }};
  const BADGE_STYLE = {{
    "BENIGN":      {{ bg:"#14532d", text:"#86efac" }},
    "DDoS":        {{ bg:"#450a0a", text:"#fca5a5" }},
    "Port Scan":   {{ bg:"#1e3a5f", text:"#93c5fd" }},
    "Brute Force": {{ bg:"#431407", text:"#fed7aa" }},
    "Web Attack":  {{ bg:"#3b0764", text:"#e9d5ff" }},
  }};

  const DRAW_MS = 1200, FADE_MS = 600, TTL_MS = 1800, PATH_POINTS = 360, HEAD_FADE_MS = 300;

  // Sacred Heart University - the target
  const TARGET = {{ lat: 41.221288, lon: -73.241378 }};

  // Global cities for source geo approximation (dataset IPs are internal)
  const CITIES = [
    {{n:"New York",lat:40.71,lon:-74.01}},{{n:"Los Angeles",lat:34.05,lon:-118.24}},
    {{n:"Chicago",lat:41.88,lon:-87.63}},{{n:"London",lat:51.51,lon:-0.13}},
    {{n:"Paris",lat:48.86,lon:2.35}},{{n:"Berlin",lat:52.52,lon:13.40}},
    {{n:"Moscow",lat:55.76,lon:37.62}},{{n:"Beijing",lat:39.90,lon:116.41}},
    {{n:"Tokyo",lat:35.68,lon:139.69}},{{n:"Mumbai",lat:19.08,lon:72.88}},
    {{n:"Sao Paulo",lat:-23.55,lon:-46.63}},{{n:"Lagos",lat:6.52,lon:3.38}},
    {{n:"Sydney",lat:-33.87,lon:151.21}},{{n:"Seoul",lat:37.57,lon:126.98}},
    {{n:"Singapore",lat:1.35,lon:103.82}},{{n:"Dubai",lat:25.20,lon:55.27}},
    {{n:"Toronto",lat:43.65,lon:-79.38}},{{n:"Mexico City",lat:19.43,lon:-99.13}},
    {{n:"Cairo",lat:30.04,lon:31.24}},{{n:"Istanbul",lat:41.01,lon:28.98}},
    {{n:"Jakarta",lat:-6.21,lon:106.85}},{{n:"Bangkok",lat:13.76,lon:100.50}},
    {{n:"Karachi",lat:24.86,lon:67.01}},{{n:"Tehran",lat:35.69,lon:51.39}},
    {{n:"Riyadh",lat:24.71,lon:46.68}},{{n:"Johannesburg",lat:-26.20,lon:28.04}},
    {{n:"Buenos Aires",lat:-34.60,lon:-58.38}},{{n:"Lima",lat:-12.05,lon:-77.04}},
    {{n:"Ho Chi Minh City",lat:10.82,lon:106.63}},{{n:"Hong Kong",lat:22.32,lon:114.17}}
  ];

  function hashStr(s) {{
    let h = 0;
    for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
    return Math.abs(h);
  }}

  function ipToSrc(ip) {{
    const h = hashStr(ip);
    const city = CITIES[h % CITIES.length];
    return {{
      lat: city.lat + (((h >> 8) % 100) / 100 - 0.5) * 1.2,
      lon: city.lon + (((h >> 16) % 100) / 100 - 0.5) * 1.2,
      name: city.n
    }};
  }}

  function buildPath(src, dst) {{
    const path = [];
    const dlat = dst.lat - src.lat, dlon = dst.lon - src.lon;
    const dist = Math.sqrt(dlat*dlat + dlon*dlon), len = Math.max(dist, 0.001);
    let perpLat = -dlon / len, perpLon = dlat / len;
    if (perpLat < 0) {{ perpLat = -perpLat; perpLon = -perpLon; }}
    const offset = Math.min(dist * 0.18, 20);
    const cLat = Math.max(-75, Math.min(75, src.lat + dlat*0.5 + perpLat*offset));
    const cLon = src.lon + dlon*0.5 + perpLon*offset;
    for (let i = 0; i <= PATH_POINTS; i++) {{
      const t = i / PATH_POINTS, u = 1-t;
      path.push([
        u*u*src.lon + 2*u*t*cLon + t*t*dst.lon,
        u*u*src.lat + 2*u*t*cLat + t*t*dst.lat
      ]);
    }}
    return path;
  }}

  // Pre-fill the log from the saved history on disk (newest first) so it
  // persists across slider moves, reruns, and reboots. New tracer arrivals are
  // still appended on top as they land.
  const CLEAR_LOG = {clear_log_js};
  const ALERT_HISTORY = CLEAR_LOG ? [] : {alert_history_json};
  const alertLog = ALERT_HISTORY.slice().reverse();
  let threatCount = alertLog.filter(e => e.attack !== 'BENIGN').length;
  let logDirty = true;

  // The ONLY place that appends to the log. Called exactly once per tracer,
  // from the arrival check in updateMap(). Do not call it anywhere else.
  function addToLog(p) {{
    const t = new Date();
    const ts = t.toLocaleTimeString('en-US', {{hour12:false, hour:'2-digit', minute:'2-digit', second:'2-digit'}});
    if (p.attack !== 'BENIGN') threatCount++;
    alertLog.unshift({{ time:ts, ts:t.toISOString(), srcIp:p.srcIp, dstIp:p.dstIp, attack:p.attack, confidence:p.confidence }});
    if (alertLog.length > 100) alertLog.pop();
    logDirty = true;
    saveLog();
  }}

  // Persist the log to disk via serve_events.py so it survives a browser refresh
  // or reboot. Saved oldest-first to match the file format the dashboard reads.
  function saveLog() {{
    try {{
      fetch('http://127.0.0.1:8000/save_alerts', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(alertLog.slice().reverse()),
      }});
    }} catch (err) {{ /* server down; the in-page log is still fine */ }}
  }}

  // If Clear log was just pressed, overwrite disk with the now-empty log a few
  // times over the first second. This wins the race against the previous iframe
  // (which may still POST its old log once before it is torn down).
  if (CLEAR_LOG) {{
    saveLog();
    setTimeout(saveLog, 300);
    setTimeout(saveLog, 800);
  }}

  function renderLog() {{
    const tbody = document.getElementById('alert-tbody');
    const threats = alertLog.filter(e => e.attack !== 'BENIGN');
    document.getElementById('alert-count').textContent = threats.length + ' threat' + (threats.length !== 1 ? 's' : '') + ' detected';

    // Summary cards are computed from the SAME threats array as the log, so they
    // are always exactly 1:1 with the rows shown below.
    const types = new Set(threats.map(e => e.attack));
    const sources = new Set(threats.map(e => e.srcIp));
    const avg = threats.length ? threats.reduce((s, e) => s + (e.confidence || 0), 0) / threats.length : 0;
    document.getElementById('sum-threats').textContent = threats.length;
    document.getElementById('sum-types').textContent = types.size;
    document.getElementById('sum-sources').textContent = sources.size;
    document.getElementById('sum-conf').textContent = threats.length ? (avg * 100).toFixed(0) + '%' : 'N/A';

    if (threats.length === 0) {{
      tbody.innerHTML = '<tr><td colspan="5" style="color:#475569;text-align:center;padding:16px;">No threats detected yet...</td></tr>';
      return;
    }}
    tbody.innerHTML = threats.map((e, i) => {{
      const b = BADGE_STYLE[e.attack] || {{bg:"#1e293b", text:"#e2e8f0"}};
      return `<tr${{i === 0 ? ' class="row-new"' : ''}}>
        <td style="color:#64748b;">${{e.time}}</td>
        <td style="font-family:monospace;color:#94a3b8;">${{e.srcIp}}</td>
        <td style="font-family:monospace;color:#94a3b8;">${{e.dstIp}}</td>
        <td><span style="background:${{b.bg}};color:${{b.text}};padding:1px 8px;border-radius:10px;font-size:0.68rem;font-weight:600;">${{e.attack}}</span></td>
        <td style="color:#94a3b8;">${{(e.confidence*100).toFixed(1)}}%</td>
      </tr>`;
    }}).join('');
  }}

  let livePackets = [];

  const waitForDeck = setInterval(() => {{
    if (!window.deck) return;
    clearInterval(waitForDeck);
    const {{DeckGL, TileLayer, BitmapLayer, ScatterplotLayer, MapView}} = window.deck;

    const basemap = new TileLayer({{
      id:"basemap",
      data:"https://cartodb-basemaps-a.global.ssl.fastly.net/dark_all/{{z}}/{{x}}/{{y}}.png",
      minZoom:0, maxZoom:19, tileSize:256,
      renderSubLayers: props => {{
        const {{boundingBox}} = props.tile;
        return new BitmapLayer(props, {{ data:null, image:props.data,
          bounds:[boundingBox[0][0], boundingBox[0][1], boundingBox[1][0], boundingBox[1][1]] }});
      }}
    }});

    const deckgl = new DeckGL({{
      container:"live-map", views: new MapView({{repeat:true}}),
      initialViewState:{{ longitude:-95, latitude:39, zoom:2, pitch:0, bearing:0 }},
      controller:{{ minZoom:1.2 }}, layers:[basemap]
    }});

    function spawnEvent(evt) {{
      const src = ipToSrc(evt.srcIp);
      livePackets.push({{
        ts: Date.now(),
        attack: evt.attack,
        srcIp: evt.srcIp,
        dstIp: evt.dstIp,
        confidence: evt.confidence,
        src: [src.lon, src.lat],
        dst: [TARGET.lon, TARGET.lat],
        path: buildPath(src, TARGET),
      }});
    }}

    function updateMap() {{
      const now = Date.now();
      livePackets = livePackets.filter(p => now - p.ts < TTL_MS);
      document.getElementById('count').textContent = livePackets.length;

      const trailDots = [], sources = [], heads = [];

      livePackets.forEach(p => {{
        const age = now - p.ts;
        const progress = Math.min(1, age / DRAW_MS);
        const drawing = progress < 0.99;
        if (!drawing && !p.arrivedAt) {{ p.arrivedAt = now; addToLog(p); }}  // one alert per tracer, on arrival
        const opacity = drawing ? 1.0 : Math.max(0, 1 - (now - p.arrivedAt) / FADE_MS);
        if (opacity <= 0) return;

        const N = p.path.length - 1;
        const lastIdx = Math.max(1, Math.min(N, Math.ceil(progress * N)));
        const color = COLOR_MAP[p.attack] || [100, 116, 139];

        for (let i = 0; i <= lastIdx; i++) {{
          trailDots.push({{ position: p.path[i], color, opacity }});
        }}
        sources.push({{ position: p.src, color, opacity }});

        if (drawing) {{
          heads.push({{ position: p.path[lastIdx], color, opacity: 1.0 }});
        }} else {{
          const ho = Math.max(0, 1 - (now - p.arrivedAt) / HEAD_FADE_MS);
          if (ho > 0) heads.push({{ position: p.path[N], color, opacity: ho }});
        }}
      }});

      deckgl.setProps({{ layers: [
        basemap,
        new ScatterplotLayer({{ id:"trails", data:trailDots, getPosition:d=>d.position, getFillColor:d=>[...d.color, Math.round(180*d.opacity)], getRadius:1.5, radiusUnits:"pixels" }}),
        new ScatterplotLayer({{ id:"sources", data:sources, getPosition:d=>d.position, getFillColor:d=>[...d.color, Math.round(220*d.opacity)], getRadius:5, radiusUnits:"pixels" }}),
        new ScatterplotLayer({{ id:"heads", data:heads, getPosition:d=>d.position, getFillColor:d=>[...d.color, Math.round(255*d.opacity)], getLineColor:d=>[255,255,255,Math.round(200*d.opacity)], stroked:true, getLineWidth:1.5, lineWidthUnits:"pixels", getRadius:6, radiusUnits:"pixels" }}),
        new ScatterplotLayer({{ id:"target", data:[{{position:[TARGET.lon, TARGET.lat]}}], getPosition:d=>d.position, getFillColor:[59,130,246,220], getLineColor:[255,255,255,200], stroked:true, getLineWidth:2, lineWidthUnits:"pixels", getRadius:9, radiusUnits:"pixels" }}),
      ]}});
    }}

    function animLoop() {{ updateMap(); requestAnimationFrame(animLoop); }}
    requestAnimationFrame(animLoop);

    // Fetch live_events.json directly from serve_events.py every 2s. Because this
    // happens inside the iframe, the Streamlit page never reloads and the map
    // view (pan/zoom) is never reset. Every poll, fire a tracer for each attack
    // currently in live_events.json. capture.py keeps rewriting that file while an
    // attack is active, so an ongoing attack strikes the map again every poll, and
    // the alert log gets exactly one row per tracer (1:1) when each tracer lands.
    const EVENTS_URL = 'http://127.0.0.1:8000/live_events.json';

    async function pollEvents() {{
      try {{
        const resp = await fetch(EVENTS_URL + '?t=' + Date.now());
        if (resp.ok) {{
          const data = await resp.json();
          data.forEach(e => {{
            if (e.attack === 'BENIGN') return;
            spawnEvent(e);   // every detection -> one tracer -> one alert
          }});
        }}
      }} catch (err) {{ /* server not running yet; try again next tick */ }}
    }}
    pollEvents();
    setInterval(pollEvents, 2000);

    setInterval(() => {{ if (logDirty) {{ logDirty = false; renderLog(); }} }}, 100);
  }}, 100);
</script>
</body>
</html>
"""

components.html(LIVE_MAP_HTML, height=790, scrolling=False)

# ---------------------------------------------------------------------------
# CHARTS
# ---------------------------------------------------------------------------

_chart_title, _chart_btn = st.columns([4, 1], vertical_alignment="center")
with _chart_title:
    st.markdown('<div class="section-title" style="margin:0;border:none;padding:0;">Analytics</div>', unsafe_allow_html=True)
with _chart_btn:
    # Re-reads alert_history.json and redraws the charts on demand (one rerun,
    # no repeating page-reload flash).
    st.button("↻ Refresh charts", use_container_width=True)

# All charts are built from the real captured attacks (captured_threats).
if captured_threats.empty:
    st.info("No attacks captured yet. Run capture.py, then click ↻ Refresh charts.")
else:
    left, right = st.columns(2)

    with left:
        st.markdown('<div class="section-title">Threats by Type</div>', unsafe_allow_html=True)
        type_counts = captured_threats["Classification"].value_counts().reset_index()
        type_counts.columns = ["Attack Type", "Count"]
        fig1 = px.bar(type_counts, x="Attack Type", y="Count", color="Attack Type", color_discrete_map=color_map)
        fig1.update_layout(**chart_layout, showlegend=False)
        fig1.update_traces(marker_line_width=0)
        fig1.update_xaxes(gridcolor="#1e293b")
        fig1.update_yaxes(gridcolor="#1e293b")
        st.plotly_chart(fig1, use_container_width=True, config={"displayModeBar": False})

    with right:
        st.markdown('<div class="section-title">Threat Distribution</div>', unsafe_allow_html=True)
        fig2 = px.pie(type_counts, values="Count", names="Attack Type", color="Attack Type", color_discrete_map=color_map, hole=0.45)
        fig2.update_layout(**chart_layout)
        fig2.update_traces(textfont_color="#e2e8f0", textinfo="percent+label")
        st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})

    st.markdown('<div class="section-title">Threat Activity</div>', unsafe_allow_html=True)
    threats_timeline = captured_threats.dropna(subset=["Timestamp"]).copy()
    if threats_timeline.empty:
        st.caption("Not enough timestamped data to plot activity yet.")
    else:
        threats_timeline["Minute"] = threats_timeline["Timestamp"].dt.floor("min")
        hourly = threats_timeline.groupby(["Minute", "Classification"]).size().reset_index(name="Count")
        fig3 = px.area(hourly, x="Minute", y="Count", color="Classification", color_discrete_map=color_map)
        fig3.update_layout(**chart_layout, height=300)
        fig3.update_xaxes(gridcolor="#1e293b")
        fig3.update_yaxes(gridcolor="#1e293b")
        st.plotly_chart(fig3, use_container_width=True, config={"displayModeBar": False})
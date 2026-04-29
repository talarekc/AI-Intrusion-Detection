import streamlit as st
import streamlit.components.v1 as components
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

    /* Cap layout width so it doesn't stretch on 2K+ screens */
    .block-container {
        max-width: 1400px !important;
        margin-left: auto !important;
        margin-right: auto !important;
    }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# MODEL INTEGRATION POINT
# When the real model is ready, replace load_predictions() with a function
# that calls your model or reads its output file/API. The returned DataFrame
# must have these columns:
#   Timestamp (datetime), Source IP (str), Src Port (int),
#   Destination IP (str), Classification (str), Confidence (float 0-1),
#   Severity (str: "Critical" | "Warning" | "Low" | "None")
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "Port Scan": "Low",
    "Brute Force": "Critical",
    "DDoS": "Critical",
    "Web Attack": "Warning",
    "Benign": "None",
}

MODEL_INFO = {
    "name": "Random Forest",
    "dataset": "CICIDS2017",
    "f1_score": None,   # set this once the model is trained (e.g. 0.94)
    "classes": ["Benign", "Port Scan", "Brute Force", "DDoS", "Web Attack"],
}


@st.cache_data(ttl=60)
def load_predictions() -> pd.DataFrame:
    """Return a DataFrame of model predictions.

    Swap the body of this function when the real model is available.
    The cache refreshes every 60 seconds so live data stays current.
    """
    random.seed(42)
    attack_types = MODEL_INFO["classes"]
    data = []
    for _ in range(300):
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
            "Severity": SEVERITY_MAP.get(attack, "Unknown"),
            "Confidence": confidence,
        })
    return pd.DataFrame(data).sort_values("Timestamp", ascending=False).reset_index(drop=True)


df = load_predictions()
available_classes = sorted(df["Classification"].unique().tolist())
available_severities = sorted(df["Severity"].unique().tolist())

# Sidebar
with st.sidebar:
    st.markdown("### Filters")
    st.markdown("---")
    selected_types = st.multiselect("Attack Type", available_classes, default=available_classes)
    min_confidence = st.slider("Min Confidence", 0.0, 1.0, 0.7)
    severity_filter = st.multiselect("Severity", available_severities, default=available_severities)
    st.markdown("---")
    st.markdown("##### Model Info")
    f1_display = f"{MODEL_INFO['f1_score']:.2f}" if MODEL_INFO["f1_score"] is not None else "Pending"
    st.markdown(f"""
    <div style='color: #64748b; font-size: 0.8rem; line-height: 1.6;'>
    Model: {MODEL_INFO['name']}<br>
    Dataset: {MODEL_INFO['dataset']}<br>
    F1 Score: {f1_display}<br>
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

# Live traffic map + real-time alert log: all client-side JS, no Streamlit reruns
st.markdown('<div class="section-title">Live Traffic Map</div>', unsafe_allow_html=True)

LIVE_MAP_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://unpkg.com/deck.gl@8.9.36/dist.min.js"></script>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0a0e17; font-family: 'Inter', sans-serif; color: #e2e8f0; display: flex; flex-direction: column; height: 100vh; }
  #status { color: #64748b; font-size: 0.82rem; padding: 6px 10px; flex-shrink: 0; }
  .dot {
    display: inline-block; width: 8px; height: 8px; background: #22c55e;
    border-radius: 50%; margin-right: 6px; animation: blink 2s infinite;
  }
  @keyframes blink { 0%,100% { opacity: 1 } 50% { opacity: 0.3 } }
  #map-wrap { position: relative; flex: 1; min-height: 0; }
  #live-map { width: 100%; height: 100%; }
  #pin-overlay { position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; z-index: 5; overflow: hidden; }
  .legend { position: absolute; top: 10px; right: 10px; background: rgba(15,20,30,0.75);
    padding: 10px 14px; border-radius: 6px; font-size: 0.78rem; z-index: 10; border: 1px solid #1e293b; }
  .legend-item { display: flex; align-items: center; margin-bottom: 5px; }
  .legend-item:last-child { margin-bottom: 0; }
  .legend-box { width: 16px; height: 2px; margin-right: 8px; border-radius: 1px; }

  /* Alert log panel */
  #alert-panel {
    flex-shrink: 0;
    height: 215px;
    background: #0d1117;
    border-top: 1px solid #1e293b;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  #alert-panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 5px 12px;
    border-bottom: 1px solid #1e293b;
    flex-shrink: 0;
  }
  #alert-panel-header .title {
    font-size: 0.75rem;
    font-weight: 600;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  #alert-count { font-size: 0.72rem; color: #475569; }
  #alert-scroll { overflow-y: auto; overflow-x: auto; flex: 1; }
  #alert-table { width: 100%; border-collapse: collapse; font-size: 0.74rem; }
  #alert-table thead th {
    position: sticky; top: 0;
    background: #111827;
    color: #475569;
    text-transform: uppercase;
    font-size: 0.63rem;
    letter-spacing: 0.05em;
    padding: 3px 10px;
    text-align: left;
    border-bottom: 1px solid #1e293b;
    white-space: nowrap;
  }
  #alert-table td {
    padding: 3px 10px;
    color: #cbd5e1;
    border-bottom: 1px solid rgba(30,41,59,0.4);
    white-space: nowrap;
  }
  #alert-table tr:hover td { background: rgba(30,41,59,0.4); }
  @keyframes rowIn { from { background: rgba(59,130,246,0.12); } to { background: transparent; } }
  .row-new { animation: rowIn 1.2s ease forwards; }
</style>
</head>
<body>
  <div id="status"><span class="dot"></span><span id="count">0</span> active packet(s) in flight</div>
  <div id="map-wrap">
    <div id="live-map"></div>
    <div class="legend">
      <div class="legend-item"><div class="legend-box" style="background:#3b82f6;"></div> Port Scan</div>
      <div class="legend-item"><div class="legend-box" style="background:#ef4444;"></div> Brute Force</div>
      <div class="legend-item"><div class="legend-box" style="background:#f97316;"></div> DDoS</div>
      <div class="legend-item"><div class="legend-box" style="background:#a855f7;"></div> Web Attack</div>
    </div>
  </div>
  <div id="alert-panel">
    <div id="alert-panel-header">
      <span class="title">Alert Log</span>
      <span id="alert-count">0 alerts</span>
    </div>
    <div id="alert-scroll">
      <table id="alert-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Origin</th>
            <th>Source IP</th>
            <th>Attack</th>
            <th>Target IP</th>
          </tr>
        </thead>
        <tbody id="alert-tbody">
          <tr><td colspan="5" style="color:#475569;text-align:center;padding:16px;">Waiting for traffic…</td></tr>
        </tbody>
      </table>
    </div>
  </div>
<script>
  const colorMap = {
    "Port Scan": [59, 130, 246],
    "Brute Force": [239, 68, 68],
    "DDoS": [249, 115, 22],
    "Web Attack": [168, 85, 247]
  };
  const badgeStyle = {
    "Port Scan":   {bg:"#1e3a5f", text:"#93c5fd"},
    "Brute Force": {bg:"#450a0a", text:"#fca5a5"},
    "DDoS":        {bg:"#431407", text:"#fdba74"},
    "Web Attack":  {bg:"#3b0764", text:"#d8b4fe"}
  };
  const attacks = ["Port Scan", "Brute Force", "DDoS", "Web Attack"];

  const DRAW_MS = 900;
  const FADE_MS = 500;
  const TTL_MS = DRAW_MS + FADE_MS;
  const SPAWN_MS = 600;
  const PATH_POINTS = 360;
  const HEAD_FADE_MS = 250;

  const SOURCE_CITIES = [
    {name:"New York",lat:40.71,lon:-74.01},{name:"Los Angeles",lat:34.05,lon:-118.24},
    {name:"Chicago",lat:41.88,lon:-87.63},{name:"Houston",lat:29.76,lon:-95.37},
    {name:"Miami",lat:25.76,lon:-80.19},{name:"Seattle",lat:47.61,lon:-122.33},
    {name:"Denver",lat:39.74,lon:-104.99},{name:"Toronto",lat:43.65,lon:-79.38},
    {name:"Vancouver",lat:49.28,lon:-123.12},{name:"Mexico City",lat:19.43,lon:-99.13},
    {name:"São Paulo",lat:-23.55,lon:-46.63},{name:"Buenos Aires",lat:-34.60,lon:-58.38},
    {name:"Lima",lat:-12.05,lon:-77.04},{name:"Bogotá",lat:4.71,lon:-74.07},
    {name:"Santiago",lat:-33.45,lon:-70.67},{name:"Rio de Janeiro",lat:-22.91,lon:-43.17},
    {name:"London",lat:51.51,lon:-0.13},{name:"Paris",lat:48.86,lon:2.35},
    {name:"Berlin",lat:52.52,lon:13.40},{name:"Madrid",lat:40.42,lon:-3.70},
    {name:"Rome",lat:41.90,lon:12.50},{name:"Moscow",lat:55.76,lon:37.62},
    {name:"Stockholm",lat:59.33,lon:18.07},{name:"Amsterdam",lat:52.37,lon:4.90},
    {name:"Warsaw",lat:52.23,lon:21.01},{name:"Istanbul",lat:41.01,lon:28.98},
    {name:"Kyiv",lat:50.45,lon:30.52},{name:"Dublin",lat:53.35,lon:-6.26},
    {name:"Cairo",lat:30.04,lon:31.24},{name:"Lagos",lat:6.52,lon:3.38},
    {name:"Nairobi",lat:-1.29,lon:36.82},{name:"Johannesburg",lat:-26.20,lon:28.04},
    {name:"Casablanca",lat:33.57,lon:-7.59},{name:"Addis Ababa",lat:9.03,lon:38.74},
    {name:"Tokyo",lat:35.68,lon:139.69},{name:"Beijing",lat:39.90,lon:116.41},
    {name:"Shanghai",lat:31.23,lon:121.47},{name:"Seoul",lat:37.57,lon:126.98},
    {name:"Mumbai",lat:19.08,lon:72.88},{name:"New Delhi",lat:28.61,lon:77.21},
    {name:"Bangkok",lat:13.76,lon:100.50},{name:"Singapore",lat:1.35,lon:103.82},
    {name:"Jakarta",lat:-6.21,lon:106.85},{name:"Manila",lat:14.60,lon:120.98},
    {name:"Hanoi",lat:21.03,lon:105.85},{name:"Tehran",lat:35.69,lon:51.39},
    {name:"Karachi",lat:24.86,lon:67.01},{name:"Riyadh",lat:24.71,lon:46.68},
    {name:"Dubai",lat:25.20,lon:55.27},{name:"Hong Kong",lat:22.32,lon:114.17},
    {name:"Sydney",lat:-33.87,lon:151.21},{name:"Melbourne",lat:-37.81,lon:144.96},
    {name:"Auckland",lat:-36.85,lon:174.76}
  ];

  function ipToGeo(ip, isSource) {
    let h = 0;
    for (let i = 0; i < ip.length; i++) h = ((h << 5) - h + ip.charCodeAt(i)) | 0;
    h = Math.abs(h);
    if (isSource) {
      const city = SOURCE_CITIES[h % SOURCE_CITIES.length];
      return [city.lon + (((h >> 16) % 100) / 100 - 0.5) * 0.8,
              city.lat + (((h >> 8)  % 100) / 100 - 0.5) * 0.8];
    }
    return [-74.0 + (((h >> 8) % 1000) / 1000 - 0.5) * 1.5,
             40.7 + ((h % 1000) / 1000 - 0.5) * 1.5];
  }

  function ipToCity(ip) {
    let h = 0;
    for (let i = 0; i < ip.length; i++) h = ((h << 5) - h + ip.charCodeAt(i)) | 0;
    return SOURCE_CITIES[Math.abs(h) % SOURCE_CITIES.length].name;
  }

  // Alert log state
  const alertLog = [];
  const MAX_LOG = 50;
  let logDirty = false;

  function addToLog(p) {
    const t = new Date();
    const timeStr = t.toLocaleTimeString('en-US', {hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'});
    alertLog.unshift({ time: timeStr, city: p.srcCity, srcIp: p.srcIp, attack: p.attack, dstIp: p.dstIp });
    if (alertLog.length > MAX_LOG) alertLog.pop();
    logDirty = true;
  }

  function renderLog() {
    const tbody = document.getElementById('alert-tbody');
    const n = alertLog.length;
    document.getElementById('alert-count').textContent = n + ' alert' + (n !== 1 ? 's' : '');
    if (n === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="color:#475569;text-align:center;padding:16px;">Waiting for traffic…</td></tr>';
      return;
    }
    tbody.innerHTML = alertLog.map((e, i) => {
      const b = badgeStyle[e.attack];
      return `<tr${i === 0 ? ' class="row-new"' : ''}>
        <td style="color:#64748b;">${e.time}</td>
        <td>${e.city}</td>
        <td style="color:#94a3b8;font-family:monospace;">${e.srcIp}</td>
        <td><span style="background:${b.bg};color:${b.text};padding:1px 7px;border-radius:10px;font-size:0.68rem;font-weight:600;">${e.attack}</span></td>
        <td style="color:#94a3b8;font-family:monospace;">${e.dstIp}</td>
      </tr>`;
    }).join('');
  }

  // Quadratic bezier path in lat/lon space
  function buildPath(lat1, lon1, lat2, lon2) {
    const dlon = lon2 - lon1;
    const dlat = lat2 - lat1;
    const dist = Math.sqrt(dlat*dlat + dlon*dlon);
    const len = Math.max(dist, 0.001);
    let perpLat = -dlon / len;
    let perpLon = dlat / len;
    if (perpLat < 0) { perpLat = -perpLat; perpLon = -perpLon; }
    const offset = Math.min(dist * 0.15, 18);
    const cLat = Math.max(-60, Math.min(60, lat1 + dlat * 0.5 + perpLat * offset));
    const cLon = lon1 + dlon * 0.5 + perpLon * offset;
    const path = [];
    for (let i = 0; i <= PATH_POINTS; i++) {
      const t = i / PATH_POINTS;
      const u = 1 - t;
      path.push([u*u*lat1 + 2*u*t*cLat + t*t*lat2, u*u*lon1 + 2*u*t*cLon + t*t*lon2]);
    }
    return path;
  }

  function easeOut(t) { return t; }

  let livePackets = [];

  // Wait for deck.gl to load
  const waitForDeck = setInterval(() => {
    if (!window.deck) return;
    clearInterval(waitForDeck);

    const {DeckGL, TileLayer, BitmapLayer, PathLayer, ScatterplotLayer, MapView} = window.deck;

    const basemap = new TileLayer({
      id: "basemap",
      data: "https://cartodb-basemaps-a.global.ssl.fastly.net/dark_all/{z}/{x}/{y}.png",
      minZoom: 0, maxZoom: 19, tileSize: 256,
      renderSubLayers: props => {
        const {boundingBox} = props.tile;
        return new BitmapLayer(props, {
          data: null, image: props.data,
          bounds: [boundingBox[0][0], boundingBox[0][1], boundingBox[1][0], boundingBox[1][1]]
        });
      }
    });

    const pinOverlay = document.createElement('div');
    pinOverlay.id = 'pin-overlay';
    document.getElementById('map-wrap').appendChild(pinOverlay);

    let currentDstPositions = [];
    const arrivedDsts = {};
    let pinHitTargets = [];

    const tooltip = document.createElement('div');
    tooltip.style.cssText = 'position:absolute;display:none;background:rgba(15,20,30,0.9);color:#e2e8f0;font-size:0.75rem;padding:4px 8px;border-radius:4px;border:1px solid #1e293b;pointer-events:none;z-index:20;white-space:nowrap;';
    document.getElementById('map-wrap').appendChild(tooltip);

    function renderPins() {
      const viewports = deckgl.getViewports();
      if (!viewports || !viewports.length) return;
      const viewport = viewports[0];
      pinOverlay.innerHTML = '';
      pinHitTargets = [];
      currentDstPositions.forEach(({pos, ip}) => {
        const [x, y] = viewport.project(pos);
        if (x < -20 || x > pinOverlay.clientWidth + 20) return;
        if (y < -20 || y > pinOverlay.clientHeight + 20) return;
        const el = document.createElement('span');
        el.textContent = '📍';
        el.style.cssText = `position:absolute;left:${x}px;top:${y}px;font-size:22px;transform:translate(-50%,-100%);pointer-events:none;`;
        pinOverlay.appendChild(el);
        pinHitTargets.push({ x, y, ip });
      });
    }

    document.getElementById('map-wrap').addEventListener('mousemove', e => {
      const rect = document.getElementById('map-wrap').getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      let found = null;
      for (const pin of pinHitTargets) {
        const dx = mx - pin.x, dy = my - (pin.y - 14);
        if (Math.sqrt(dx*dx + dy*dy) < 14) { found = pin; break; }
      }
      if (found) {
        tooltip.style.display = 'block';
        tooltip.style.left = (found.x + 12) + 'px';
        tooltip.style.top = (found.y - 36) + 'px';
        tooltip.textContent = found.ip;
      } else {
        tooltip.style.display = 'none';
      }
    });
    document.getElementById('map-wrap').addEventListener('mouseleave', () => { tooltip.style.display = 'none'; });

    const deckgl = new DeckGL({
      container: "live-map",
      views: new MapView({ repeat: true }),
      initialViewState: { longitude: -40, latitude: 30, zoom: 2, pitch: 0, bearing: 0 },
      controller: { minZoom: 1.2 },
      layers: [basemap]
    });

    function spawnPacket() {
      const attack = attacks[Math.floor(Math.random() * attacks.length)];
      const srcIp = "192.168.1." + (1 + Math.floor(Math.random() * 254));
      const dstIp = "10.0.0." + (1 + Math.floor(Math.random() * 50));
      const [srcLon, srcLat] = ipToGeo(srcIp, true);
      const [dstLon, dstLat] = ipToGeo(dstIp, false);
      livePackets.push({
        ts: Date.now(), attack, srcIp, dstIp,
        srcCity: ipToCity(srcIp),
        src: [srcLon, srcLat], dst: [dstLon, dstLat],
        path: buildPath(srcLat, srcLon, dstLat, dstLon)
      });
    }

    function spawnTick() {
      const n = 1 + Math.floor(Math.random() * 2);
      for (let i = 0; i < n; i++) spawnPacket();
    }

    function updateMap() {
      const now = Date.now();
      livePackets = livePackets.filter(p => now - p.ts < TTL_MS);
      document.getElementById("count").textContent = livePackets.length;

      const trailDots = [];
      const sources = [];
      const heads = [];

      livePackets.forEach(p => {
        const age = now - p.ts;
        const rawProgress = Math.min(1, age / DRAW_MS);
        const progress = easeOut(rawProgress);
        const drawing = progress < 0.99;
        if (!drawing && !p.arrivedAt) {
          p.arrivedAt = now;
          addToLog(p);
        }
        const opacity = drawing ? 1.0 : Math.max(0, 1 - (now - p.arrivedAt) / FADE_MS);
        if (opacity <= 0) return;

        const N = p.path.length - 1;
        const lastIdx = Math.max(1, Math.min(N, Math.ceil(progress * N)));
        const color = colorMap[p.attack];

        for (let i = 0; i <= lastIdx; i++) {
          const pt = p.path[i];
          trailDots.push({ position: [pt[1], pt[0]], color, opacity });
        }

        sources.push({ position: p.src, opacity });

        if (drawing) {
          const head = p.path[lastIdx];
          heads.push({ position: [head[1], head[0]], color, opacity: 1.0 });
        } else {
          const headOpacity = Math.max(0, 1 - (now - p.arrivedAt) / HEAD_FADE_MS);
          if (headOpacity > 0) {
            const head = p.path[N];
            heads.push({ position: [head[1], head[0]], color, opacity: headOpacity });
          }
        }
      });

      const pathLayers = [new ScatterplotLayer({
        id: "trails", data: trailDots,
        getPosition: d => d.position,
        getFillColor: d => [...d.color, Math.round(255 * d.opacity)],
        getRadius: 1.2, radiusUnits: "pixels"
      })];

      const sourceLayer = new ScatterplotLayer({
        id: "sources", data: sources,
        getPosition: d => d.position,
        getFillColor: d => [239, 68, 68, Math.round(220 * d.opacity)],
        getRadius: 4, radiusUnits: "pixels"
      });

      const headLayer = new ScatterplotLayer({
        id: "heads", data: heads,
        getPosition: d => d.position,
        getFillColor: d => [...d.color, Math.round(255 * d.opacity)],
        getLineColor: d => [255, 255, 255, Math.round(230 * d.opacity)],
        stroked: true, getLineWidth: 1.5, lineWidthUnits: "pixels",
        getRadius: 5, radiusUnits: "pixels"
      });

      let pinsChanged = false;
      livePackets.forEach(p => {
        const age = now - p.ts;
        const progress = easeOut(Math.min(1, age / DRAW_MS));
        if (progress < 0.99) return;
        const key = p.dst.join(",");
        if (!arrivedDsts[key]) {
          arrivedDsts[key] = { pos: p.dst, ip: p.dstIp };
          pinsChanged = true;
        }
      });
      if (pinsChanged) {
        currentDstPositions = Object.values(arrivedDsts);
      }

      deckgl.setProps({ layers: [basemap, ...pathLayers, sourceLayer, headLayer] });
      renderPins();
    }

    function animLoop() { updateMap(); requestAnimationFrame(animLoop); }
    requestAnimationFrame(animLoop);
    setInterval(spawnTick, SPAWN_MS);
    setInterval(() => { if (logDirty) { logDirty = false; renderLog(); } }, 100);
    spawnTick();
  }, 100);
</script>
</body>
</html>
"""

components.html(LIVE_MAP_HTML, height=720, scrolling=False)

# Charts
left, right = st.columns(2)

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

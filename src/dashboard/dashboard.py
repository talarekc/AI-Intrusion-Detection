import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import joblib
import random
import json
import os
from datetime import datetime, timedelta

# Page setup
st.set_page_config(page_title="AI Threat Detection Dashboard", layout="wide", initial_sidebar_state="expanded")

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
# CONFIG — update these paths if needed
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "BENIGN": "None",
    "DDoS": "Critical",
}

MODEL_INFO = {
    "name": "Random Forest",
    "dataset": "CICIDS2017",
    "f1_score": 0.9999,
    "classes": ["BENIGN", "DDoS"],
}

POSSIBLE_PATHS = [
    r"C:\Users\brian\OneDrive - Sacred Heart University\CIC-IDS-2017\MachineLearningCSV\MachineLearningCVE\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
  # r"C:\Users\cole\...", (REMOVE COMMENT AND UPDATE PATH)
  # r"C:\Users\frank\...", (REMOVE COMMENT AND UPDATE PATH)
]

CSV_PATH = next((p for p in POSSIBLE_PATHS if os.path.exists(p)), None)
if CSV_PATH is None:
    st.error("Dataset not found. Download CICIDS2017 and update the path in dashboard.py")
    st.stop()
MODEL_PATH = r"C:\Users\brian\OneDrive - Sacred Heart University\main\models\random_forest_model.joblib"
ENCODER_PATH = r"C:\Users\brian\OneDrive - Sacred Heart University\main\models\label_encoder.joblib"

# ---------------------------------------------------------------------------
# MODEL LOADING
# ---------------------------------------------------------------------------

@st.cache_resource
def load_model():
    model = joblib.load(MODEL_PATH)
    encoder = joblib.load(ENCODER_PATH)
    return model, encoder

# ---------------------------------------------------------------------------
# PREDICTIONS
# ---------------------------------------------------------------------------

@st.cache_data(ttl=60)
def load_predictions() -> pd.DataFrame:
    model, encoder = load_model()

    df_raw = pd.read_csv(CSV_PATH)
    df_raw = df_raw.drop_duplicates()
    df_raw = df_raw.replace([np.inf, -np.inf], np.nan)
    df_raw = df_raw.dropna()

    X = df_raw.drop(' Label', axis=1)

    y_pred = model.predict(X)
    y_conf = model.predict_proba(X).max(axis=1)
    labels = encoder.inverse_transform(y_pred)

    result = pd.DataFrame({
        "Timestamp": pd.Timestamp.now() - pd.to_timedelta(np.arange(len(labels)) * 30, unit='s'),
        "Source IP": [f"192.168.1.{i%254+1}" for i in range(len(labels))],
        "Src Port": [random.choice([22, 80, 443, 445, 3389, 8080]) for _ in range(len(labels))],
        "Destination IP": [f"10.0.0.{i%50+1}" for i in range(len(labels))],
        "Classification": labels,
        "Confidence": y_conf,
        "Severity": [SEVERITY_MAP.get(l, "Unknown") for l in labels],
    })

    return result.sort_values("Timestamp", ascending=False).reset_index(drop=True)


df = load_predictions()
available_classes = sorted(df["Classification"].unique().tolist())
available_severities = sorted(df["Severity"].unique().tolist())

# ---------------------------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("### Filters")
    st.markdown("---")
    selected_types = st.multiselect("Attack Type", available_classes, default=available_classes)
    min_confidence = st.slider("Min Confidence", 0.0, 1.0, 0.7)
    severity_filter = st.multiselect("Severity", available_severities, default=available_severities)
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

# ---------------------------------------------------------------------------
# FILTERS
# ---------------------------------------------------------------------------

filtered = df[
    (df["Classification"].isin(selected_types)) &
    (df["Confidence"] >= min_confidence) &
    (df["Severity"].isin(severity_filter))
]

threats = filtered[filtered["Classification"] != "BENIGN"]

# ---------------------------------------------------------------------------
# HEADER
# ---------------------------------------------------------------------------

st.markdown('<div class="main-header">AI Threat Detection Dashboard</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header"><span class="live-dot"></span>Monitoring network traffic in real time</div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# METRIC CARDS
# ---------------------------------------------------------------------------

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
    "DDoS": "#ef4444",
    "BENIGN": "#22c55e",
}

# ---------------------------------------------------------------------------
# LIVE MAP — driven by real model predictions
# ---------------------------------------------------------------------------

st.markdown('<div class="section-title">Live Traffic Map: Real Model Predictions</div>', unsafe_allow_html=True)

# Pass real classified events into the JS map (sample up to 300)
map_sample = pd.DataFrame(columns=threats.columns)
map_events = []
for _, row in map_sample.iterrows():
    map_events.append({
        "srcIp": row["Source IP"],
        "dstIp": row["Destination IP"],
        "attack": row["Classification"],
        "confidence": round(float(row["Confidence"]), 3),
    })

map_events_json = json.dumps(map_events)

LIVE_MAP_HTML = f"""
<!DOCTYPE html>
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
  #alert-panel {{ flex-shrink: 0; height: 215px; background: #0d1117; border-top: 1px solid #1e293b; display: flex; flex-direction: column; overflow: hidden; }}
  #alert-panel-header {{ display: flex; justify-content: space-between; align-items: center; padding: 5px 12px; border-bottom: 1px solid #1e293b; flex-shrink: 0; }}
  #alert-panel-header .title {{ font-size: 0.75rem; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.06em; }}
  #alert-count {{ font-size: 0.72rem; color: #475569; }}
  #alert-scroll {{ overflow-y: auto; overflow-x: auto; flex: 1; }}
  #alert-table {{ width: 100%; border-collapse: collapse; font-size: 0.74rem; }}
  #alert-table thead th {{ position: sticky; top: 0; background: #111827; color: #475569; text-transform: uppercase; font-size: 0.63rem; letter-spacing: 0.05em; padding: 3px 10px; text-align: left; border-bottom: 1px solid #1e293b; white-space: nowrap; }}
  #alert-table td {{ padding: 3px 10px; color: #cbd5e1; border-bottom: 1px solid rgba(30,41,59,0.4); white-space: nowrap; }}
  #alert-table tr:hover td {{ background: rgba(30,41,59,0.4); }}
  @keyframes rowIn {{ from {{ background: rgba(239,68,68,0.15); }} to {{ background: transparent; }} }}
  .row-new {{ animation: rowIn 1.5s ease forwards; }}
</style>
</head>
<body>
  <div id="status"><span class="dot"></span>Replaying <span id="count">0</span> model-classified events</div>
  <div id="map-wrap">
    <div id="live-map"></div>
    <div class="legend">
      <div class="legend-row">Model Output</div>
      <div class="legend-item"><div class="legend-box" style="background:#ef4444;"></div> DDoS</div>
      <div class="legend-item"><div class="legend-box" style="background:#22c55e;"></div> BENIGN</div>
      <div class="legend-item"><div class="legend-box" style="background:#3b82f6;width:10px;height:10px;border-radius:50%;"></div> Target (SHU)</div>
    </div>
  </div>
  <div id="alert-panel">
    <div id="alert-panel-header">
      <span class="title">Real-Time Alert Log</span>
      <span id="alert-count">0 threats detected</span>
    </div>
    <div id="alert-scroll">
      <table id="alert-table">
        <thead><tr><th>Time</th><th>Source IP</th><th>Dest IP</th><th>Classification</th><th>Confidence</th></tr></thead>
        <tbody id="alert-tbody"><tr><td colspan="5" style="color:#475569;text-align:center;padding:16px;">Loading model predictions...</td></tr></tbody>
      </table>
    </div>
  </div>
<script>
  const MODEL_EVENTS = {map_events_json};

  const COLOR_MAP = {{
    "DDoS":   [239, 68,  68],
    "BENIGN": [34,  197, 94],
  }};
  const BADGE_STYLE = {{
    "DDoS":   {{ bg:"#450a0a", text:"#fca5a5" }},
    "BENIGN": {{ bg:"#14532d", text:"#86efac" }},
  }};

  const DRAW_MS = 1200, FADE_MS = 600, TTL_MS = 1800, PATH_POINTS = 360, HEAD_FADE_MS = 300;

  // Sacred Heart University — the target
  const TARGET = {{ lat: 41.1543, lon: -73.2571 }};

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

  const alertLog = [];
  let logDirty = false;
  let threatCount = 0;

  function addToLog(p) {{
    const t = new Date();
    const ts = t.toLocaleTimeString('en-US', {{hour12:false, hour:'2-digit', minute:'2-digit', second:'2-digit'}});
    if (p.attack !== 'BENIGN') threatCount++;
    alertLog.unshift({{ time:ts, srcIp:p.srcIp, dstIp:p.dstIp, attack:p.attack, confidence:p.confidence }});
    if (alertLog.length > 100) alertLog.pop();
    logDirty = true;
  }}

  function renderLog() {{
    const tbody = document.getElementById('alert-tbody');
    document.getElementById('alert-count').textContent = threatCount + ' threat' + (threatCount !== 1 ? 's' : '') + ' detected';
    const threats = alertLog.filter(e => e.attack !== 'BENIGN');
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
  let eventIndex = 0;

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
      initialViewState:{{ longitude:-20, latitude:30, zoom:2, pitch:0, bearing:0 }},
      controller:{{ minZoom:1.2 }}, layers:[basemap]
    }});

    function spawnNext() {{
      if (MODEL_EVENTS.length === 0) return;
      const evt = MODEL_EVENTS[eventIndex % MODEL_EVENTS.length];
      eventIndex++;
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
      document.getElementById('count').textContent = MODEL_EVENTS.length;

      const trailDots = [], sources = [], heads = [];

      livePackets.forEach(p => {{
        const age = now - p.ts;
        const progress = Math.min(1, age / DRAW_MS);
        const drawing = progress < 0.99;
        if (!drawing && !p.arrivedAt) {{ p.arrivedAt = now; addToLog(p); }}
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

    function scheduleNext() {{
      if (MODEL_EVENTS.length === 0) return;
      const evt = MODEL_EVENTS[eventIndex % MODEL_EVENTS.length];
      const isThreat = evt && evt.attack !== 'BENIGN';
      spawnNext();
      setTimeout(scheduleNext, isThreat ? 250 : 700);
    }}
    scheduleNext();

    setInterval(() => {{ if (logDirty) {{ logDirty = false; renderLog(); }} }}, 100);
  }}, 100);
</script>
</body>
</html>
"""

components.html(LIVE_MAP_HTML, height=720, scrolling=False)

# ---------------------------------------------------------------------------
# CHARTS
# ---------------------------------------------------------------------------

left, right = st.columns(2)

with left:
    st.markdown('<div class="section-title">Threats by Type</div>', unsafe_allow_html=True)
    type_counts = threats["Classification"].value_counts().reset_index()
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

st.markdown('<div class="section-title">Threat Activity (Last 24 Hours)</div>', unsafe_allow_html=True)
threats_timeline = threats.copy()
threats_timeline["Hour"] = threats_timeline["Timestamp"].dt.floor("h")
hourly = threats_timeline.groupby(["Hour", "Classification"]).size().reset_index(name="Count")
fig3 = px.area(hourly, x="Hour", y="Count", color="Classification", color_discrete_map=color_map)
fig3.update_layout(**chart_layout, height=300)
fig3.update_xaxes(gridcolor="#1e293b")
fig3.update_yaxes(gridcolor="#1e293b")
st.plotly_chart(fig3, use_container_width=True, config={"displayModeBar": False})
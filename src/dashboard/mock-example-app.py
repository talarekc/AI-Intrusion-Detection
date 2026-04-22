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

# Live traffic map: client-side JS animation, no Streamlit reruns
st.markdown('<div class="section-title">Live Traffic Map</div>', unsafe_allow_html=True)

LIVE_MAP_HTML = """
<!DOCTYPE html>
<html>
<head>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
<style>
  body { margin: 0; background: #0a0e17; font-family: 'Inter', sans-serif; color: #e2e8f0; }
  #status { color: #64748b; font-size: 0.85rem; margin: 0 0 0.5rem 4px; }
  .dot {
    display: inline-block; width: 8px; height: 8px; background: #22c55e;
    border-radius: 50%; margin-right: 6px; animation: pulse 2s infinite;
  }
  @keyframes pulse { 0%,100% { opacity: 1 } 50% { opacity: 0.3 } }
</style>
</head>
<body>
  <div id="status"><span class="dot"></span><span id="count">0</span> active packet(s) in flight</div>
  <div id="live-map" style="width:100%;height:500px;"></div>
<script>
  const colorMap = {
    "Port Scan": "#3b82f6",
    "Brute Force": "#ef4444",
    "DDoS": "#f97316",
    "Web Attack": "#a855f7"
  };
  const attacks = ["Port Scan", "Brute Force", "DDoS", "Web Attack"];

  // Animation timing
  const DRAW_MS = 900;       // arc extends src -> dst over this duration
  const IMPACT_MS = 500;     // destination pulse duration after arrival
  const FADE_MS = 500;       // fade-out after draw completes
  const TTL_MS = DRAW_MS + FADE_MS;
  const SPAWN_MS = 600;      // new packets spawn every this often
  const FRAME_MS = 40;       // ~25fps animation tick
  const PATH_POINTS = 24;    // resolution of great-circle arc

  let livePackets = [];

  // Curated source cities (lat, lon) — sources snap to one of these so they
  // always land on a populated city, never in the ocean.
  const SOURCE_CITIES = [
    [40.71, -74.01], [34.05, -118.24], [41.88, -87.63], [29.76, -95.37],
    [25.76, -80.19], [47.61, -122.33], [39.74, -104.99], [43.65, -79.38],
    [49.28, -123.12], [19.43, -99.13],
    [-23.55, -46.63], [-34.60, -58.38], [-12.05, -77.04], [4.71, -74.07],
    [-33.45, -70.67], [-22.91, -43.17],
    [51.51, -0.13], [48.86, 2.35], [52.52, 13.40], [40.42, -3.70],
    [41.90, 12.50], [55.76, 37.62], [59.33, 18.07], [52.37, 4.90],
    [52.23, 21.01], [41.01, 28.98], [50.45, 30.52], [53.35, -6.26],
    [30.04, 31.24], [6.52, 3.38], [-1.29, 36.82], [-26.20, 28.04],
    [33.57, -7.59], [9.03, 38.74],
    [35.68, 139.69], [39.90, 116.41], [31.23, 121.47], [37.57, 126.98],
    [19.08, 72.88], [28.61, 77.21], [13.76, 100.50], [1.35, 103.82],
    [-6.21, 106.85], [14.60, 120.98], [21.03, 105.85], [35.69, 51.39],
    [24.86, 67.01], [24.71, 46.68], [25.20, 55.27], [22.32, 114.17],
    [-33.87, 151.21], [-37.81, 144.96], [-36.85, 174.76]
  ];

  function ipToGeo(ip, isSource) {
    let h = 0;
    for (let i = 0; i < ip.length; i++) {
      h = ((h << 5) - h + ip.charCodeAt(i)) | 0;
    }
    h = Math.abs(h);
    if (isSource) {
      const city = SOURCE_CITIES[h % SOURCE_CITIES.length];
      const jitterLat = (((h >> 8) % 100) / 100 - 0.5) * 0.8;
      const jitterLon = (((h >> 16) % 100) / 100 - 0.5) * 0.8;
      return [city[0] + jitterLat, city[1] + jitterLon];
    }
    return [
      40.7 + ((h % 1000) / 1000 - 0.5) * 1.5,
      -74.0 + (((h >> 8) % 1000) / 1000 - 0.5) * 1.5
    ];
  }

  // Quadratic bezier path in lat/lon space — direct route from src to dst
  // with a gentle perpendicular arc. Avoids the polar loops that great-circle
  // paths can produce on flat projections.
  function buildPath(lat1, lon1, lat2, lon2) {
    // Treat map as flat: go directly across the projection from src to dst,
    // even if that's the longer path on a globe. No dateline wraparound.
    const dlon = lon2 - lon1;
    const dlat = lat2 - lat1;
    const lon2eff = lon2;

    const dist = Math.sqrt(dlat*dlat + dlon*dlon);
    const len = Math.max(dist, 0.001);

    // Perpendicular offset, always biased "upward" (toward northern hemisphere)
    // so all arcs curve consistently rather than randomly above/below.
    let perpLat = -dlon / len;
    let perpLon = dlat / len;
    if (perpLat < 0) { perpLat = -perpLat; perpLon = -perpLon; }
    const offset = dist * 0.15;

    const cLat = lat1 + dlat * 0.5 + perpLat * offset;
    const cLon = lon1 + dlon * 0.5 + perpLon * offset;

    const path = [];
    for (let i = 0; i <= PATH_POINTS; i++) {
      const t = i / PATH_POINTS;
      const u = 1 - t;
      const lat = u*u*lat1 + 2*u*t*cLat + t*t*lat2;
      const lon = u*u*lon1 + 2*u*t*cLon + t*t*lon2eff;
      path.push([lat, lon]);
    }
    return path;
  }

  // ease-out cubic: starts fast, slows toward destination — feels like a packet
  function easeOut(t) { return 1 - Math.pow(1 - t, 3); }

  const layout = {
    paper_bgcolor: "rgba(0,0,0,0)",
    plot_bgcolor: "rgba(0,0,0,0)",
    font: { family: "Inter", color: "#94a3b8" },
    margin: { l: 0, r: 0, t: 10, b: 0 },
    showlegend: true,
    legend: { font: { size: 11, color: "#e2e8f0" }, bgcolor: "rgba(0,0,0,0)" },
    geo: {
      bgcolor: "rgba(0,0,0,0)",
      showland: true, landcolor: "#111827",
      showcountries: true, countrycolor: "#1e293b",
      showocean: true, oceancolor: "#0a0e17",
      coastlinecolor: "#1e293b",
      projection: { type: "natural earth" },
      showframe: false
    }
  };

  Plotly.newPlot("live-map", [], layout, { displayModeBar: false, responsive: true });

  function spawnPacket() {
    const attack = attacks[Math.floor(Math.random() * attacks.length)];
    const srcIp = "192.168.1." + (1 + Math.floor(Math.random() * 254));
    const dstIp = "10.0.0." + (1 + Math.floor(Math.random() * 50));
    const [srcLat, srcLon] = ipToGeo(srcIp, true);
    const [dstLat, dstLon] = ipToGeo(dstIp, false);
    livePackets.push({
      ts: Date.now(),
      attack, srcIp, dstIp, srcLat, srcLon, dstLat, dstLon,
      path: buildPath(srcLat, srcLon, dstLat, dstLon)
    });
  }

  function spawnTick() {
    const n = 1 + Math.floor(Math.random() * 2);
    for (let i = 0; i < n; i++) spawnPacket();
  }

  function frame() {
    const now = Date.now();
    livePackets = livePackets.filter(p => now - p.ts < TTL_MS);

    const traces = [];

    // Static legend stubs: one per attack type, fixed order, no data.
    // These provide a stable legend regardless of which packets are in flight.
    attacks.forEach(a => {
      traces.push({
        type: "scattergeo",
        lat: [null], lon: [null],
        mode: "lines",
        line: { width: 2, color: colorMap[a] },
        name: a,
        legendgroup: a,
        showlegend: true,
        hoverinfo: "skip"
      });
    });

    const srcLats = [], srcLons = [], srcText = [], srcOpac = [];
    const dstLats = [], dstLons = [], dstSizes = [], dstText = [];
    const headLats = [], headLons = [], headColors = [], headSizes = [];

    livePackets.forEach(p => {
      const age = now - p.ts;
      const rawProgress = Math.min(1.0, age / DRAW_MS);
      const progress = easeOut(rawProgress);
      const drawing = age < DRAW_MS;

      // Opacity: full while drawing, then linear fade after arrival
      const opacity = drawing ? 1.0 : Math.max(0, 1 - (age - DRAW_MS) / FADE_MS);
      if (opacity <= 0) return;

      const color = colorMap[p.attack] || "#3b82f6";

      // Build current arc segment from src to current head position
      const N = p.path.length - 1;
      const lastIdx = Math.max(1, Math.min(N, Math.ceil(progress * N)));
      const lats = [], lons = [];
      for (let i = 0; i <= lastIdx; i++) {
        lats.push(p.path[i][0]);
        lons.push(p.path[i][1]);
      }

      traces.push({
        type: "scattergeo",
        lat: lats, lon: lons,
        mode: "lines",
        line: { width: 2, color: color },
        opacity: opacity,
        legendgroup: p.attack,
        showlegend: false,
        hoverinfo: "skip"
      });

      // Source marker
      srcLats.push(p.srcLat); srcLons.push(p.srcLon);
      srcText.push(p.srcIp + " &rarr; " + p.dstIp + "<br>" + p.attack);
      srcOpac.push(opacity * 0.85);

      if (drawing) {
        // Bright head marker leading the line — the "tracer"
        const head = p.path[lastIdx];
        headLats.push(head[0]);
        headLons.push(head[1]);
        headColors.push(color);
        headSizes.push(9);
      } else {
        // Destination pulse — grows briefly on impact, then settles
        const impactAge = age - DRAW_MS;
        const pulseT = Math.min(1, impactAge / IMPACT_MS);
        const pulseSize = 9 + (1 - pulseT) * 10;
        dstLats.push(p.dstLat); dstLons.push(p.dstLon);
        dstSizes.push(pulseSize);
        dstText.push(p.dstIp);
      }
    });

    if (srcLats.length) {
      traces.push({
        type: "scattergeo",
        lat: srcLats, lon: srcLons, mode: "markers",
        marker: { size: 6, color: "#ef4444", opacity: srcOpac, line: { width: 0 } },
        name: "Source", text: srcText, hoverinfo: "text", showlegend: false
      });
    }
    if (headLats.length) {
      traces.push({
        type: "scattergeo",
        lat: headLats, lon: headLons, mode: "markers",
        marker: {
          size: headSizes, color: headColors,
          line: { color: "#ffffff", width: 1.5 }
        },
        hoverinfo: "skip", showlegend: false
      });
    }
    if (dstLats.length) {
      traces.push({
        type: "scattergeo",
        lat: dstLats, lon: dstLons, mode: "markers",
        marker: {
          size: dstSizes, color: "#22c55e", symbol: "diamond",
          line: { color: "#bbf7d0", width: 1 }
        },
        name: "Destination", text: dstText, hoverinfo: "text", showlegend: false
      });
    }

    Plotly.react("live-map", traces, layout, { displayModeBar: false, responsive: true });
    document.getElementById("count").textContent = livePackets.length;
  }

  setInterval(frame, FRAME_MS);
  setInterval(spawnTick, SPAWN_MS);
  spawnTick();
</script>
</body>
</html>
"""

components.html(LIVE_MAP_HTML, height=560, scrolling=False)

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

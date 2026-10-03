import time
import json
import threading
import asyncio
import os
from collections import Counter
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from google.antigravity import Agent, LocalAgentConfig
import simulator
# Defensive agent import. If any name is missing from agent.py,
# we fall back to a stub AgentService so the dashboard always loads.
try:
    from agent import AGENT, start_agent
    _AGENT_AVAILABLE = True
except ImportError:
    _AGENT_AVAILABLE = False

    class _StubAgent:
        """No-op stand-in so the dashboard renders when agent.py fails."""
        def __init__(self):
            self.blocked_ips = set()
            self.tier_states = {"tier1": "IDLE", "tier2": "IDLE",
                                "tier3": "IDLE"}
            self.tier_counts = {"tier1": 0, "tier2": 0, "tier3": 0}
        def snapshot_state(self):
            return {"agent_state": "IDLE",
                    "current_task": "Agent offline",
                    "verifications": 0,
                    "actions_taken": 0}
        def snapshot_blocked(self):
            return set()
        def snapshot_log(self):
            return []
        def block_ip(self, ip, reason, **kw):
            pass
        def reset(self):
            pass
        def memory_summary(self):
            return {"blocked_from_history": [],
                    "history_file": "", "history_entries": 0}

    AGENT = _StubAgent()
    def start_agent(*a, **kw):
        return None

# Provide module-level stubs for names that may not exist in agent.py.
# These are used in optional UI blocks that we'll delete below, but
# we define them defensively in case any reference remains.
try:
    from agent import THREAT_INTEL_DB
except ImportError:
    THREAT_INTEL_DB = {}

try:
    from agent import MEMORY_FILE
except ImportError:
    MEMORY_FILE = None

try:
    from agent import PLAYBOOKS
except ImportError:
    PLAYBOOKS = {}

try:
    from agent import generate_attack_narrative
except ImportError:
    def generate_attack_narrative() -> str:
        return "(narrative feature unavailable)"
import streamlit as st
from packet_buffer import PacketBuffer
from detector import (
    AnomalyDetector, FloodRule, PortScanRule,
    BruteForceRule, IcmpFloodRule, NullScanRule,
    XmasScanRule, MaliciousFileRule
)
from datetime import datetime

AGENT_PIXELS = [
    "....HHHHHHHH....",
    "...HHHHHHHHHH...",
    "..HHHHHHHHHHHH..",
    "..HHSSSSSSSSHH..",
    "..HSSSSSSSSSSH..",
    "..HSEESSSSEESH..",
    "..HSEBSSSSBESH..",
    "..HSSSSSSSSSSH..",
    "..HSSSMMMMSSSH..",
    "...SSSSSSSSSS...",
    "....SSSSSSSS....",
    "..AATTTTTTTTAA..",
    "..AATTTTTTTTAA..",
    "..AATTTTTTTTAA..",
    "..AATTTTTTTTAA..",
    "..AATTTTTTTTAA..",
    "..AATTTTTTTTAA..",
    "....TTTTTTTT....",
    "....PPPPPPPP....",
    "....PPPPPPPP....",
    "....PPPPPPPP....",
    "....PPP..PPP....",
    "....PPP..PPP....",
    "....FFF..FFF....",
]

PIXEL_COLORS = {
    "H": "#3d2b1f", "S": "#d4a373", "E": "#ffffff",
    "B": "#1e3a8a", "M": "#8b5a2b", "T": "#00a6a6",
    "A": "#d4a373", "P": "#2f4f7f", "F": "#4a4a4a",
}

TOUR_STEPS = [
    {
        "title": "Welcome",
        "body": "This dashboard analyzes network traffic in real time. "
                "Let's walk through what you're seeing.",
        "target": None,
    },
    {
        "title": "📥 Incoming Packets",
        "body": "Every packet hitting the server appears here — "
                "timestamp, source, protocol, size, flags. "
                "Attacker rows are tinted red.",
        "target": "pane1",
    },
    {
        "title": "📊 Traffic Patterns",
        "body": "Protocol mix, packets-per-second rate, and byte "
                "throughput. The red dashed line is our 30 PPS threshold.",
        "target": "pane2",
    },
    {
        "title": "🚨 Threat Detection",
        "body": "The risk gauge climbs as attacks fire. Each alert "
                "shows the attack type, source IP, and reason.",
        "target": "pane3",
    },
    {
        "title": "🤖 AI Explainer",
        "body": "Every alert type is explained in plain English by "
                "an AI agent. Click ℹ️ on any alert to see the rule "
                "and threshold that triggered it.",
        "target": "pane3",
    },
    {
        "title": "🎯 Threat Scorecard & Timeline",
        "body": "Below the panes: per-IP threat scores and a timeline "
                "of when each attack fired.",
        "target": "footer",
    },
    {
        "title": "Try It Yourself",
        "body": "Block an IP with 🚫, tune thresholds in the sidebar, "
                "or export alerts as CSV. The demo is fully interactive.",
        "target": None,
    },
]

GEO_MAP = {
    "192.168.1.94": ("Beijing", "CN", 39.9, 116.4),
    "192.168.1.95": ("Moscow", "RU", 55.75, 37.62),
    "192.168.1.96": ("São Paulo", "BR", -23.55, -46.63),
    "192.168.1.97": ("Lagos", "NG", 6.52, 3.38),
    "192.168.1.98": ("Mumbai", "IN", 19.08, 72.88),
    "192.168.1.99": ("Kyiv", "UA", 50.45, 30.52),
}
GEO_DEFAULT = ("Unknown", "—", 0, 0)

def safe_float(value, default: float = 0.0) -> float:
    """Coerce value to float, falling back to default on None/errors."""
    try:
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        return default

def _audit(actor: str, action: str, detail: str = "") -> None:
    """Append an entry to the session audit log."""
    try:
        st.session_state.audit_log.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "actor": actor,
            "action": action,
            "detail": detail,
        })
        if len(st.session_state.audit_log) > 200:
            st.session_state.audit_log = st.session_state.audit_log[-200:]
    except Exception:
        pass

def _recent_pps(packets: list[dict]) -> float:
    """Packets per second over the last ~10 packets. Never returns None."""
    if not packets or len(packets) < 2:
        return 0.0
    try:
        from detector import analyze_pps
        value = analyze_pps(packets[-10:])
    except Exception:
        return 0.0
    return float(value) if value is not None else 0.0

from collections import defaultdict

def _threat_scorecard(alerts: list[dict]) -> pd.DataFrame:
    """Group alerts by source IP and compute a per-IP threat score."""
    by_ip = defaultdict(lambda: {
        "alerts": 0,
        "types": set(),
        "first_time": None,
        "last_time": None,
        "blocked": False,
    })

    for a in alerts:
        ip = a.get("ip")
        if not ip:
            continue
        if a.get("type") == "BLOCKED IP":
            by_ip[ip]["blocked"] = True
            continue
        rec = by_ip[ip]
        rec["alerts"] += 1
        rec["types"].add(a["type"])
        t = a.get("time", "")
        if t:
            if rec["first_time"] is None or t < rec["first_time"]:
                rec["first_time"] = t
            if rec["last_time"] is None or t > rec["last_time"]:
                rec["last_time"] = t

    rows = []
    for ip, rec in by_ip.items():
        score = min(100,
                    rec["alerts"] * 15
                    + len(rec["types"]) * 20
                    + (30 if rec["blocked"] else 0))
        rows.append({
            "IP": ip,
            "Threat Score": score,
            "Alerts": rec["alerts"],
            "Attack Types": len(rec["types"]),
            "First Seen": rec["first_time"] or "—",
            "Last Seen": rec["last_time"] or "—",
            "Status": "🚫 Blocked" if rec["blocked"] else "🔴 Active",
        })

    if not rows:
        return pd.DataFrame(columns=["IP", "Threat Score", "Alerts",
                                     "Attack Types", "First Seen",
                                     "Last Seen", "Status"])

    df = pd.DataFrame(rows).sort_values(
        ["Threat Score", "Alerts", "IP"],
        ascending=[False, False, True],
    ).reset_index(drop=True)
    return df

def _filter_by_server(packets, server):
    if server == "All servers":
        return packets
    return [p for p in packets if p.get("destination") == server]

def build_flow_chart(packets: list[dict]) -> go.Figure:
    """Return a Plotly scatter showing recent packets flowing to a server."""
    fig = go.Figure()
    
    server_label = "MULTIPLE SERVERS"
    if packets:
        dsts = {p.get("destination") for p in packets if "destination" in p}
        if len(dsts) == 1:
            server_label = f"SERVER {list(dsts)[0]}"
            
    # Server marker
    fig.add_trace(go.Scatter(
        x=[10], y=[0],
        mode="markers+text",
        marker=dict(symbol="square", size=24, color="white"),
        text=[server_label],
        textposition="top center",
        hoverinfo="skip"
    ))
    
    if not packets:
        fig.add_annotation(
            text="Waiting for packets...",
            x=5, y=0,
            showarrow=False,
            font=dict(color="#8b949e", size=14)
        )
    else:
        recent = packets[-20:]
        max_index = len(recent)
        
        for i, p in enumerate(recent):
            # i=0 is oldest in window, i=19 is newest
            # Animate moving towards server (x=10)
            age = max_index - i
            x_pos = (age / max_index) * 10
            
            ip_parts = p["source"].split(".")
            y_offset = (int(ip_parts[-1]) % 10) - 5
            
            is_attacker = p["source"].startswith("192.168.1.9") and int(ip_parts[-1]) >= 94
            has_file = p.get("filename") is not None
            
            color = "#ef4444" if is_attacker else "#f59e0b" if has_file else "#3b82f6"
            size = 16 if (is_attacker or has_file) else 12
            
            # Line to server
            fig.add_trace(go.Scatter(
                x=[x_pos, 10],
                y=[y_offset, 0],
                mode="lines",
                line=dict(color=color, width=1, dash="dot"),
                hoverinfo="skip"
            ))
            
            # Packet marker
            fig.add_trace(go.Scatter(
                x=[x_pos],
                y=[y_offset],
                mode="markers",
                marker=dict(color=color, size=size),
                hovertext=f"{p['source']} -> {p['protocol']} size={p['size']}"
            ))

    fig.update_layout(
        height=200,
        margin=dict(l=20, r=20, t=20, b=20),
        paper_bgcolor="#161b22",
        plot_bgcolor="#161b22",
        showlegend=False,
        xaxis=dict(showgrid=False, zeroline=False, visible=False, range=[0, 11]),
        yaxis=dict(showgrid=False, zeroline=False, visible=False, range=[-6, 6])
    )
    
    return fig

from datetime import datetime
from collections import defaultdict

def build_throughput_chart(packets: list[dict]) -> go.Figure:
    """Stacked area chart of bytes/sec by protocol."""
    CHART_HEIGHT = 220
    COLOR = {"TCP": "#3b82f6", "UDP": "#22c55e", "ICMP": "#f97316"}

    if len(packets) < 2:
        fig = go.Figure()
        fig.add_annotation(text="Waiting for traffic…",
                           showarrow=False,
                           font={"color": "#8b949e", "size": 13})
        fig.update_layout(
            height=CHART_HEIGHT,
            paper_bgcolor="#161b22", plot_bgcolor="#161b22",
            xaxis={"visible": False}, yaxis={"visible": False},
        )
        return fig

    # Bucket by seconds-since-first-packet
    try:
        t0 = datetime.strptime(packets[0]["timestamp"], "%H:%M:%S.%f")
    except (ValueError, KeyError):
        return build_throughput_chart([])

    buckets = defaultdict(lambda: defaultdict(int))
    for p in packets:
        try:
            t = datetime.strptime(p["timestamp"], "%H:%M:%S.%f")
            offset = max(0, int((t - t0).total_seconds()))
        except (ValueError, KeyError):
            continue
        buckets[offset][p["protocol"]] += p["size"]

    seconds = sorted(buckets.keys())

    fig = go.Figure()
    for proto in ["TCP", "UDP", "ICMP"]:
        ys = [buckets[s].get(proto, 0) / 1024 for s in seconds]
        fig.add_trace(go.Scatter(
            x=seconds, y=ys,
            name=proto, mode="lines",
            stackgroup="one",
            line={"width": 0.5, "color": COLOR[proto]},
            fillcolor=COLOR[proto],
            hovertemplate=f"{proto}: %{{y:.1f}} KB/s<extra></extra>",
        ))

    fig.update_layout(
        height=CHART_HEIGHT,
        margin={"t": 60, "b": 40, "l": 50, "r": 20},
        paper_bgcolor="#161b22", plot_bgcolor="#161b22",
        font={"color": "#8b949e", "size": 11},
        xaxis={"title": "Seconds since start",
               "showgrid": False, "tickmode": "linear",
               "dtick": 5},
        yaxis={"title": "KB/s", "gridcolor": "#30363d"},
        legend={"orientation": "h",
                "yanchor": "bottom", "y": 1.02,
                "xanchor": "left",  "x": 0},
    )
    return fig

def build_timeline(alerts: list[dict]) -> go.Figure:
    """Return a Plotly scatter showing alert occurrences over time."""
    if not alerts:
        fig = go.Figure()
        fig.add_annotation(text="No alerts yet", showarrow=False,
                           font={"color": "#8b949e", "size": 13})
        fig.update_layout(height=140, paper_bgcolor="#161b22",
                          plot_bgcolor="#161b22",
                          xaxis={"visible": False},
                          yaxis={"visible": False})
        return fig

    # Parse each alert's "time" field (HH:MM:SS) into seconds since
    # the first alert's time.
    def _to_sec(hms: str) -> float:
        h, m, s = hms.split(":")
        return int(h) * 3600 + int(m) * 60 + int(s)

    t0 = None
    for a in alerts:
        if "time" in a:
            t0 = _to_sec(a["time"])
            break
            
    if t0 is None:
        fig = go.Figure()
        fig.update_layout(height=140, paper_bgcolor="#161b22",
                          plot_bgcolor="#161b22",
                          xaxis={"visible": False},
                          yaxis={"visible": False})
        return fig

    type_order = ["DoS / FLOOD", "PORT SCAN", "SSH BRUTE FORCE",
                  "ICMP FLOOD", "NULL SCAN", "XMAS SCAN",
                  "MALICIOUS FILE", "BLOCKED IP"]
    color_map = {
        "DoS / FLOOD":       "#ef4444",
        "PORT SCAN":         "#f59e0b",
        "SSH BRUTE FORCE":   "#a855f7",
        "ICMP FLOOD":        "#3b82f6",
        "NULL SCAN":         "#8b949e",
        "XMAS SCAN":         "#d97706",
        "MALICIOUS FILE":    "#dc2626",
        "BLOCKED IP":        "#6e7681"
    }

    xs, ys, texts, colors = [], [], [], []
    for a in alerts:
        if "time" not in a:
            continue
        if a["type"] not in type_order:
            continue
        xs.append(_to_sec(a["time"]) - t0)
        ys.append(a["type"])
        texts.append(f"{a['type']} — {a['ip']}")
        colors.append(color_map[a["type"]])

    fig = go.Figure(go.Scatter(
        x=xs, y=ys, mode="markers",
        marker={"size": 14, "color": colors,
                "line": {"width": 1, "color": "#fafafa"}},
        text=texts, hovertemplate="%{text}<extra></extra>",
    ))
    fig.update_layout(
        height=180,
        margin={"t": 20, "b": 30, "l": 130, "r": 20},
        paper_bgcolor="#161b22", plot_bgcolor="#161b22",
        font={"color": "#8b949e"},
        xaxis={"title": "Seconds since session start",
               "gridcolor": "#30363d", "zeroline": False},
        yaxis={"gridcolor": "#30363d", "zeroline": False,
               "categoryorder": "array",
               "categoryarray": list(reversed(type_order))},
        showlegend=False,
    )
    return fig

def build_geo_map(alerts: list[dict]) -> go.Figure:
    """Scatter-geo world map with attacker pins."""
    pins = [a for a in alerts if a["type"] != "BLOCKED IP"]
    lats, lons, texts, colors = [], [], [], []
    for a in pins:
        city, cc, lat, lon = GEO_MAP.get(a["ip"], GEO_DEFAULT)
        if lat == 0 and lon == 0:
            continue
        lats.append(lat)
        lons.append(lon)
        texts.append(f"{a['ip']} — {city}, {cc}")
        colors.append("#ef4444")
    if not lats:
        fig = go.Figure()
        fig.add_annotation(text="No geo data", showarrow=False,
                           font={"color": "#8b949e"})
        fig.update_layout(height=280, paper_bgcolor="#161b22",
                          plot_bgcolor="#161b22",
                          xaxis={"visible": False},
                          yaxis={"visible": False})
        return fig
    fig = go.Figure(go.Scattergeo(
        lat=lats, lon=lons, mode="markers",
        marker={"size": 12, "color": colors,
                "line": {"width": 1, "color": "#fafafa"}},
        text=texts, hovertemplate="%{text}<extra></extra>",
    ))
    fig.update_geos(
        showcountries=True, countrycolor="#30363d",
        showcoastlines=True, coastlinecolor="#30363d",
        showland=True, landcolor="#1f242c",
        showocean=True, oceancolor="#0e1117",
        bgcolor="#161b22",
    )
    fig.update_layout(
        height=280,
        margin={"t": 10, "b": 10, "l": 10, "r": 10},
        paper_bgcolor="#161b22",
        showlegend=False,
    )
    return fig

st.set_page_config(layout="wide", page_title="Network Packet Analyzer")

st.markdown("""
<style>
/* Pane card container */
div[data-testid="stVerticalBlockBorderWrapper"] {
    background: #161b22;
    border: 1px solid #30363d !important;
    border-radius: 12px;
    padding: 1rem 1.1rem !important;
}
/* Pane header badge */
.pane-badge {
    display: inline-block;
    padding: 6px 16px;
    border-radius: 8px;
    font-weight: 600;
    font-size: 16px;
    margin-bottom: 12px;
}
.pane-badge.blue   { color: #58a6ff; background: #132039; }
.pane-badge.green  { color: #3fb950; background: #0f2417; }
.pane-badge.red    { color: #f85149; background: #2d1519; }
/* Monospace table */
div[data-testid="stDataFrame"] * { font-family: ui-monospace, monospace; }
/* Alert card base */
.alert-card {
    border-radius: 8px;
    padding: 12px 14px;
    margin-bottom: 10px;
    border-left: 4px solid;
}
.alert-card .title   { font-weight: 700; font-size: 15px; }
.alert-card .ip      { color: #8b949e; font-size: 12px; float: right;
                       font-family: ui-monospace, monospace; }
.alert-card .detail  { color: #c9d1d9; font-size: 13px; margin-top: 4px; }
.alert-flood   { background: #2d1519; border-color: #f85149; color: #f85149; }
.alert-scan    { background: #2d2215; border-color: #f59e0b; color: #f59e0b; }
.alert-brute   { background: #2a1e2d; border-color: #a855f7; color: #a855f7; }
.alert-icmp    { background: #152638; border-color: #58a6ff; color: #58a6ff; }
.alert-null    { background: #1a1a1a; border-color: #8b949e; color: #8b949e; }
.alert-xmas    { background: #2d1f15; border-color: #d97706; color: #d97706; }
.alert-malware {
    background: #2d0d0d;
    border-color: #dc2626;
    color: #dc2626;
    border-left-width: 6px;
}
.alert-malware .hash {
    color: #8b949e;
    font-size: 11px;
    font-family: ui-monospace, monospace;
    margin-top: 4px;
}
.alert-blocked {
    background: #1f1f1f;
    border-color: #6e7681;
    border-left-color: #6e7681;
    color: #6e7681;
}
.alert-blocked .title { color: #8b949e; }
.alert-blocked .detail { color: #6e7681; }
/* Dimmed row style for Pane 1 */
.blocked-row { opacity: 0.4; }
.ai-note {
    margin-top: 6px;
    padding: 6px 10px;
    background: rgba(59, 130, 246, 0.08);
    border-left: 2px solid #3b82f6;
    border-radius: 4px;
    font-size: 12px;
    color: #a5b4fc;
    font-style: italic;
    line-height: 1.4;
}
.explain-panel {
    background: #0d1117;
    border: 1px solid #30363d;
    border-left: 4px solid #f59e0b;
    border-radius: 8px;
    padding: 12px 14px;
    margin-bottom: 12px;
    font-size: 13px;
}
.explain-title {
    font-weight: 700;
    font-size: 15px;
    color: #f59e0b;
    margin-bottom: 8px;
}
.explain-panel code {
    background: #1f242c;
    color: #a5b4fc;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 12px;
}
/* Footer bar */
.footer-bar {
    position: fixed; bottom: 0; left: 0; right: 0;
    background: #0d1117; border-top: 1px solid #30363d;
    padding: 8px 24px; font-size: 13px; color: #8b949e;
    font-family: ui-monospace, monospace; z-index: 999;
}
.footer-bar b { color: #e6edf3; }
.tour-overlay {
    background: linear-gradient(135deg, #1e40af 0%, #312e81 100%);
    border: 2px solid #60a5fa;
    border-radius: 12px;
    padding: 16px 22px;
    margin-bottom: 16px;
    box-shadow: 0 0 24px rgba(96, 165, 250, 0.35);
}
.tour-progress {
    color: #93c5fd;
    font-size: 11px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin-bottom: 6px;
}
.tour-title {
    color: #ffffff;
    font-weight: 700;
    font-size: 20px;
    margin-bottom: 6px;
}
.tour-body {
    color: #dbeafe;
    font-size: 14px;
    line-height: 1.5;
}
.hero-strip {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 12px;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 20px;
}
.hero-cell {
    text-align: center;
    padding: 6px;
    border-right: 1px solid #21262d;
}
.hero-cell:last-child { border-right: none; }
.hero-label {
    color: #8b949e;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    margin-bottom: 4px;
}
.hero-value {
    color: #fafafa;
    font-size: 26px;
    font-weight: 700;
    font-family: ui-monospace, monospace;
    line-height: 1.1;
}
@keyframes alert-pulse-glow {
    0%   { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
    50%  { box-shadow: 0 0 0 8px rgba(239, 68, 68, 0); }
    100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
}
.alert-pulse {
    animation: alert-pulse-glow 1.2s ease-out 2;
    border-width: 2px;
}
.pixel-agent {
    transition: filter 0.4s ease, transform 0.4s ease;
}
.pixel-agent[data-state="IDLE"]         { filter: grayscale(0.5); }
.pixel-agent[data-state="MONITORING"]   { 
    filter: none;
    animation: breathe 2.5s ease-in-out infinite;
}
.pixel-agent[data-state="INVESTIGATING"]{
    filter: drop-shadow(0 0 6px #f59e0b);
    animation: investigate-bob 0.9s ease-in-out infinite;
}
.pixel-agent[data-state="BLOCKING"]     {
    filter: drop-shadow(0 0 8px #ef4444);
    transform: scale(1.05);
    animation: block-shake 0.5s ease-in-out 2;
}
.pixel-agent[data-state="ERROR"]        { 
    filter: hue-rotate(300deg);
    animation: error-flash 0.6s ease-in-out infinite;
}

@keyframes blink {
    0%, 92%, 100% { opacity: 1; }
    95%, 97%      { opacity: 0.2; }
}
.pixel-agent .pixel[data-px="5-4"],
.pixel-agent .pixel[data-px="5-5"],
.pixel-agent .pixel[data-px="5-10"],
.pixel-agent .pixel[data-px="5-11"],
.pixel-agent .pixel[data-px="6-4"],
.pixel-agent .pixel[data-px="6-5"],
.pixel-agent .pixel[data-px="6-10"],
.pixel-agent .pixel[data-px="6-11"] {
    animation: blink 3.2s infinite;
}
@keyframes investigate-bob {
    0%, 100% { transform: translateY(0); }
    50%      { transform: translateY(-4px); }
}
@keyframes block-shake {
    0%, 100% { transform: translateX(0) scale(1.05); }
    20%      { transform: translateX(-4px) scale(1.05); }
    40%      { transform: translateX(4px)  scale(1.05); }
    60%      { transform: translateX(-3px) scale(1.05); }
    80%      { transform: translateX(3px)  scale(1.05); }
}
@keyframes error-flash {
    0%, 100% { filter: hue-rotate(300deg) brightness(1); }
    50%      { filter: hue-rotate(300deg) brightness(1.4); }
}
@keyframes breathe {
    0%, 100% { transform: scale(1); }
    50%      { transform: scale(1.02); }
}
.agent-bubble {
    background: #1f242c;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 6px 10px;
    font-size: 11px;
    color: #c9d1d9;
    max-width: 220px;
    margin-bottom: 6px;
    position: relative;
    font-family: ui-monospace, monospace;
}
.agent-bubble::after {
    content: "";
    position: absolute;
    bottom: -8px;
    left: 20px;
    border: 4px solid transparent;
    border-top-color: #30363d;
}
</style>
""", unsafe_allow_html=True)

if "packet_buffer" not in st.session_state:
    st.session_state.packet_buffer = PacketBuffer()
if "detector" not in st.session_state:
    st.session_state.detector = AnomalyDetector()
if "agent_thread" not in st.session_state:
    st.session_state.agent_thread = None
if "sim_started" not in st.session_state:
    st.session_state.sim_started = False
if "last_analyzed_idx" not in st.session_state:
    st.session_state.last_analyzed_idx = 0
if "last_agent_answer" not in st.session_state:
    st.session_state.last_agent_answer = None
if "last_agent_question" not in st.session_state:
    st.session_state.last_agent_question = None
if "narrative" not in st.session_state:
    st.session_state.narrative = None
if "sim_thread" not in st.session_state:
    st.session_state.sim_thread = None
if "replay_mode" not in st.session_state:
    st.session_state.replay_mode = False
if "replay_snapshot" not in st.session_state:
    st.session_state.replay_snapshot = []
if "replay_position" not in st.session_state:
    st.session_state.replay_position = 0
if "replay_speed" not in st.session_state:
    st.session_state.replay_speed = 1.0
if "report_visible" not in st.session_state:
    st.session_state.report_visible = False
if "last_toast_ms" not in st.session_state:
    st.session_state.last_toast_ms = 0
if "scenario" not in st.session_state:
    st.session_state.scenario = "full"
if "type_explanations" not in st.session_state:
    st.session_state.type_explanations = {}
if "selected_alert_idx" not in st.session_state:
    st.session_state.selected_alert_idx = None
if "ai_explainer_on" not in st.session_state:
    st.session_state.ai_explainer_on = True
if "tour_step" not in st.session_state:
    st.session_state.tour_step = -1
if "_pps_peak" not in st.session_state:
    st.session_state._pps_peak = 0
if "last_alert_count" not in st.session_state:
    st.session_state.last_alert_count = 0
if "fresh_alert_until" not in st.session_state:
    st.session_state.fresh_alert_until = 0
if "_agent_loop" not in st.session_state:
    st.session_state._agent_loop = None
if "explainer_prewarm_started" not in st.session_state:
    st.session_state.explainer_prewarm_started = False

if not os.environ.get("GEMINI_API_KEY"):
    st.session_state.ai_explainer_on = False

def _get_event_loop():
    if st.session_state._agent_loop is None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        st.session_state._agent_loop = loop
    return st.session_state._agent_loop

def render_pixel_agent(agent_state: str, current_task: str) -> str:
    """Return HTML for the pixel agent. Each pixel = a 6px div."""
    pixel_size = 6
    rows_html = []
    for row_idx, row in enumerate(AGENT_PIXELS):
        cells = []
        for col_idx, ch in enumerate(row):
            if ch == ".":
                cells.append(
                    f"<div style='width:{pixel_size}px; "
                    f"height:{pixel_size}px;'></div>"
                )
            else:
                color = PIXEL_COLORS.get(ch, "#000000")
                cells.append(
                    f"<div class='pixel' "
                    f"data-px='{row_idx}-{col_idx}' "
                    f"style='width:{pixel_size}px; "
                    f"height:{pixel_size}px; "
                    f"background:{color};'></div>"
                )
        rows_html.append(
            f"<div style='display:flex;'>{''.join(cells)}</div>"
        )
    return f"""
        <div class='agent-bubble'>{current_task}</div>
        <div class='pixel-agent' data-state='{agent_state}'
             style='display:inline-block; image-rendering: pixelated;
                    padding:8px; background:#0d1117;
                    border-radius:8px;
                    border:1px solid #30363d;'>
          {''.join(rows_html)}
        </div>
    """

def _explain_type(alert_type: str) -> str:
    """Blocking call: explain an attack type. Two sentences max."""
    prompt = (
        f"Explain the network security attack '{alert_type}' in 2 "
        f"short sentences for a non-technical audience. Say what it "
        f"is and why it is dangerous."
    )
    async def _run():
        config = LocalAgentConfig(
            system_instructions=(
                "You are a network security analyst. Write a single "
                "tooltip. Two sentences maximum. No bullet points."
            )
        )
        async with Agent(config) as agent:
            resp = await agent.chat(prompt)
            return await resp.text()
    try:
        loop = _get_event_loop()
        return loop.run_until_complete(
            asyncio.wait_for(_run(), timeout=6.0)
        )
    except Exception as e:
        return f"(explainer unavailable: {type(e).__name__})"

ALERT_TYPES = [
    "DoS / FLOOD", "PORT SCAN", "SSH BRUTE FORCE", "ICMP FLOOD",
    "NULL SCAN", "XMAS SCAN", "MALICIOUS FILE", "KILL CHAIN",
]

def _prewarm_explanations():
    for t in ALERT_TYPES:
        try:
            if t not in st.session_state.type_explanations:
                st.session_state.type_explanations[t] = _explain_type(t)
        except Exception:
            pass   # never let prewarm kill the app

# Start prewarm once, only if API key present
if (st.session_state.ai_explainer_on
        and not st.session_state.explainer_prewarm_started):
    st.session_state.explainer_prewarm_started = True
    threading.Thread(target=_prewarm_explanations,
                     daemon=True, name="ai-prewarm").start()
if "selected_server" not in st.session_state:
    st.session_state.selected_server = "All servers"
if "audit_log" not in st.session_state:
    st.session_state.audit_log = []
    _audit("SYSTEM", "session_started", "buffer initialized")

flash = st.session_state.pop("rules_applied_flash", None)
if flash == "applied":
    st.toast("✅ Detection rules updated", icon="⚙️")
elif flash == "defaults":
    st.toast("↩️ Rules reset to defaults", icon="⚙️")

def start_simulator_once() -> None:
    """Spawn the simulator daemon thread at most once per live thread.

    Idempotent: no-op if the stored thread is still running.
    Survives Streamlit script reloads as long as session_state persists.
    """
    existing = st.session_state.get("sim_thread")
    if existing is not None and existing.is_alive():
        return
    t = threading.Thread(
        target=simulator.simulate_traffic,
        args=(st.session_state.packet_buffer,),
        kwargs={"scenario": st.session_state.scenario},
        daemon=True,
        name="packet-simulator",
    )
    t.start()
    st.session_state.sim_thread = t
    st.session_state.sim_started = True

def start_agent_once():
    """Spawn the agent daemon thread at most once per live thread."""
    existing = st.session_state.get("agent_thread")
    if existing is not None and existing.is_alive():
        return
    t = start_agent(
        st.session_state.packet_buffer,
        st.session_state.detector,
        poll_interval=4.0,
    )
    st.session_state.agent_thread = t

if st.sidebar.button("🔄 Reset & Re-run Simulation"):
    _audit("ANALYST", "session_reset", "buffer + alerts cleared")
    st.session_state.packet_buffer.clear()
    st.session_state.detector.reset()
    AGENT.reset()
    st.session_state.last_analyzed_idx = 0
    st.session_state.sim_started = False
    st.session_state.replay_mode = False
    st.session_state.selected_alert_idx = None
    st.session_state._pps_peak = 0
    for k in ("cfg_flood", "cfg_scan", "cfg_brute"):
        st.session_state.pop(k, None)
    st.rerun()

sim_alive = (st.session_state.get("sim_thread") is not None
             and st.session_state.sim_thread.is_alive())

if st.session_state.sim_started:
    st.sidebar.status("Simulator: running")
st.sidebar.markdown("---")

if st.session_state.tour_step == -1:
    if st.sidebar.button("🎬 Start Guided Tour",
                         use_container_width=True,
                         key="tour_start"):
        st.session_state.tour_step = 0
        st.rerun()
else:
    st.sidebar.markdown(
        "<div style='color:#f59e0b; font-size:12px; "
        "margin-bottom:6px;'>🎬 Tour active</div>",
        unsafe_allow_html=True,
    )
    st.sidebar.caption(
        f"Step {st.session_state.tour_step + 1} "
        f"of {len(TOUR_STEPS)}"
    )
    if st.sidebar.button("⏹️ End Tour",
                         use_container_width=True,
                         key="tour_end"):
        st.session_state.tour_step = -1
        st.rerun()

st.session_state.ai_explainer_on = st.sidebar.toggle(
    "🤖 AI Explainer",
    value=st.session_state.ai_explainer_on,
    key="ai_toggle",
    help="Show AI-generated explanations on each alert card.",
)
if not os.environ.get("GEMINI_API_KEY"):
    st.sidebar.caption("⚠️ Set GEMINI_API_KEY to enable.")

with st.sidebar.expander("🎬 Quick Demos", expanded=True):
    presets = [
        ("🌊 Flood", "flood_only"),
        ("🔍 Port Scan", "scan_only"),
        ("🔐 Brute Force", "brute_only"),
        ("📁 File Transfer", "files_only"),
        ("🎯 Full Demo", "full"),
    ]
    for label, scenario in presets:
        if st.button(label, use_container_width=True,
                     key=f"preset_{scenario}"):
            st.session_state.scenario = scenario
            st.session_state.packet_buffer.clear()
            st.session_state.detector = AnomalyDetector()
            st.session_state.last_analyzed_idx = 0
            AGENT.reset()
            st.session_state._pps_peak = 0
            st.session_state.selected_alert_idx = None
            st.session_state.sim_started = False
            st.session_state.sim_thread = None
            st.rerun()

SERVER_OPTIONS = ["All servers", "10.0.0.5", "10.0.0.6", "10.0.0.7"]
st.session_state.selected_server = st.sidebar.selectbox(
    "🎯 Target Server", SERVER_OPTIONS,
    index=SERVER_OPTIONS.index(st.session_state.selected_server),
    key="server_selector",
)

with st.sidebar.expander("⚙️ Detection Rules", expanded=False):
    flood_threshold = st.slider(
        "Flood Threshold", 5, 50, 15, key="cfg_flood")
    scan_unique_ports = st.slider(
        "Port Scan Unique Ports", 5, 20, 10, key="cfg_scan")
    brute_syn_count = st.slider(
        "Brute Force SYN Count", 3, 20, 8, key="cfg_brute")

    st.caption("Lower = faster detection (and more false "
               "positives). Raise flood above 25 and the demo "
               "attack slips through.")

    btn_cols = st.columns(2)
    with btn_cols[0]:
        apply_clicked = st.button("Apply", use_container_width=True,
                                  key="cfg_apply")
    with btn_cols[1]:
        defaults_clicked = st.button("Defaults",
                                     use_container_width=True,
                                     key="cfg_defaults")

def _rebuild_detector(flood, scan, brute):
    """Rebuild the detector with new thresholds, preserving alerts."""
    prior_alerts = list(st.session_state.detector.alerts)
    prior_risk = st.session_state.detector.risk_score
    st.session_state.detector = AnomalyDetector(rules=[
        IcmpFloodRule(),
        NullScanRule(),
        XmasScanRule(),
        FloodRule(threshold=flood),
        PortScanRule(unique_ports=scan),
        BruteForceRule(threshold=brute),
        MaliciousFileRule(),
    ])
    st.session_state.detector.alerts = prior_alerts
    st.session_state.detector.risk_score = prior_risk
    # Reset last_analyzed_idx so the ENTIRE existing buffer gets
    # re-analyzed against the new thresholds.
    st.session_state.last_analyzed_idx = 0

if apply_clicked:
    _audit("ANALYST", "rules_updated",
           f"flood={flood_threshold}, scan={scan_unique_ports}, "
           f"brute={brute_syn_count}")
    _rebuild_detector(flood_threshold, scan_unique_ports, brute_syn_count)
    st.session_state.rules_applied_flash = "applied"
    st.rerun()

if defaults_clicked:
    _audit("ANALYST", "rules_reset", "defaults")
    _rebuild_detector(15, 10, 8)
    st.session_state.rules_applied_flash = "defaults"
    st.rerun()

st.sidebar.caption("Hackathon demo · Phase 4.1 skeleton")
if AGENT.snapshot_blocked():
    st.sidebar.caption("🚫 Blocked: " + ", ".join(sorted(AGENT.snapshot_blocked())))

with st.sidebar.expander("🎬 Replay Mode", expanded=False):
    if not st.session_state.replay_mode:
        if st.button("▶️ Enter Replay Mode", use_container_width=True):
            st.session_state.replay_snapshot = list(
                st.session_state.packet_buffer.snapshot()
            )
            st.session_state.replay_position = len(
                st.session_state.replay_snapshot
            )
            st.session_state.replay_mode = True
            st.rerun()
    else:
        max_pos = len(st.session_state.replay_snapshot)
        st.session_state.replay_position = st.slider(
            "Position", 0, max_pos,
            st.session_state.replay_position,
            key="replay_slider",
        )
        st.session_state.replay_speed = st.select_slider(
            "Speed", options=[0.5, 1.0, 2.0, 4.0],
            value=st.session_state.replay_speed,
            key="replay_speed_slider",
        )
        if st.button("⏹️ Exit Replay Mode", use_container_width=True):
            st.session_state.replay_mode = False
            st.session_state.replay_snapshot = []
            st.session_state.replay_position = 0
            st.rerun()

st.sidebar.markdown("---")

with st.sidebar.expander("📜 Audit Log", expanded=False):
    if st.button("🗑️ Clear Audit Log", use_container_width=True):
        st.session_state.audit_log = []
        st.rerun()
    if not st.session_state.audit_log:
        st.caption("No activity yet.")
    else:
        for entry in reversed(st.session_state.audit_log[-20:]):
            color = {"SYSTEM": "#8b949e",
                     "DETECTOR": "#ef4444",
                     "ANALYST": "#3b82f6"}.get(entry["actor"],
                                                "#8b949e")
            st.markdown(
                f"<div style='font-family: ui-monospace, monospace; "
                f"font-size: 11px; margin: 2px 0;'>"
                f"<span style='color:#6e7681;'>"
                f"{entry['time']}</span> "
                f"<span style='color:{color}; font-weight:600;'>"
                f"[{entry['actor']}]</span> "
                f"<span style='color:#c9d1d9;'>{entry['action']}</span>"
                f"<br><span style='color:#8b949e; "
                f"padding-left:60px;'>{entry['detail']}</span>"
                f"</div>",
                unsafe_allow_html=True,
            )
        st.caption(f"Showing latest 20 of "
                   f"{len(st.session_state.audit_log)} entries.")

with st.sidebar.expander("🌍 Attacker Geography", expanded=False):
    if not st.session_state.detector.alerts:
        st.caption("No attackers yet.")
    else:
        seen = {}
        for a in st.session_state.detector.alerts:
            if a["type"] == "BLOCKED IP":
                continue
            seen[a["ip"]] = seen.get(a["ip"], 0) + 1
        for ip, count in sorted(seen.items(), key=lambda kv: -kv[1]):
            city, cc, lat, lon = GEO_MAP.get(ip, GEO_DEFAULT)
            st.markdown(f"**{ip}** — {city}, {cc} · {count} alerts")

    if os.environ.get("SOC_WEBHOOK_URL"):
        st.sidebar.caption("🔔 Webhook notifications enabled")
    else:
        st.sidebar.caption("🔔 Webhook not configured")

alerts = st.session_state.detector.alerts
num_alerts = len(alerts)

if num_alerts == 0:
    st.sidebar.caption("📥 No alerts to export yet")
else:
    # Stable schema — guarantees identical columns for every export,
    # prevents NaN cells for alerts that lack filename/file_hash
    COLUMNS = ["time", "type", "severity", "ip", "detail",
               "filename", "file_hash"]
    df_export = pd.DataFrame(alerts).reindex(
        columns=COLUMNS, fill_value=""
    )
    csv_data = df_export.to_csv(index=False)
    json_data = json.dumps(alerts, indent=2, default=str)

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")

    st.sidebar.download_button(
        label="📥 Export Alerts (CSV)",
        data=csv_data,
        file_name=f"alerts_{ts}.csv",
        mime="text/csv",
        use_container_width=True,
        key="export_csv",
    )
    st.sidebar.download_button(
        label="📥 Export Alerts (JSON)",
        data=json_data,
        file_name=f"alerts_{ts}.json",
        mime="application/json",
        use_container_width=True,
        key="export_json",
    )

if st.sidebar.button("📄 Generate Report", use_container_width=True, key="gen_report"):
    st.session_state.report_visible = True

if not st.session_state.replay_mode:
    start_simulator_once()
    if _AGENT_AVAILABLE:
        start_agent_once()

st.markdown("## 🛡️ Network Packet Analyzer — Live Threat Monitor")
if st.session_state.replay_mode:
    visible_packets = st.session_state.replay_snapshot[
        :st.session_state.replay_position
    ]
    # Rebuild detector from scratch against the visible slice
    replay_detector = AnomalyDetector(rules=[
        IcmpFloodRule(),
        NullScanRule(),
        XmasScanRule(),
        FloodRule(threshold=st.session_state.get('cfg_flood', 15)),
        PortScanRule(unique_ports=st.session_state.get('cfg_scan', 10)),
        BruteForceRule(threshold=st.session_state.get('cfg_brute', 8)),
        MaliciousFileRule(),
    ])
    for pkt in visible_packets:
        if pkt["source"] in AGENT.snapshot_blocked():
            continue
        replay_detector.analyze(pkt)
        
    st.markdown(
        f"<div style='background:#f59e0b; color:#000; "
        f"padding:6px 12px; border-radius:6px; font-weight:700; "
        f"text-align:center;'>"
        f"🎬 REPLAY MODE — {st.session_state.replay_position}/"
        f"{len(st.session_state.replay_snapshot)} packets · "
        f"{st.session_state.replay_speed}x speed</div>",
        unsafe_allow_html=True,
    )
else:
    replay_detector = st.session_state.detector
    visible_packets = st.session_state.packet_buffer.snapshot()
    
    new_packets = visible_packets[st.session_state.last_analyzed_idx:]
    for pkt in new_packets:
        if pkt["source"] in AGENT.snapshot_blocked():
            continue
        prev_len = len(replay_detector.alerts)
        replay_detector.analyze(pkt)
        if len(replay_detector.alerts) > prev_len:
            new_alert = replay_detector.alerts[-1]
            _audit("DETECTOR", new_alert["type"], f"{new_alert['ip']} — {new_alert['detail']}")
            if new_alert.get("severity") == "HIGH":
                now_ms = int(time.time() * 1000)
                if now_ms - st.session_state.last_toast_ms > 3000:
                    st.toast(
                        f"⚠️ {new_alert['type']} — {new_alert['ip']}",
                        icon="🚨",
                    )
                    st.session_state.last_toast_ms = now_ms
            st.session_state.last_alert_count += 1
            st.session_state.fresh_alert_until = int(time.time() * 1000) + 3000
    st.session_state.last_analyzed_idx = len(visible_packets)

# Executive Metrics Hero Strip
if st.session_state.get("replay_mode", False):
    _hero_packets = st.session_state.replay_snapshot[
        :st.session_state.replay_position
    ]
    _hero_alerts = replay_detector.alerts
    _hero_risk = replay_detector.risk_score
else:
    _hero_packets = st.session_state.packet_buffer.snapshot()
    _hero_alerts = st.session_state.detector.alerts
    _hero_risk = st.session_state.detector.risk_score

from detector import analyze_pps
_pps_now = (analyze_pps(_hero_packets[-10:])
            if len(_hero_packets) >= 2 else 0.0)
st.session_state._pps_peak = max(
    st.session_state._pps_peak, _pps_now
)

n_packets   = len(_hero_packets)
n_alerts    = len(_hero_alerts)
n_attackers = len({a["ip"] for a in _hero_alerts
                   if a["type"] != "BLOCKED IP"})
n_blocked   = len(AGENT.snapshot_blocked())

if _hero_risk < 20:
    risk_color = "#22c55e"
elif _hero_risk < 50:
    risk_color = "#f59e0b"
elif _hero_risk < 80:
    risk_color = "#ef4444"
else:
    risk_color = "#dc2626"

st.markdown(f"""
    <div class="hero-strip">
      <div class="hero-cell">
        <div class="hero-label">Packets</div>
        <div class="hero-value">{n_packets}</div>
      </div>
      <div class="hero-cell">
        <div class="hero-label">Alerts</div>
        <div class="hero-value">{n_alerts}</div>
      </div>
      <div class="hero-cell">
        <div class="hero-label">Attackers</div>
        <div class="hero-value">{n_attackers}</div>
      </div>
      <div class="hero-cell">
        <div class="hero-label">Risk Score</div>
        <div class="hero-value" style="color:{risk_color};">
          {round(_hero_risk)}
        </div>
      </div>
      <div class="hero-cell">
        <div class="hero-label">Peak PPS</div>
        <div class="hero-value">{st.session_state._pps_peak:.0f}</div>
      </div>
      <div class="hero-cell">
        <div class="hero-label">Blocked</div>
        <div class="hero-value">{n_blocked}</div>
      </div>
    </div>
""", unsafe_allow_html=True)

if st.session_state.tour_step >= 0:
    step = TOUR_STEPS[st.session_state.tour_step]
    st.markdown(f"""
        <div class="tour-overlay">
          <div class="tour-progress">
            Step {st.session_state.tour_step + 1} / {len(TOUR_STEPS)}
          </div>
          <div class="tour-title">{step['title']}</div>
          <div class="tour-body">{step['body']}</div>
        </div>
    """, unsafe_allow_html=True)

    tcol0, tcol1, tcol2, tcol3, tcol4 = st.columns([2, 1, 1, 1, 2])
    with tcol1:
        if st.button("◀ Back", use_container_width=True,
                     key="tour_back",
                     disabled=(st.session_state.tour_step == 0)):
            st.session_state.tour_step -= 1
            st.rerun()
    with tcol2:
        is_last = (st.session_state.tour_step == len(TOUR_STEPS) - 1)
        label = "Finish ✓" if is_last else "Next ▶"
        if st.button(label, use_container_width=True, key="tour_next"):
            if is_last:
                st.session_state.tour_step = -1
            else:
                st.session_state.tour_step += 1
            st.rerun()
    with tcol3:
        if st.button("Skip", use_container_width=True, key="tour_skip"):
            st.session_state.tour_step = -1
            st.rerun()
            
    if step.get("target"):
        st.caption(f"↳ Look at: **{step['target']}**")


st_version = st.__version__.split(".")
if int(st_version[0]) == 1 and int(st_version[1]) < 29:
    st.warning("Upgrade Streamlit: pip install -U streamlit>=1.29")
    border_kwargs = {}
else:
    border_kwargs = {"border": True}

if st.session_state.report_visible:
    with st.container(**border_kwargs):
        st.markdown("## 📄 Session Summary Report")

        alerts = st.session_state.detector.alerts
        packets = st.session_state.packet_buffer.snapshot()
        blocked = AGENT.snapshot_blocked()

        # Compute summary stats
        by_type = {}
        for a in alerts:
            by_type[a["type"]] = by_type.get(a["type"], 0) + 1
        top_attacker = (max(
            {a["ip"]: sum(1 for x in alerts if x["ip"] == a["ip"])
             for a in alerts if a["type"] != "BLOCKED IP"}.items(),
            key=lambda kv: kv[1], default=("—", 0),
        ))

        duration = packets[-1]["timestamp"] if packets else "—"
        started = packets[0]["timestamp"] if packets else "—"

        cols = st.columns(4)
        cols[0].metric("Packets Analyzed", len(packets))
        cols[1].metric("Total Alerts", len(alerts))
        cols[2].metric("Peak Risk",
                       f"{min(100, len(alerts) * 20):.0f}")
        cols[3].metric("Blocked IPs", len(blocked))

        st.markdown("### Alerts by Type")
        if by_type:
            for t, n in sorted(by_type.items(),
                               key=lambda kv: -kv[1]):
                st.markdown(f"- **{t}**: {n}")
        else:
            st.caption("No alerts this session.")

        st.markdown("### Top Attacker")
        st.markdown(f"**{top_attacker[0]}** — {top_attacker[1]} alerts")

        st.markdown("### Session Window")
        st.markdown(f"First packet: `{started}`  ·  Last: `{duration}`")

        st.markdown("---")
        if st.button("🗑️ Dismiss Report", key="dismiss_report"):
            st.session_state.report_visible = False
            st.rerun()


with st.expander("What am I looking at?"):
    st.markdown("""
    - **Pane 1**: Every packet arriving at the server, in real time.
    - **Pane 2**: Visual patterns of normal traffic — protocol mix and PPS.
    - **Pane 3**: Live intrusion detection. The risk gauge climbs when a single source IP floods the server. Alerts list the offending IP.
    """)

st.markdown("---")
cols = st.columns(len(SERVER_OPTIONS))
for i, srv in enumerate(SERVER_OPTIONS):
    pkts = _filter_by_server(visible_packets, srv)
    cols[i].metric(srv, len(pkts), "packets")
st.markdown("---")

col1, col2, col3 = st.columns([2, 2, 1.5], gap="medium")

with col1:
    with st.container(**border_kwargs):
        st.markdown('<div class="pane-badge blue">Incoming Packets</div>',
                    unsafe_allow_html=True)

        packets = _filter_by_server(visible_packets, st.session_state.selected_server)

        if not packets:
            st.info("Waiting for packets…")
        else:
            COLS = ["timestamp", "source", "protocol", "size", "flags"]
            df = pd.DataFrame(packets[-30:], columns=COLS)
            df.columns = ["TIMESTAMP", "SOURCE", "PROTO", "SIZE", "FLAGS"]
            
            if len(packets) > 30:
                st.caption(f"... {len(packets) - 30} more normal packets ...")

            def style_rows(row):
                src = str(row["SOURCE"])
                proto = str(row["PROTO"])
                bg = "background-color: #3d1518" if src.startswith("192.168.1.9") else ""
                colors = {"TCP": "#3b82f6", "UDP": "#3fb950", "ICMP": "#f0883e"}
                c = colors.get(proto, "inherit")
                
                styles = []
                for col in row.index:
                    cell_style = bg
                    if src in AGENT.snapshot_blocked():
                        cell_style += "; opacity: 0.4; color: #6e7681"
                    elif col == "PROTO":
                        cell_style += f"; color: {c}"
                    else:
                        cell_style += "; color: #c9d1d9"
                    styles.append(cell_style)
                return styles

            styled = df.style.apply(style_rows, axis=1)
            st.dataframe(styled, use_container_width=True, height=320)

            st.markdown("---")

            agent_state_dict = AGENT.snapshot_state()
            agent_state = agent_state_dict["agent_state"]

            st.markdown(
                "<div style='color:#8b949e; font-size:11px; "
                "letter-spacing:1.5px; text-transform:uppercase; "
                "margin-bottom:8px;'>"
                "🤖 AGENT STEVE — AUTONOMOUS SOC ANALYST"
                "</div>",
                unsafe_allow_html=True,
            )

            steve_col, status_col = st.columns([1, 2])

            with steve_col:
                st.markdown(render_pixel_agent(agent_state, agent_state_dict['current_task']),
                            unsafe_allow_html=True)

            with status_col:
                state_color = {
                    "MONITORING":    "#22c55e",
                    "INVESTIGATING": "#f59e0b",
                    "BLOCKING":      "#ef4444",
                    "ERROR":         "#dc2626",
                    "IDLE":          "#8b949e",
                }.get(agent_state, "#8b949e")

                st.markdown(f"""
                    <div style='padding-top:8px;'>
                      <div style='display:flex; align-items:center;
                                  gap:8px; margin-bottom:6px;'>
                        <div style='width:10px; height:10px;
                                    border-radius:50%;
                                    background:{state_color};'></div>
                        <span style='color:{state_color}; font-weight:700;
                                     letter-spacing:1px; font-size:12px;'>
                          {agent_state}
                        </span>
                      </div>
                      <div style='color:#c9d1d9; font-size:12px;
                                  line-height:1.4; margin-bottom:8px;'>
                        {agent_state_dict['current_task']}
                      </div>
                      <div style='color:#8b949e; font-size:11px;
                                  font-family:ui-monospace;'>
                        Verifications: {agent_state_dict['verifications']} ·
                        Blocks: {agent_state_dict['actions_taken']}
                      </div>
                    </div>
                """, unsafe_allow_html=True)
with col2:
    with st.container(**border_kwargs):
        st.markdown('<div class="pane-badge green">Server Request Analysis</div>',
                    unsafe_allow_html=True)
        if not packets:
            st.info("Charts render once traffic arrives.")
        else:
            # Chart 1: Protocol Distribution
            proto_counts = df["PROTO"].value_counts().reset_index()
            proto_counts.columns = ["Protocol", "Count"]
            fig1 = px.bar(
                proto_counts, x="Protocol", y="Count", color="Protocol",
                title="Protocol Distribution", height=250,
                color_discrete_map={"TCP": "#3b82f6", "UDP": "#3fb950", "ICMP": "#f0883e"},
                text="Count"
            )
            fig1.update_layout(showlegend=False)
            st.plotly_chart(fig1, use_container_width=True)

            # Chart 2: Packets Per Second
            # Truncate timestamp to HH:MM:SS
            df["second"] = df["TIMESTAMP"].str[:8]
            pps = df.groupby("second").size().reset_index(name="Packets")
            fig2 = px.line(
                pps, x="second", y="Packets", 
                title="Packets Per Second (PPS)", height=250
            )
            fig2.update_traces(line_color="#58a6ff")
            
            max_val = pps["Packets"].max() if not pps.empty else 0
            fig2.add_hline(
                y=30, line_dash="dash", line_color="red", 
                annotation_text="Threshold"
            )
            if max_val > 0:
                max_row = pps.loc[pps["Packets"].idxmax()]
                fig2.add_annotation(x=max_row["second"], y=max_row["Packets"],
                                    text=f"peak {max_val}", showarrow=True)
            st.plotly_chart(fig2, use_container_width=True)

            st.markdown("**Throughput (KB/s by protocol)**")
            
            # Resolve visible packets exactly matching replay mode status
            vp = (
                st.session_state.replay_snapshot[:st.session_state.replay_position]
                if st.session_state.get("replay_mode", False)
                else st.session_state.packet_buffer.snapshot()
            )
            
            st.plotly_chart(
                build_throughput_chart(vp),
                use_container_width=True,
                config={"displayModeBar": False},
                key="throughput_chart",
            )
with col3:
    with st.container(**border_kwargs):
        st.markdown('<div class="pane-badge red">Threat Detection</div>',
                    unsafe_allow_html=True)
        st.caption("Alerts are shown for all servers.")
        
        idx = st.session_state.selected_alert_idx
        alerts_list = replay_detector.alerts
        if idx is not None and not (0 <= idx < len(alerts_list)):
            st.session_state.selected_alert_idx = None
            idx = None

        if idx is not None:
            alert = alerts_list[idx]
            RULE_INFO = {
                "DoS / FLOOD":     ("FloodRule",      "≥15 packets from one source in 3s"),
                "PORT SCAN":       ("PortScanRule",   "≥10 unique dst ports from one source in 5s"),
                "SSH BRUTE FORCE": ("BruteForceRule", "≥8 TCP SYN to port 22 from one source in 5s"),
                "ICMP FLOOD":      ("IcmpFloodRule",  "≥15 ICMP packets from one source in 3s"),
                "NULL SCAN":       ("NullScanRule",   "≥3 TCP packets with zero flags in 5s"),
                "XMAS SCAN":       ("XmasScanRule",   "≥3 TCP packets with FIN+PSH+URG in 5s"),
                "MALICIOUS FILE":  ("MaliciousFileRule", "dangerous extension, hash, or filename pattern"),
                "KILL CHAIN":      ("KillChainRule",  "≥2 different rule types from same IP within 60s"),
                "BLOCKED IP":      ("(analyst action)", "manually blocked by user"),
            }
            rule, criteria = RULE_INFO.get(alert["type"], ("—", "—"))

            st.markdown(f"""
                <div class="explain-panel">
                  <div class="explain-title">🔍 Why did this fire?</div>
                  <div style="color:#c9d1d9; line-height:1.6;">
                    <b>Alert:</b> {alert['type']} — <code>{alert['ip']}</code><br>
                    <b>Time:</b> {alert['time']}<br>
                    <b>Detail:</b> {alert['detail']}<br>
                    <b>Rule:</b> <code>{rule}</code><br>
                    <b>Criteria:</b> {criteria}<br>
                    <b>Severity:</b> {alert.get('severity', '—')}
                  </div>
                </div>
            """, unsafe_allow_html=True)

            if st.button("Close", key="explain_panel_close"):
                st.session_state.selected_alert_idx = None
                st.rerun()

        # 0. Top Attackers Chart
        st.markdown('<div style="color:#8b949e; font-size:14px; font-weight:600; margin-bottom:8px;">🎯 Top Attackers</div>', unsafe_allow_html=True)
        if not replay_detector.alerts:
            st.caption("No attackers yet")
        else:
            attacker_counts = Counter(a["ip"] for a in replay_detector.alerts)
            top_attackers = attacker_counts.most_common(5)
            top_attackers.reverse()
            
            ips = [item[0] for item in top_attackers]
            counts = [item[1] for item in top_attackers]
            
            atk_fig = go.Figure(go.Bar(
                x=counts,
                y=ips,
                orientation='h',
                marker=dict(color="#ef4444")
            ))
            atk_fig.update_layout(
                height=140,
                margin=dict(l=0, r=0, t=0, b=0),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                showlegend=False,
                xaxis=dict(visible=False, showgrid=False, zeroline=False),
                yaxis=dict(visible=True, showgrid=False, zeroline=False, tickfont=dict(color="#c9d1d9", size=11))
            )
            st.plotly_chart(atk_fig, use_container_width=True, config={"displayModeBar": False})
        


        # 1. Risk Score Gauge
        risk = replay_detector.risk_score

        # Severity label above the gauge
        if risk < 20:
            label, color = "LOW RISK", "#22c55e"
        elif risk < 50:
            label, color = "MEDIUM RISK", "#f59e0b"
        elif risk < 80:
            label, color = "HIGH RISK", "#ef4444"
        else:
            label, color = "CRITICAL", "#dc2626"

        st.markdown(
            f"<div style='text-align:center; margin-bottom:4px;'>"
            f"<span style='color:{color}; font-weight:700; font-size:14px; "
            f"letter-spacing:1.5px;'>{label}</span></div>",
            unsafe_allow_html=True,
        )

        # Semicircle gauge
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk,
            number={"font": {"size": 44, "color": "#fafafa",
                             "family": "ui-monospace, monospace"},
                    "suffix": ""},
            gauge={
                "shape": "angular",
                "axis": {
                    "range": [0, 100],
                    "tickwidth": 0,
                    "tickcolor": "#161b22",
                    "tickvals": [0, 25, 50, 75, 100],
                    "tickfont": {"color": "#8b949e", "size": 10},
                },
                "bar": {"color": color, "thickness": 0.30},
                "bgcolor": "#30363d",
                "borderwidth": 0,
                "steps": [],
            },
            domain={"x": [0, 1], "y": [0, 1]},
        ))
        fig.update_layout(
            height=220,
            margin={"t": 20, "b": 0, "l": 20, "r": 20},
            paper_bgcolor="#161b22",
            plot_bgcolor="#161b22",
            font={"color": "#8b949e"},
        )
        st.plotly_chart(
            fig,
            use_container_width=True,
            config={"displayModeBar": False},
            key="risk_gauge",
        )
        
        # 2. Live Alert Feed
        n_alerts = len(replay_detector.alerts)
        st.markdown(f"#### Active Alerts · {n_alerts}")
        with st.container(height=340, border=False):
            alerts = replay_detector.alerts
            indexed = list(enumerate(alerts))
            if not indexed:
                st.success("✅ No intrusions detected")
            else:
                TYPE_TO_CLASS = {
                    "DoS / FLOOD":       "alert-flood",
                    "PORT SCAN":         "alert-scan",
                    "SSH BRUTE FORCE":   "alert-brute",
                    "ICMP FLOOD":        "alert-icmp",
                    "NULL SCAN":         "alert-null",
                    "XMAS SCAN":         "alert-xmas",
                    "MALICIOUS FILE":    "alert-malware",
                    "BLOCKED IP":        "alert-blocked",
                }
                for original_idx, a in reversed(indexed):
                    cls = TYPE_TO_CLASS.get(a["type"], "alert-null")
                    
                    now_ms = int(time.time() * 1000)
                    # Only the newest alert pulses, and only for 3 seconds
                    is_fresh = (
                        original_idx == len(alerts) - 1
                        and now_ms < st.session_state.fresh_alert_until
                    )
                    pulse_class = " alert-pulse" if is_fresh else ""
                    
                    hash_line = (f'<div class="hash">SHA256: '
                                 f'{a.get("file_hash", "")[:16]}…</div>'
                                 if a["type"] == "MALICIOUS FILE" else "")
                    card_col, info_col, block_col = st.columns([4, 1, 1])
                    with card_col:
                        ai_note = ""
                        if st.session_state.ai_explainer_on and a["type"] != "BLOCKED IP":
                            expl = st.session_state.type_explanations.get(a["type"])
                            if expl and not expl.startswith("(explainer unavailable"):
                                ai_note = f'<div class="ai-note">🤖 {expl}</div>'
                        
                        st.markdown(
                            f'<div class="alert-card {cls}{pulse_class}">'
                            f'  <div class="title">{a["type"]}</div>'
                            f'  <span class="ip">{a["ip"]}</span>'
                            f'  <div class="detail">{a["detail"]}</div>'
                            f'  {hash_line}'
                            f'  {ai_note}'
                            f'</div>',
                            unsafe_allow_html=True)
                    with info_col:
                        if st.button("ℹ️", key=f"why_{original_idx}", help="Why did this alert fire?", use_container_width=True):
                            st.session_state.selected_alert_idx = original_idx
                            st.rerun()
                    with block_col:
                        if a["type"] != "BLOCKED IP" and a["ip"] not in AGENT.snapshot_blocked():
                            key = f"block_{original_idx}_{a['ip']}_{a.get('time', '').replace(':', '')}"
                            if st.button("🚫", key=key, help=f"Block {a['ip']}", use_container_width=True):
                                AGENT.block_ip(a["ip"], "manually blocked by analyst")
                                _audit("ANALYST", "blocked_ip", a["ip"])
                                replay_detector.alerts.append({
                                    "time": datetime.now().strftime("%H:%M:%S"),
                                    "type": "BLOCKED IP",
                                    "ip": a["ip"],
                                    "detail": "manually blocked by analyst",
                                    "severity": "INFO",
                                })
                                # NOTE: no +20 risk — blocking is a response action,
                                # not a new detection.
                                st.rerun()

        # Agent Decision Log

        decisions = AGENT.snapshot_log()
        if decisions:
            with st.expander(f"🧠 Agent Decision Log · {len(decisions)}",
                             expanded=False):
                for entry in reversed(decisions[-15:]):
                    color = {"BLOCKED": "#ef4444",
                             "VERIFIED": "#3b82f6",
                             "IGNORED": "#8b949e"}.get(entry["event"], "#8b949e")
                    st.markdown(
                        f"<div style='font-family: ui-monospace; "
                        f"font-size: 12px; padding: 4px 0;'>"
                        f"<span style='color:#6e7681;'>{entry['time']}</span> "
                        f"<span style='color:{color}; font-weight:600;'>"
                        f"[{entry['event']}]</span> "
                        f"<span style='color:#c9d1d9;'>{entry['ip']}</span> "
                        f"<span style='color:#8b949e;'>— {entry['reason']}</span>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )
        else:
            st.caption("🧠 Agent has not made any decisions yet.")

st.caption("Live packet stream hitting the server — updated every 1.5s")
st.markdown("### 📡 Live Packet Flow → Server")
with st.container(**border_kwargs):
    flow_col_left, flow_col_right = st.columns([4, 1])
    with flow_col_left:
        snapshot = _filter_by_server(visible_packets, st.session_state.selected_server)
        flow_fig = build_flow_chart(snapshot)
        st.plotly_chart(flow_fig, use_container_width=True, key="flow_chart")
    with flow_col_right:
        pps_value = _recent_pps(snapshot) or 0.0
        st.metric("PPS", f"{safe_float(pps_value):.0f}")
        sources_value = len({p['source'] for p in snapshot[-30:]}) if snapshot else 0
        st.metric("Active Sources", sources_value)

alerts_source = (
    replay_detector.alerts
    if st.session_state.get("replay_mode", False)
    else st.session_state.detector.alerts
)

if alerts_source:
    st.markdown("### 🎯 Per-IP Threat Scorecard")
    with st.container(border=True):
        df = _threat_scorecard(alerts_source)
        if not df.empty:
            def _color_score(val):
                if val >= 70:
                    return "background-color: #4a1518; color: #fca5a5; font-weight: 700;"
                if val >= 40:
                    return "background-color: #3d2f0f; color: #fbbf24; font-weight: 700;"
                return "background-color: #14331a; color: #6ee7a0; font-weight: 700;"

            try:
                styled = df.style.map(_color_score, subset=["Threat Score"])
            except AttributeError:
                styled = df.style.applymap(_color_score, subset=["Threat Score"])
            
            st.dataframe(
                styled,
                use_container_width=True,
                hide_index=True,
                height=min(220, 40 + len(df) * 36),
            )

def build_heatmap(alerts: list[dict]) -> go.Figure:
    """GitHub-style grid: one cell per second, colored by alert count."""
    if not alerts:
        fig = go.Figure()
        fig.add_annotation(text="No data yet", showarrow=False,
                           font={"color": "#8b949e"})
        fig.update_layout(height=80, paper_bgcolor="#161b22",
                          plot_bgcolor="#161b22",
                          xaxis={"visible": False},
                          yaxis={"visible": False})
        return fig

    from collections import Counter
    sec_counts = Counter(a["time"][:8] for a in alerts
                         if a.get("time"))
    if not sec_counts:
        return build_heatmap([])

    # Build a single-row heatmap across all seconds
    all_times = sorted(sec_counts.keys())
    # Parse into offsets
    from datetime import datetime
    t0 = datetime.strptime(all_times[0], "%H:%M:%S")
    xs, ys, counts = [], [], []
    for t in all_times:
        try:
            dt = datetime.strptime(t, "%H:%M:%S")
            offset = int((dt - t0).total_seconds())
        except ValueError:
            continue
        xs.append(offset)
        ys.append("alerts")
        counts.append(sec_counts[t])

    fig = go.Figure(go.Heatmap(
        x=xs, y=ys, z=[counts],
        colorscale=[
            [0.0,  "#161b22"],
            [0.3,  "#1e3a8a"],
            [0.6,  "#7c2d12"],
            [1.0,  "#dc2626"],
        ],
        showscale=False,
        hovertemplate="+%{x}s: %{z} alerts<extra></extra>",
        xgap=2,
    ))
    fig.update_layout(
        height=100,
        margin={"t": 20, "b": 30, "l": 60, "r": 20},
        paper_bgcolor="#161b22",
        plot_bgcolor="#161b22",
        xaxis={"title": "Seconds since session start",
               "gridcolor": "#30363d"},
        yaxis={"showticklabels": False},
    )
    return fig

if alerts_source:
    st.markdown("### 🔥 Alert Density Heatmap")
    with st.container(border=True):
        st.plotly_chart(
            build_heatmap(alerts_source),
            use_container_width=True,
            config={"displayModeBar": False},
            key="heatmap_chart",
        )

st.markdown("### 🕐 Alert Timeline")
with st.container(**border_kwargs):
    st.plotly_chart(
        build_timeline(replay_detector.alerts),
        use_container_width=True,
        config={"displayModeBar": False},
        key="alert_timeline",
    )

with st.expander("🌍 Attacker Geography", expanded=False):
    st.plotly_chart(build_geo_map(replay_detector.alerts),
                    use_container_width=True,
                    config={"displayModeBar": False},
                    key="geo_map")

n_types = len({a["type"] for a in replay_detector.alerts})
files_blocked = sum(1 for a in replay_detector.alerts if a["type"] == "MALICIOUS FILE")
st.markdown(f"""
<div class="footer-bar">
    Sidebar: 🔄 Reset &amp; Re-run  ·  Buffer: <b>{len(visible_packets)} pkts</b>
    ·  Alerts: <b>{len(replay_detector.alerts)} ({n_types}/7 types)</b>
    ·  Files blocked: <b>{files_blocked}</b>
    ·  Blocked IPs: <b>{len(AGENT.snapshot_blocked())}</b>
    ·  Sim: <b>{'running' if sim_alive else 'stopped'}</b>
</div>
""", unsafe_allow_html=True)

if st.session_state.replay_mode:
    step = max(1, int(st.session_state.replay_speed))
    st.session_state.replay_position = min(
        len(st.session_state.replay_snapshot),
        st.session_state.replay_position + step,
    )
    time.sleep(0.5)
else:
    if st.session_state.tour_step == -1:
        time.sleep(1.5)
        st.rerun()

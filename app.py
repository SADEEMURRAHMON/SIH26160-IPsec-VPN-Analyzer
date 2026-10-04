"""IPsec VPN Analyzer - SIH26160 - Team SYNTRIX. Run: streamlit run app.py"""
import html as html_lib, json, os, tempfile
import streamlit as st
import pandas as pd
from src.pcap_parser import parse_capture, MAX_BYTES
from src.session_loader import sessions_from_capture, load_json_sessions
from src.feature_engineering import add_features
from src.anomaly_detector import detect
from src.risk_engine import assess
from dashboard import overview, packet_analysis, risk_analysis, timeline

ROOT = os.path.dirname(os.path.abspath(__file__))
st.set_page_config(page_title="IPsec VPN Analyzer", page_icon="🔐", layout="wide")
st.markdown("<style>.stApp{background:#0b1220;color:#e6edf3}h1,h2,h3{color:#7fd1ff}"
            "[data-testid=stMetric]{background:#111a2e;border:1px solid #223;padding:10px;border-radius:8px}</style>", unsafe_allow_html=True)
st.title("🔐 IPsec VPN Analyzer")
st.subheader("AI-Assisted Security Analysis of IPsec VPN Traffic")
st.caption("SIH26160 · NTRO · Team SYNTRIX")
st.error("SYNTHETIC / DEFENSIVE PROTOTYPE - demo data is simulated. Findings are indicators that require validation; "
         "the tool does not decrypt VPN traffic, recover keys or identify hidden users.")

SRC = ["Demo capture (sample/demo_all.pcap)", "Demo session JSON (sample/sample_sessions.json)", "Upload PCAP / pcapng", "Upload session JSON"]
mode = st.sidebar.radio("Input", SRC)
cap_mb = st.sidebar.number_input("Upload size limit (MB)", 1, 200, MAX_BYTES // 2**20)
up = st.sidebar.file_uploader("File", type=["pcap", "pcapng", "cap"] if mode == SRC[2] else ["json"]) if mode in SRC[2:] else None


@st.cache_data(show_spinner="Analysing capture...", max_entries=4)
def analyse_capture(data, cap_mb):
    """Parse + score a capture once; Streamlit reruns (tab clicks, selectboxes) then reuse the result."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
        f.write(data); path = f.name
    try:
        pk, ike, info = parse_capture(path, max_bytes=cap_mb * 2**20)
    finally:
        os.unlink(path)
    notes = [info["error"]] if info["error"] else []
    df, n2 = sessions_from_capture(ike, pk)
    return assess(detect(add_features(df))), pk, ike, notes + n2


def run(mode, up, cap_mb):
    empty = pd.DataFrame(columns=["time", "kind", "src", "dst"])
    if mode == SRC[0] or (mode == SRC[2] and up):
        data = up.getvalue() if up else open(os.path.join(ROOT, "sample", "demo_all.pcap"), "rb").read()
        return analyse_capture(data, cap_mb)
    if mode == SRC[1] or (mode == SRC[3] and up):
        df, notes = load_json_sessions(os.path.join(ROOT, "sample", "sample_sessions.json") if mode == SRC[1] else up)
        return assess(detect(add_features(df))), empty, [], notes
    return pd.DataFrame(), empty, [], ["Upload a file in the sidebar to begin."]


df, pk, ike, notes = run(mode, up, cap_mb)
for n in notes: st.warning(n)
tabs = st.tabs(["Command Center", "Packet Analysis", "Risk Explanation", "Timeline"])
with tabs[0]: overview.render(df)
with tabs[1]: packet_analysis.render(pk)
with tabs[2]: risk_analysis.render(df)
with tabs[3]: timeline.render(pk, ike)
if not df.empty:
    rows = json.loads(df.to_json(orient="records"))
    css = "body{font:14px system-ui;margin:24px}h1{font-size:20px}.s{border:1px solid #ccd;border-radius:8px;padding:10px;margin:10px 0}td,th{border:1px solid #ccd;padding:4px 8px;text-align:left}table{border-collapse:collapse}"
    body = "".join(
        f"<div class=s><b>Session {r.session_id} - {html_lib.escape(str(r.peer))}</b> | {r.ike_version} | {html_lib.escape(str(r.cipher))} | {html_lib.escape(str(r.dh_group))}"
        f"<br>Security Risk Score <b>{r.risk_score} ({r.risk_level})</b> | evidence: {r.source} | ML anomaly: {'n/a' if pd.isna(r.anomaly_score) else int(r.anomaly_score)}"
        f"<table><tr><th>Rule<th>Finding<th>Points<th>Evidence<th>Remediation</tr>"
        + "".join(f"<tr><td>{f['id']}<td>{html_lib.escape(f['label'])}<td>{f['points']}<td>{f['tier']}<td>{html_lib.escape(f['fix'])}</tr>" for f in r.findings)
        + "</table></div>" for r in df.itertuples())
    html = (f"<!doctype html><meta charset=utf-8><style>{css}</style><h1>IPsec VPN Analyzer report - SIH26160 Team SYNTRIX</h1>"
            "<p><b>SYNTHETIC / DEFENSIVE PROTOTYPE.</b> Findings are indicators requiring validation; the tool does not decrypt VPN traffic.</p>" + body)
    c = st.sidebar
    c.download_button("Download JSON report", json.dumps(rows, indent=2), "ipsec_report.json", "application/json")
    c.download_button("Download HTML report", html, "ipsec_report.html", "text/html")

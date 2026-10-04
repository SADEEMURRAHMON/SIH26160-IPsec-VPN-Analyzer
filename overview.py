"""Page 1 - Command Center."""
import pandas as pd
import streamlit as st
import plotly.express as px
from dashboard.plotting import show

ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
COLORS = {"LOW": "#2ecc71", "MEDIUM": "#f1c40f", "HIGH": "#e67e22", "CRITICAL": "#e74c3c"}


def render(df):
    if df.empty:
        st.info("No VPN sessions were found in this input.")
        return
    c = st.columns(4)
    c[0].metric("Max Security Risk Score", int(df.risk_score.max()))
    c[1].metric("High / Critical sessions", int(df.risk_level.isin(["HIGH", "CRITICAL"]).sum()))
    c[2].metric("ML behaviour anomalies", int(df.ml_anomaly.sum()))
    c[3].metric("Total sessions", len(df))
    icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
    flag = ["⚠ ANOMALY" if m == 1 else "n/a" if st_ == "insufficient data" else "normal" for m, st_ in zip(df.ml_anomaly, df.ml_status)]
    t = pd.DataFrame({"Session": df.session_id, "Peer": df.peer, "IKE": df.ike_version, "Risk score": df.risk_score,
                      "Risk level": [f"{icon[x]} {x}" + ("*" if na else "") for x, na in zip(df.risk_level, df.not_assessed)], "Cipher": df.cipher, "Integrity": df.integrity,
                      "DH group": df.dh_group, "ML anomaly score": [("n/a" if pd.isna(a) else f"{a:.0f}") for a in df.anomaly_score], "ML indicator": flag, "Explanation": df.explanation})
    st.dataframe(t, hide_index=True, column_config={
        "Session": st.column_config.NumberColumn(width="small"), "IKE": st.column_config.TextColumn(width="small"),
        "Risk score": st.column_config.NumberColumn(width="small", format="%d"),
        "Risk level": st.column_config.TextColumn(width="medium"),
        "ML anomaly score": st.column_config.TextColumn(help="Percentile vs a synthetic normal baseline. n/a = too few packets."),
        "Explanation": st.column_config.TextColumn(width="large")})
    counts = df.risk_level.value_counts().reindex(ORDER, fill_value=0).reset_index()
    counts.columns = ["risk_level", "sessions"]
    fig = px.bar(counts, x="risk_level", y="sessions", color="risk_level", color_discrete_map=COLORS,
                 title="Sessions by risk level", template="plotly_dark", text="sessions")
    fig.update_yaxes(dtick=1, rangemode="tozero")
    fig.update_layout(showlegend=False)
    show(fig)
    if any(df.not_assessed.map(bool)):
        st.caption("* Some fields were unknown for this session, so part of the configuration was NOT assessed (see Explanation / Risk Explanation).")
    st.caption("Security Risk Score = configuration indicators only. The ML anomaly score is separate and is not added to it.")

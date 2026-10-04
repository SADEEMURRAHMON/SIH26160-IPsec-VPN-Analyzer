"""Page 3 - Risk Explanation."""
import pandas as pd
import streamlit as st
import plotly.express as px
from dashboard.overview import COLORS
from dashboard.plotting import show
from src.anomaly_detector import baseline_medians


LABELS = {"packets": "Packets", "bytes": "Bytes", "duration": "Duration (s)", "pps": "Packets / s", "mean_pkt": "Mean packet size (B)"}


def behaviour(r):
    """Explain the ML indicator: this session's traffic vs the synthetic normal baseline."""
    base = baseline_medians()
    rows = [dict(Metric=LABELS[k], This_session=None if pd.isna(r[k]) else round(float(r[k]), 1), Baseline_median=round(base[k], 1),
                 Ratio=None if pd.isna(r[k]) else round(float(r[k]) / base[k], 1)) for k in LABELS]
    if r.ml_status == "insufficient data":
        st.caption("Behaviour indicator: not enough packets in this session to judge (needs at least 20).")
        return
    if r.ml_anomaly == 1:
        st.warning("⚠ Behaviour anomaly: this session's traffic volume is far from the synthetic normal baseline. "
                   "This is an indicator to investigate, not proof of malicious activity.")
    with st.expander("Why this ML score? (this session vs synthetic normal baseline)", expanded=bool(r.ml_anomaly == 1)):
        st.dataframe(pd.DataFrame(rows).rename(columns={"This_session": "This session", "Baseline_median": "Baseline median"}), hide_index=True)


def render(df):
    if df.empty:
        st.info("No sessions to explain.")
        return
    ids = [f"{r.session_id} - {r.peer}" for r in df.itertuples()]
    r = df.iloc[ids.index(st.selectbox("Select a session", ids))]
    c = st.columns(3)
    c[0].metric("Security Risk Score", int(r.risk_score))
    c[1].metric("Risk level", r.risk_level)
    a = r.anomaly_score
    c[2].metric("ML anomaly score", "n/a" if pd.isna(a) else f"{a:.0f}", help=f"Status: {r.ml_status}. An anomaly is not automatically malicious.")
    behaviour(r)
    st.caption(f"Evidence source for configuration fields: {r.source}"
               + (" (read from cleartext IKE)" if r.source == "OBSERVED" else " (user-supplied, unverified)"))
    if r.not_assessed:
        st.info("Not assessed (data unknown, so the score above does not cover these): " + ", ".join(r.not_assessed))
    if isinstance(r.offered, list):
        st.subheader("Offered vs selected")
        off = pd.DataFrame({"Initiator offered": r.offered})
        off["Responder selected"] = ["✔ selected" if x == r.selected else "" for x in r.offered]
        st.dataframe(off, hide_index=True, column_config={"Initiator offered": st.column_config.TextColumn(width="large")})
        st.write(f"**Responder selected:** `{r.selected}`")
    st.subheader("Score breakdown")
    if r.findings:
        f = pd.DataFrame(r.findings)
        st.dataframe(f[["id", "label", "points", "tier", "fix"]], hide_index=True,
                     column_config={"id": st.column_config.TextColumn(width="medium"), "points": st.column_config.NumberColumn(width="small"), "label": st.column_config.TextColumn(width="large"), "fix": st.column_config.TextColumn("Remediation", width="large")})
        scored = f[f.points > 0].sort_values("points")
        if not scored.empty:
            fig = px.bar(scored, x="points", y="id", orientation="h", template="plotly_dark", text="points",
                         title=f"Points contributing to the total of {int(r.risk_score)}", color_discrete_sequence=[COLORS[r.risk_level]])
            fig.update_xaxes(rangemode="tozero")
            fig.update_traces(textposition="inside", textfont_color="white")
            show(fig)
        else:
            st.caption("These are notes/advisories worth 0 points, so the score stays 0.")
    else:
        st.success("No configuration indicators found.")
    st.info("Findings are indicators that require validation. They do not prove compromise, and this tool does not decrypt VPN traffic.")

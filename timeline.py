"""Page 4 - Timeline."""
import pandas as pd
import streamlit as st
import plotly.express as px
from dashboard.plotting import show


def render(pk, ike):
    if pk.empty:
        st.info("No packet timestamps available (JSON metadata input).")
        return
    t0 = pk.time.min()
    g = pk.assign(t=((pk.time - t0) // 5) * 5).groupby(["t", "kind"]).size().reset_index(name="packets")
    fig = px.bar(g, x="t", y="packets", color="kind", template="plotly_dark", title="VPN packet volume per 5 s bin",
                 labels={"t": "seconds since first packet"})
    for e in ike[:40]:
        fig.add_vline(x=e["time"] - t0, line_width=1, line_dash="dot", line_color="#8e9aaf")
    fig.update_xaxes(range=[-5, float(pk.time.max() - t0) + 10])
    fig.update_yaxes(rangemode="tozero")
    show(fig)
    st.caption("Dotted lines mark IKE messages. Packet volume is the total across all sessions in the capture.")
    ev = pd.DataFrame([dict(seconds=round(e["time"] - t0, 2), version=f"IKEv{e['version']}", src=e["src"], dst=e["dst"],
                            event=("Aggressive Mode" if e["aggressive"] else "SA_INIT response" if e["response"] else "SA_INIT request" if e["version"] == 2 else "IKEv1 message")) for e in ike])
    st.subheader("IKE events")
    st.dataframe(ev, hide_index=True)

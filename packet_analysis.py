"""Page 2 - Packet Analysis."""
import pandas as pd
import streamlit as st
import plotly.express as px
from dashboard.plotting import show


def render(pk):
    if pk.empty:
        st.info("No packet data (JSON metadata input has no packets).")
        return
    k = pk.kind.value_counts()
    c = st.columns(5)
    c[0].metric("Total packets", len(pk))
    c[1].metric("ESP", int(k.get("ESP", 0) + k.get("ESP-in-UDP", 0)))
    c[2].metric("AH", int(k.get("AH", 0)))
    c[3].metric("IKE UDP/500", int(k.get("IKE-500", 0)))
    c[4].metric("NAT-T UDP/4500", int(k.get("NAT-T-4500", 0)))
    st.warning("ESP payloads are encrypted. Packet headers alone do NOT reveal the negotiated cipher; "
               "cipher and DH findings come only from cleartext IKE_SA_INIT messages.")
    f = st.columns(3)
    kinds = f[0].multiselect("Protocol", sorted(pk.kind.unique()), default=sorted(pk.kind.unique()))
    s, d = f[1].text_input("Source IP contains"), f[2].text_input("Destination IP contains")
    v = pk[pk.kind.isin(kinds)]
    v = v[v.src.str.contains(s, regex=False)] if s else v
    v = v[v.dst.str.contains(d, regex=False)] if d else v
    st.caption(f"{len(v)} packets match (showing first 1,000)")
    v = v.head(1000).assign(timestamp_utc=lambda x: pd.to_datetime(x.time, unit="s", utc=True).dt.strftime("%Y-%m-%d %H:%M:%S.%f").str[:-3])
    v = v[["no", "timestamp_utc", "src", "dst", "kind", "sport", "dport", "length", "spi"]].copy()
    for c in ("sport", "dport", "spi"):
        v[c] = v[c].astype("string").fillna("")
    st.dataframe(v, hide_index=True)
    mix = pk[pk.kind.isin(kinds)].kind.value_counts().reset_index()
    mix.columns = ["kind", "packets"]
    fig = px.bar(mix, y="kind", x="packets", color="kind", orientation="h", text="packets", title="Packets by protocol", template="plotly_dark")
    fig.update_layout(showlegend=False)
    fig.update_traces(textposition="outside", cliponaxis=False)
    show(fig)

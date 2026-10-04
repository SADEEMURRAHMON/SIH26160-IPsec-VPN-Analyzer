"""Chart helper: locks charts so a stray click cannot zoom, pan or hide series during a demo."""
import streamlit as st


def show(fig):
    fig.update_layout(legend_itemclick=False, legend_itemdoubleclick=False, dragmode=False, margin=dict(t=50, b=30))
    fig.update_xaxes(fixedrange=True)
    fig.update_yaxes(fixedrange=True)
    st.plotly_chart(fig, config={"displayModeBar": False})

import json, os, struct
import pandas as pd
import pytest
from src.pcap_parser import parse_capture
from src.ike_parser import parse
from src.session_loader import sessions_from_capture, load_json_sessions
from src.feature_engineering import add_features
from src.anomaly_detector import detect, evaluate
from src.risk_engine import assess

EXPECTED = json.load(open("sample/expected_findings.json"))

def analyse(path):
    pk, ike, info = parse_capture(path)
    df, _ = sessions_from_capture(ike, pk)
    return assess(detect(add_features(df))), pk, info

@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_golden_capture_matches_expected_findings(name):
    df, _, info = analyse(f"sample/{name}.pcap")
    assert info["error"] is None and len(df) == 1
    r = df.iloc[0]
    assert sorted(f["id"] for f in r.findings) == EXPECTED[name]["findings"]
    assert r.ml_anomaly == EXPECTED[name]["anomaly"]

def test_combined_demo_has_all_sessions_and_is_deterministic():
    a, _, _ = analyse("sample/demo_all.pcap"); b, _, _ = analyse("sample/demo_all.pcap")
    assert len(a) == 8 and list(a.risk_score) == list(b.risk_score)

def test_bad_files_do_not_crash(tmp_path):
    for name, data in {"empty": b"", "garbage": os.urandom(500), "trunc": open("sample/strong.pcap", "rb").read()[:1000]}.items():
        p = tmp_path / name; p.write_bytes(data)
        pk, ike, info = parse_capture(str(p))
        assert isinstance(pk, pd.DataFrame)
    assert parse_capture(str(tmp_path / "missing"))[2]["error"]
    big = tmp_path / "big"; big.write_bytes(b"x" * 2048)
    assert "limit" in parse_capture(str(big), max_bytes=1024)[2]["error"]

def test_malformed_ike_packets_return_none_or_safe():
    assert parse(b"") is None and parse(b"\x00" * 10) is None and parse(b"\xff" * 64) is None
    hdr = struct.pack("!8s8sBBBBII", b"a" * 8, b"\0" * 8, 33, 0x20, 34, 0x08, 0, 5000)  # claims 5000 bytes, has 28
    m = parse(hdr)
    assert m is not None and m["proposals"] == []
    hdr2 = hdr + struct.pack("!BBH", 0, 0, 9999) + b"\x01" * 20  # oversized payload length
    assert parse(hdr2)["proposals"] == []

def test_ml_handles_tiny_and_empty_inputs():
    one, _ = load_json_sessions({"sessions": [{"packets": 500, "bytes": 400000, "duration": 100}]})
    r = detect(add_features(one)).iloc[0]
    assert 0 <= r.anomaly_score <= 100 and r.ml_anomaly in (0, 1)
    thin, _ = load_json_sessions({"sessions": [{"session_id": 1}]})
    t = detect(add_features(thin)).iloc[0]
    assert t.ml_status == "insufficient data" and t.ml_anomaly == 0 and pd.isna(t.anomaly_score)
    assert detect(add_features(pd.DataFrame(columns=one.columns))).empty

def test_ml_detects_injected_outliers_on_synthetic_data():
    e = evaluate()
    assert e["detection_rate"] >= 0.9 and e["false_positive_rate"] <= 0.08

def test_streamlit_app_runs_in_every_demo_mode():
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py")), default_timeout=120).run()
    assert not at.exception
    at.selectbox[0].set_value("2 - 10.0.2.2").run()  # session with findings: exercises the breakdown chart
    assert not at.exception
    at.sidebar.radio[0].set_value("Demo session JSON (sample/sample_sessions.json)").run()
    assert not at.exception
    at.sidebar.radio[0].set_value("Upload PCAP / pcapng").run()
    assert not at.exception

import json
import pandas as pd
from src.session_loader import load_json_sessions

def test_loads_sample_file():
    df, warns = load_json_sessions("sample/sample_sessions.json")
    assert len(df) == 5 and not warns
    assert set(df.source) == {"SUPPLIED"}

def test_missing_optional_fields_tolerated():
    df, _ = load_json_sessions({"sessions": [{"session_id": 1}]})
    r = df.iloc[0]
    assert r.cipher == "unknown" and r.ike_version == "unknown" and pd.isna(r.packets)

def test_ike_version_normalised():
    df, _ = load_json_sessions({"sessions": [{"ike_version": "ikev1"}, {"ike_version": 2}, {"ike_version": "IKEv2"}]})
    assert list(df.ike_version) == ["IKEv1", "IKEv2", "IKEv2"]

def test_bad_inputs_do_not_crash():
    assert load_json_sessions("{not json")[0].empty
    assert load_json_sessions({"sessions": "x"})[0].empty
    df, w = load_json_sessions({"sessions": [1, {"session_id": 2}]})
    assert len(df) == 1 and w
    assert load_json_sessions("no/such/file.json")[0].empty

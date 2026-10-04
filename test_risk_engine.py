import pandas as pd
from src.session_loader import load_json_sessions
from src.feature_engineering import add_features, cipher_family, hash_family, dh_id
from src.risk_engine import assess, level

def run(**kw):
    base = dict(session_id=1, peer="p", ike_version="IKEv2", cipher="AES-256-GCM", integrity="SHA256", dh_group="group14", auth="certificate")
    df, _ = load_json_sessions({"sessions": [{**base, **kw}]})
    return assess(add_features(df)).iloc[0]

def ids(r): return {f["id"] for f in r.findings}

def test_modern_config_is_low_and_aes_sha2_not_flagged():
    r = run()
    assert r.risk_score == 0 and r.risk_level == "LOW" and not r.findings
    assert not ids(run(cipher="AES-128-CBC", integrity="HMAC-SHA2-256"))

def test_weak_configuration_detection():
    assert ids(run(cipher="3DES")) == {"ENC-3DES"}
    assert ids(run(cipher="DES-CBC")) == {"ENC-DES"}
    assert ids(run(integrity="MD5")) == {"HASH-MD5"}
    assert ids(run(integrity="SHA-1")) == {"HASH-SHA1"}
    assert ids(run(dh_group="group2")) == {"DH-WEAK"} and ids(run(dh_group="MODP-1024")) == {"DH-WEAK"}
    assert ids(run(dh_group="group5")) == {"DH-LOW"}
    assert ids(run(ike_version="IKEv1")) == {"IKEV1"}
    assert ids(run(auth="PSK")) == {"AUTH-PSK"} and run(auth="PSK").risk_score == 0

def test_multiple_weaknesses_score_and_cap():
    r = run(ike_version="IKEv1", cipher="3DES", integrity="MD5", dh_group="group1")
    assert r.risk_score == 78 and r.risk_level == "CRITICAL"
    r = run(ike_version="IKEv1", cipher="DES", integrity="MD5", dh_group="group1", aggressive=True)
    assert r.risk_score == 100  # 20+30+20+20+15 = 105 capped

def test_level_boundaries():
    assert [level(s) for s in (0, 24, 25, 49, 50, 74, 75, 100)] == ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"]

def test_deterministic():
    a, b = run(cipher="3DES", integrity="SHA1"), run(cipher="3DES", integrity="SHA1")
    assert a.risk_score == b.risk_score and a.explanation == b.explanation

def test_explanation_lists_every_contribution():
    r = run(cipher="3DES", integrity="SHA1")
    assert "3DES" in r.explanation and "SHA-1" in r.explanation and "+18" in r.explanation and "+12" in r.explanation

def test_normalisers():
    assert cipher_family("AES-GCM-16-256") == "AEAD" and cipher_family("3DES-CBC") == "3DES" and cipher_family("DES") == "DES"
    assert hash_family("HMAC-SHA1-96") == "SHA1" and hash_family("HMAC-SHA2-256-128") == "SHA2" and hash_family("MD5") == "MD5"
    assert dh_id("group14") == 14 and dh_id("MODP-2048") == 14 and dh_id("Curve25519") == 31

def test_unknown_fields_are_reported_not_treated_as_safe():
    df, _ = load_json_sessions({"sessions": [{"session_id": 1}]})
    r = assess(add_features(df)).iloc[0]
    assert r.risk_score == 0 and set(r.not_assessed) == {"cipher", "integrity/PRF", "DH group", "IKE version"}
    assert "NOT ASSESSED" in r.explanation
    assert run().not_assessed == []

"""Transparent Security Risk Score (configuration only). Every point is listed; the ML result is NOT blended in.
Bands: 0-24 LOW, 25-49 MEDIUM, 50-74 HIGH, 75-100 CRITICAL. Not an attack probability."""
import pandas as pd


def _t(x):
    return bool(x) if x is not None and x == x else False


def _offer_weak(r):
    g, s = r.get("offered_grades"), r.get("selected_grade")
    return isinstance(g, list) and s is not None and s == s and s > 1 and any(x <= 1 for x in g)


def _resp_weaker(r):
    g, s = r.get("offered_grades"), r.get("selected_grade")
    return isinstance(g, list) and bool(g) and s is not None and s == s and s < max(g)


# id, label, points, condition, remediation
RULES = [
    ("IKEV1", "IKEv1 observed", 20, lambda r: _t(r["ike_v1"]), "Use IKEv2 (strongSwan: keyexchange=ikev2)."),
    ("AGGR-MODE", "IKEv1 Aggressive Mode observed", 15, lambda r: _t(r["aggressive"]),
     "Disable aggressive mode; with a PSK it can allow offline guessing of the captured handshake."),
    ("ENC-DES", "DES cipher", 30, lambda r: r["cipher_family"] == "DES", "Replace with AES-GCM (ike=aes256gcm16-prfsha384-curve25519!)."),
    ("ENC-3DES", "3DES cipher (64-bit block)", 18, lambda r: r["cipher_family"] == "3DES", "Replace with AES-GCM (ike=aes256gcm16-prfsha384-curve25519!)."),
    ("HASH-MD5", "MD5 integrity/PRF", 20, lambda r: "MD5" in (r["integ_family"], r["prf_family"]), "Use SHA-2 (prfsha384) or an AEAD cipher."),
    ("HASH-SHA1", "SHA-1 integrity/PRF", 12,
     lambda r: "MD5" not in (r["integ_family"], r["prf_family"]) and "SHA1" in (r["integ_family"], r["prf_family"]), "Use SHA-2 (prfsha384) or an AEAD cipher."),
    ("DH-WEAK", "DH group 1/2 (<=1024-bit MODP)", 20, lambda r: r["dh_id"] in (1, 2), "Use group 14+ or Curve25519 (curve25519)."),
    ("DH-LOW", "DH group 5 (1536-bit MODP)", 12, lambda r: r["dh_id"] == 5, "Use group 14+ or Curve25519."),
    ("OFFER-WEAK", "Weak suite offered although a strong one was selected", 8, _offer_weak, "Remove weak proposals from the ike= list on every gateway."),
    ("RESP-WEAKER", "Responder selected a weaker suite than the best offered", 8, _resp_weaker, "Set responder policy to prefer the strongest proposal."),
    ("AUTH-PSK", "Pre-shared key authentication (note only, 0 points)", 0, lambda r: r["auth_type"] == "PSK", "Prefer certificates; use long random PSKs if PSK is required."),
    ("NO-PQ", "No post-quantum hybrid key exchange (advisory, 0 points)", 0,
     lambda r: r["source"] == "OBSERVED" and r["ike_v2"] and r["addke"] is False, "Consider RFC 9370 hybrid key exchange when supported."),
]


def level(score):
    return "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"


def not_assessed(r):
    """Fields that were unknown, so the matching rules could not be evaluated (never silently treated as safe)."""
    na = []
    if r["cipher_family"] == "UNKNOWN": na.append("cipher")
    if r["integ_family"] == "NONE" and r["prf_family"] == "NONE" and r["cipher_family"] != "AEAD": na.append("integrity/PRF")
    if r["dh_id"] != r["dh_id"]: na.append("DH group")
    if r["ike_version"] == "unknown": na.append("IKE version")
    return na


def assess_row(r):
    tier = "OBSERVED" if r["source"] == "OBSERVED" else "SUPPLIED"
    f = [dict(id=i, label=lb, points=p, tier=("ADVISORY" if i == "NO-PQ" else tier), fix=fx)
         for i, lb, p, c, fx in RULES if c(r)]
    score = min(100, sum(x["points"] for x in f))
    na = not_assessed(r)
    reasons = [f"{x['label']} (+{x['points']}, {x['tier']})" for x in f] or ["No weak configuration indicators found"]
    text = "; ".join(reasons) + (f" | NOT ASSESSED (unknown): {', '.join(na)}" if na else "")
    return dict(risk_score=score, risk_level=level(score), findings=f, explanation=text, not_assessed=na)


def assess(df):
    if df.empty:
        return df.assign(risk_score=[], risk_level=[], findings=[], explanation=[], not_assessed=[])
    out = pd.DataFrame([assess_row(r) for r in df.to_dict("records")], index=df.index)
    return pd.concat([df, out], axis=1)

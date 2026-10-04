"""Turn raw session fields into normalised security features (works for observed and supplied data)."""
import re
import numpy as np
import pandas as pd

MODP_BITS = {768: 1, 1024: 2, 1536: 5, 2048: 14, 3072: 15, 4096: 16, 6144: 17, 8192: 18}
NAMED = {"ECP-256": 19, "ECP-384": 20, "ECP-521": 21, "CURVE25519": 31, "CURVE448": 32}


def cipher_family(s):
    u = str(s).upper()
    if "3DES" in u or "TRIPLE" in u or "DES3" in u:
        return "3DES"
    if re.search(r"(^|[^A-Z0-9])DES($|[^A-Z0-9])", u):
        return "DES"
    if "GCM" in u or "CHACHA" in u:
        return "AEAD"
    return "AES" if "AES" in u else "UNKNOWN"


def hash_family(s):
    u = str(s).upper()
    if "MD5" in u:
        return "MD5"
    if re.search(r"SHA-?2|SHA-?(256|384|512)", u):
        return "SHA2"
    if re.search(r"SHA-?1(?!\d)", u):
        return "SHA1"
    return "NONE"


def dh_id(s):
    u = str(s).upper()
    for k, v in NAMED.items():
        if k in u:
            return v
    m = re.search(r"MODP[-_ ]?(\d+)", u)
    if m:
        return MODP_BITS.get(int(m.group(1)), np.nan)
    m = re.search(r"(?:GROUP|DH)[-_ ]?(\d+)", u)
    return int(m.group(1)) if m else np.nan


def auth_type(s):
    u = str(s).lower()
    return "PSK" if ("psk" in u or "pre-shared" in u or "preshared" in u) else \
        "certificate" if ("cert" in u or "rsa" in u or "ecdsa" in u) else "unknown"


def add_features(df):
    df = df.copy()
    if df.empty:
        for c in ["cipher_family", "integ_family", "prf_family", "auth_type", "pps", "mean_pkt", "ike_v1", "ike_v2"]:
            df[c] = []
        return df
    df["cipher_family"] = df.cipher.map(cipher_family)
    df["integ_family"] = df.integrity.map(hash_family)
    df["prf_family"] = df.prf.map(hash_family)
    df["dh_id"] = [d if pd.notna(d) else dh_id(g) for d, g in zip(df.dh_id, df.dh_group)]
    df["auth_type"] = df.auth.map(auth_type)
    df["ike_v1"], df["ike_v2"] = df.ike_version == "IKEv1", df.ike_version == "IKEv2"
    dur = df.duration.astype(float).where(df.duration.astype(float) > 0)
    df["pps"] = df.packets.astype(float) / dur
    df["mean_pkt"] = df.bytes.astype(float) / df.packets.astype(float).where(df.packets.astype(float) > 0)
    return df

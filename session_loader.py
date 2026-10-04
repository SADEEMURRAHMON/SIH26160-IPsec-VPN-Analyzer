"""Build one common Session table from (a) IKE messages found in a capture [OBSERVED]
or (b) a user-supplied JSON file [SUPPLIED, unverified]."""
import json
import numpy as np
import pandas as pd
from src import ike_parser as ik

COLUMNS = ["session_id", "peer", "ike_version", "cipher", "integrity", "prf", "dh_group", "dh_id", "auth", "status",
           "packets", "bytes", "duration", "source", "aggressive", "offered", "selected", "offered_grades",
           "selected_grade", "addke", "first_ts"]


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return np.nan


def _ver(v):
    s = str(v or "").upper().replace("IKE", "").replace("V", "").strip()
    return {"1": "IKEv1", "2": "IKEv2"}.get(s, "unknown")


def load_json_sessions(source):
    """source: path, JSON string/bytes, file-like object or dict. Returns (df, warnings). Optional fields may be missing."""
    warns = []
    try:
        if isinstance(source, dict):
            data = source
        elif hasattr(source, "read"):
            data = json.loads(source.read())
        elif isinstance(source, (bytes, str)) and str(source).lstrip()[:1] in "{[":
            data = json.loads(source)
        else:
            with open(source, "r", encoding="utf-8") as f:
                data = json.load(f)
    except (OSError, ValueError) as e:
        return pd.DataFrame(columns=COLUMNS), [f"Could not read JSON: {e}"]
    items = data.get("sessions") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return pd.DataFrame(columns=COLUMNS), ["JSON must contain a 'sessions' list."]
    rows = []
    for i, s in enumerate(items):
        if not isinstance(s, dict):
            warns.append(f"Entry {i} skipped (not an object).")
            continue
        rows.append(dict(
            session_id=s.get("session_id", i + 1), peer=s.get("peer") or "unknown", ike_version=_ver(s.get("ike_version")),
            cipher=str(s.get("cipher") or "unknown"), integrity=str(s.get("integrity") or ""), prf=str(s.get("prf") or ""),
            dh_group=str(s.get("dh_group") or "unknown"), dh_id=np.nan, auth=str(s.get("auth") or "unknown"),
            status=s.get("status") or "unknown", packets=_num(s.get("packets")), bytes=_num(s.get("bytes")),
            duration=_num(s.get("duration")), source="SUPPLIED", aggressive=bool(s.get("aggressive", False)),
            offered=None, selected=None, offered_grades=None, selected_grade=None, addke=None, first_ts=np.nan))
    return pd.DataFrame(rows, columns=COLUMNS), warns


def sessions_from_capture(ike, pk):
    """Pair IKEv2 SA_INIT request/response by initiator SPI; add IKEv1 sessions. Stats come from all packets
    between the same two endpoints (heuristic: ESP SPIs are negotiated inside encrypted IKE_AUTH)."""
    init, resp, v1, notes, rows = {}, {}, {}, [], []
    for m in ike:
        if m["version"] == 2:
            (resp if m["response"] else init).setdefault(m["ispi"], m)
        else:
            v1.setdefault(m["ispi"], m)

    def stats(a, b):
        if pk.empty:
            return np.nan, np.nan, np.nan, np.nan
        d = pk[((pk.src == a) & (pk.dst == b)) | ((pk.src == b) & (pk.dst == a))]
        if d.empty:
            return np.nan, np.nan, np.nan, np.nan
        return len(d), float(d.length.sum()), float(d.time.max() - d.time.min()), float(d.time.min())

    n = 0
    for spi, a in init.items():
        r = resp.get(spi)
        if not r or not r["proposals"]:
            notes.append(f"IKE_SA_INIT {spi[:8]} had no readable response; skipped.")
            continue
        n += 1
        sel = r["proposals"][0]
        p, by, du, ft = stats(a["src"], a["dst"])
        enc = sel.get(1, [(0, None)])[0]
        integ = [ik.name(3, i) for i, _ in sel.get(3, []) if i]
        prf = [ik.name(2, i) for i, _ in sel.get(2, [])]
        dhs = sel.get(4, [(0, None)])[0][0]
        rows.append(dict(
            session_id=n, peer=a["dst"], ike_version="IKEv2", cipher=ik.name(1, *enc), integrity=integ[0] if integ else "AEAD",
            prf=prf[0] if prf else "", dh_group=ik.name(4, dhs), dh_id=float(dhs), auth="unknown (encrypted in IKE_AUTH)",
            status="SA_INIT answered", packets=p, bytes=by, duration=du, source="OBSERVED", aggressive=False,
            offered=[ik.suite(x) for x in a["proposals"]], selected=ik.suite(sel),
            offered_grades=[ik.grade(x) for x in a["proposals"]], selected_grade=ik.grade(sel),
            addke=any(6 <= t <= 12 for t in sel), first_ts=ft))
    for spi, a in v1.items():
        n += 1
        p, by, du, ft = stats(a["src"], a["dst"])
        rows.append(dict(
            session_id=n, peer=a["dst"], ike_version="IKEv1", cipher="unknown (IKEv1 SA not parsed)", integrity="", prf="",
            dh_group="unknown", dh_id=np.nan, auth="unknown", status="Aggressive Mode" if a["aggressive"] else "Main/other mode",
            packets=p, bytes=by, duration=du, source="OBSERVED", aggressive=a["aggressive"], offered=None, selected=None,
            offered_grades=None, selected_grade=None, addke=None, first_ts=ft))
    df = pd.DataFrame(rows, columns=COLUMNS).sort_values("first_ts", na_position="last", kind="stable").reset_index(drop=True)
    df["session_id"] = range(1, len(df) + 1)
    return df, notes

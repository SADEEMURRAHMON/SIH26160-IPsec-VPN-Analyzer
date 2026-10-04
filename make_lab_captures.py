"""Generate SYNTHETIC lab captures (never real traffic), expected findings, demo CSVs and sample JSON.
Run from the repo root:  python scripts/make_lab_captures.py"""
import json, os, random, struct, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import pandas as pd
from src.pcap_parser import parse_capture
from src.session_loader import sessions_from_capture, load_json_sessions
from src.feature_engineering import add_features
from src.anomaly_detector import detect
from src.risk_engine import assess

def tf(t, i, kl=None): return (t, i, kl)
def prop(enc, kl, prf, integ, dh, addke=False):
    return [tf(1, enc, kl), tf(2, prf)] + ([tf(3, integ)] if integ else []) + [tf(4, dh)] + ([tf(6, 36)] if addke else [])
STRONG, LEGACY = prop(20, 256, 6, 0, 31), prop(3, None, 2, 2, 2)
CBC256, WEAKCBC = prop(12, 256, 5, 12, 14), prop(12, 128, 2, 2, 2)

# name: (offered proposals, selected index, esp packets, mean size, duration s, expected finding ids, anomaly)
SCEN = {
    "strong": ([STRONG], 0, 220, 800, 150, ["NO-PQ"], 0),
    "legacy_3des": ([LEGACY, CBC256], 0, 180, 700, 120, ["DH-WEAK", "ENC-3DES", "HASH-SHA1", "NO-PQ", "RESP-WEAKER"], 0),
    "offer_weak": ([STRONG, WEAKCBC], 0, 250, 850, 160, ["NO-PQ", "OFFER-WEAK"], 0),
    "resp_weaker": ([prop(20, 128, 5, 0, 19), CBC256], 1, 200, 780, 140, ["NO-PQ", "RESP-WEAKER"], 0),
    "md5_dh5": ([prop(12, 128, 5, 1, 5)], 0, 160, 650, 110, ["DH-LOW", "HASH-MD5", "NO-PQ"], 0),
    "pq_hybrid": ([prop(20, 256, 6, 0, 20, True)], 0, 240, 820, 170, [], 0),
    "ikev1_aggressive": (None, 0, 0, 0, 0, ["AGGR-MODE", "IKEV1"], 0),
    "volume_anomaly": ([STRONG], 0, 3000, 1400, 90, ["NO-PQ"], 1),
}

def tfb(t, i, kl, last):
    at = struct.pack("!HH", 0x800E, kl) if kl else b""
    return struct.pack("!BBHBBH", 0 if last else 3, 0, 8 + len(at), t, 0, i) + at
def propb(n, tfs, last):
    body = b"".join(tfb(t, i, k, j == len(tfs) - 1) for j, (t, i, k) in enumerate(tfs))
    return struct.pack("!BBHBBBB", 0 if last else 2, 0, 8 + len(body), n, 1, 0, len(tfs)) + body
def sa_init(props, ispi, rspi, resp, rng):
    sab = b"".join(propb(n + 1, p, n == len(props) - 1) for n, p in enumerate(props))
    sa = struct.pack("!BBH", 34, 0, 4 + len(sab)) + sab
    ke = struct.pack("!BBHHH", 40, 0, 72, 31, 0) + rng.randbytes(64)
    no = struct.pack("!BBH", 0, 0, 36) + rng.randbytes(32)
    body = sa + ke + no
    return struct.pack("!8s8sBBBBII", ispi, rspi, 33, 0x20, 34, 0x20 if resp else 0x08, 0, 28 + len(body)) + body
def ikev1_aggr(ispi, rng):
    body = rng.randbytes(60)
    return struct.pack("!8s8sBBBBII", ispi, b"\0" * 8, 1, 0x10, 4, 0, 0, 28 + len(body)) + body
def ip_pkt(src, dst, proto, payload):
    a = lambda s: bytes(map(int, s.split(".")))
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0, a(src), a(dst))
    return b"\0" * 12 + b"\x08\x00" + ip + payload
def udp(sp, dp, data): return struct.pack("!HHHH", sp, dp, 8 + len(data), 0) + data
def write_pcap(path, pkts, snap=96):  # truncated capture (snaplen) keeps files small; wire length is preserved
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, snap, 1))
        for t, p, wire in sorted(pkts, key=lambda x: x[0]):
            c = p[:snap] if p[23] == 50 else p  # only ESP is snaplen-truncated; IKE kept whole
            f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(c), wire) + c)

def scenario(i, name, spec):
    offered, si, n, size, dur, _, _ = spec
    rng = random.Random(name); a, b = f"10.0.{i}.1", f"10.0.{i}.2"
    ispi, rspi, t0, out = rng.randbytes(8), rng.randbytes(8), 1790000000.0 + i, []
    if offered is None:
        pk = ip_pkt(a, b, 17, udp(500, 500, ikev1_aggr(ispi, rng))); return [(t0, pk, len(pk))]
    for t, resp, props in ((t0, False, offered), (t0 + 0.02, True, [offered[si]])):
        pk = ip_pkt(a if not resp else b, b if not resp else a, 17, udp(500, 500, sa_init(props, ispi, rspi if resp else b"\0" * 8, resp, rng)))
        out.append((t, pk, len(pk)))
    spi = rng.randbytes(4)
    for k in range(n):
        ln = int(max(80, min(1500, rng.gauss(size, size * 0.15 + 10))))
        pk = ip_pkt(a, b, 50, spi + struct.pack("!I", k + 1) + bytes(max(0, ln - 8 - 34)))
        out.append((t0 + 1 + rng.uniform(0, dur), pk, len(pk)))
    return out

def main():
    s = os.path.join(ROOT, "sample"); d = os.path.join(ROOT, "data")
    allp, expected = [], {}
    for i, (name, spec) in enumerate(SCEN.items(), 1):
        pk = scenario(i, name, spec); allp += pk
        write_pcap(os.path.join(s, name + ".pcap"), pk)
        expected[name] = dict(findings=spec[5], anomaly=spec[6])
    write_pcap(os.path.join(s, "demo_all.pcap"), allp)
    json.dump(expected, open(os.path.join(s, "expected_findings.json"), "w"), indent=2)
    sess = [  # SUPPLIED metadata examples (unverified by definition)
        dict(session_id=101, peer="Gateway-01", ike_version="IKEv2", cipher="AES-256-GCM", integrity="SHA256", dh_group="group14", auth="certificate", status="established", packets=210, bytes=168000, duration=140),
        dict(session_id=102, peer="Branch-07", ike_version="IKEv1", cipher="3DES", integrity="SHA1", dh_group="group2", auth="PSK", status="established", packets=190, bytes=142000, duration=130),
        dict(session_id=103, peer="Legacy-Router", ike_version="IKEv1", cipher="3DES", integrity="MD5", dh_group="group1", auth="PSK", status="established", packets=175, bytes=120000, duration=125),
        dict(session_id=104, peer="Gateway-02", ike_version="IKEv2", cipher="AES-256-GCM", integrity="SHA256", dh_group="group14", auth="certificate", status="established", packets=9800, bytes=13200000, duration=95),
        dict(session_id=105, peer="Partner-Site"),
    ]
    json.dump({"sessions": sess}, open(os.path.join(s, "sample_sessions.json"), "w"), indent=2)
    pk, ike, _ = parse_capture(os.path.join(s, "demo_all.pcap"))
    df, _ = sessions_from_capture(ike, pk)
    df = assess(detect(add_features(df)))
    pk.to_csv(os.path.join(d, "demo_packets.csv"), index=False)
    df.drop(columns=["findings", "offered", "offered_grades"]).to_csv(os.path.join(d, "demo_vpn_sessions.csv"), index=False)
    print("wrote", len(SCEN), "scenarios,", len(pk), "packets,", len(df), "sessions")

if __name__ == "__main__":
    main()

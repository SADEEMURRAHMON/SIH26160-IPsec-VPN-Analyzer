"""Capture-format support (VLAN, Linux cooked, IPv6, NAT-T, pcapng) and fuzzing of untrusted input."""
import logging, random, sys, os
import pandas as pd
import pytest
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, IPv6, UDP, Raw, Dot1Q, wrpcap, wrpcapng
from scapy.layers.l2 import CookedLinux
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import make_lab_captures as M
from src.ike_parser import parse
from src.pcap_parser import parse_capture
from src.session_loader import sessions_from_capture
from src.feature_engineering import add_features
from src.anomaly_detector import detect
from src.risk_engine import assess

# Explicit MAC addresses: otherwise Scapy tries to resolve them over the network (fails on Windows without Npcap).
ETH = lambda: Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
RNG = random.Random("fmt")
ISPI, RSPI = RNG.randbytes(8), RNG.randbytes(8)
REQ = M.sa_init([M.STRONG, M.WEAKCBC], ISPI, b"\0" * 8, False, RNG)
RSP = M.sa_init([M.STRONG], ISPI, RSPI, True, RNG)
v4 = lambda a, b, sp, dp, d: IP(src=a, dst=b) / UDP(sport=sp, dport=dp) / Raw(d)
v6 = lambda a, b, d: IPv6(src=a, dst=b) / UDP(sport=500, dport=500) / Raw(d)
ESP = lambda n=40: [IP(src="10.1.0.1", dst="10.1.0.2", proto=50) / Raw(bytes([0, 0, 0, 1, 0, 0, 0, i]) + bytes(90)) for i in range(n)]
CASES = {
    "ethernet": [ETH() / v4("10.1.0.1", "10.1.0.2", 500, 500, REQ), ETH() / v4("10.1.0.2", "10.1.0.1", 500, 500, RSP)] + [ETH() / p for p in ESP()],
    "vlan": [ETH() / Dot1Q(vlan=10) / v4("10.1.0.1", "10.1.0.2", 500, 500, REQ), ETH() / Dot1Q(vlan=10) / v4("10.1.0.2", "10.1.0.1", 500, 500, RSP)],
    "linux_cooked": [CookedLinux() / v4("10.1.0.1", "10.1.0.2", 500, 500, REQ), CookedLinux() / v4("10.1.0.2", "10.1.0.1", 500, 500, RSP)],
    "nat_t": [ETH() / v4("10.1.0.1", "10.1.0.2", 4500, 4500, b"\0\0\0\0" + REQ), ETH() / v4("10.1.0.2", "10.1.0.1", 4500, 4500, b"\0\0\0\0" + RSP)],
    "ipv6": [ETH() / v6("2001:db8::1", "2001:db8::2", REQ), ETH() / v6("2001:db8::2", "2001:db8::1", RSP)],
}

def analyse(path):
    pk, ike, info = parse_capture(str(path))
    df, _ = sessions_from_capture(ike, pk)
    return assess(detect(add_features(df))), pk, info

@pytest.mark.parametrize("name", sorted(CASES))
def test_pcap_variants_give_same_findings(name, tmp_path):
    p = tmp_path / f"{name}.pcap"; wrpcap(str(p), CASES[name])
    df, _, info = analyse(p)
    assert info["error"] is None and len(df) == 1
    assert sorted(f["id"] for f in df.iloc[0].findings) == ["NO-PQ", "OFFER-WEAK"]

def test_pcapng_and_nat_t_esp_classification(tmp_path):
    p = tmp_path / "x.pcapng"; wrpcapng(str(p), CASES["ethernet"])
    df, pk, _ = analyse(p)
    assert len(df) == 1 and (pk.kind == "ESP").sum() == 40
    nat = CASES["nat_t"] + [ETH() / v4("10.1.0.1", "10.1.0.2", 4500, 4500, bytes([0, 0, 0, 9, 0, 0, 0, i]) + bytes(80)) for i in range(5)]
    q = tmp_path / "nat.pcap"; wrpcap(str(q), nat)
    assert (analyse(q)[1].kind == "ESP-in-UDP").sum() == 5

def test_fuzzed_ike_packets_never_raise():
    rng = random.Random(1)
    for _ in range(3000):
        b = bytearray(REQ if rng.random() < .5 else RSP)
        for _ in range(rng.randint(1, 12)): b[rng.randrange(len(b))] = rng.randrange(256)
        if rng.random() < .3: b = b[:rng.randrange(len(b))]
        parse(bytes(b))  # must return dict/None, never raise

def test_fuzzed_capture_files_never_crash(tmp_path):
    rng = random.Random(2)
    raw = open("sample/offer_weak.pcap", "rb").read()
    for i in range(60):
        b = bytearray(raw)
        for _ in range(rng.randint(1, 30)): b[rng.randrange(len(b))] = rng.randrange(256)
        if rng.random() < .3: b = b[:rng.randrange(24, len(b))]
        p = tmp_path / f"f{i}.pcap"; p.write_bytes(bytes(b))
        pk, ike, info = parse_capture(str(p))
        assert isinstance(pk, pd.DataFrame) and isinstance(ike, list)
        sessions_from_capture(ike, pk)  # downstream must tolerate whatever was parsed

"""Streaming PCAP/pcapng reader (Scapy). Builds a packet table and collects IKE messages.
Failures (invalid, empty, truncated, oversized) are reported in `info`, never raised."""
import os
import pandas as pd
from scapy.utils import PcapReader
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from src.ike_parser import parse as parse_ike

COLUMNS = ["no", "time", "src", "dst", "proto", "kind", "sport", "dport", "length", "spi"]
MAX_BYTES, MAX_PACKETS = 50 * 2**20, 500_000


def _empty():
    return pd.DataFrame(columns=COLUMNS)


def parse_capture(path, max_bytes=MAX_BYTES, max_packets=MAX_PACKETS):
    """Return (packets_df, ike_messages, info). info = {error, truncated, packets}."""
    info = {"error": None, "truncated": False, "packets": 0}
    if not os.path.isfile(path):
        info["error"] = "File not found."
        return _empty(), [], info
    if os.path.getsize(path) > max_bytes:
        info["error"] = f"File larger than the {max_bytes // 2**20} MB limit."
        return _empty(), [], info
    rows, ike = [], []
    try:
        with PcapReader(path) as reader:
            for n, p in enumerate(reader, 1):
                if n > max_packets:
                    info["truncated"] = True
                    break
                try:
                    ip = p.getlayer(IP) or p.getlayer(IPv6)
                    if ip is None:
                        continue
                    v6 = isinstance(ip, IPv6)
                    proto = int(ip.nh if v6 else ip.proto)
                    sport = dport = spi = None
                    kind, payload = "OTHER", b""
                    if proto == 50:
                        kind, payload = "ESP", bytes(ip.payload)
                        spi = payload[:4].hex()
                    elif proto == 51:
                        kind = "AH"
                    elif proto == 17 and p.haslayer(UDP):
                        u = p.getlayer(UDP)
                        sport, dport, payload = int(u.sport), int(u.dport), bytes(u.payload)
                        kind = "UDP"
                        if 500 in (sport, dport):
                            kind = "IKE-500"
                        elif 4500 in (sport, dport):
                            if payload[:4] == b"\0\0\0\0":
                                kind, payload = "NAT-T-4500", payload[4:]
                            else:
                                kind, spi = "ESP-in-UDP", payload[:4].hex()
                    elif proto == 6 and p.haslayer(TCP):
                        t = p.getlayer(TCP)
                        kind, sport, dport = "TCP", int(t.sport), int(t.dport)
                    ts = float(p.time)
                    rows.append((n, ts, ip.src, ip.dst, proto, kind, sport, dport, int(getattr(p, "wirelen", len(p)) or len(p)), spi))
                    if kind in ("IKE-500", "NAT-T-4500"):
                        m = parse_ike(payload)
                        if m:
                            ike.append({**m, "time": ts, "src": ip.src, "dst": ip.dst})
                except Exception:
                    continue  # one malformed packet must not stop the analysis
    except Exception as e:
        info["error"] = (f"Capture could not be fully read ({type(e).__name__}); showing what was parsed." if rows
                         else "This file is not a valid PCAP/pcapng capture, or it is corrupt.")
    info["packets"] = len(rows)
    if not rows and not info["error"]:
        info["error"] = "Capture contains no IP packets."
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["sport"], df["dport"] = df["sport"].astype("Int64"), df["dport"].astype("Int64")
    return df, ike, info

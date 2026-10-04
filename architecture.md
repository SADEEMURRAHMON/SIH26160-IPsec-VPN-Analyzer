# Architecture
`pcap_parser` (Scapy stream) → `ike_parser` (bounds-checked IKE) → `session_loader` (Session table, tier OBSERVED/SUPPLIED)
→ `feature_engineering` (normalise cipher/hash/DH, rates) → `risk_engine` (config score) and `anomaly_detector`
(behaviour indicator, kept separate) → `dashboard/*` pages → JSON/HTML export. `app.py` wires input selection,
size limits and error notes. `scripts/make_lab_captures.py` creates all synthetic data.

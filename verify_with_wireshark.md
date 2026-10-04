# Verify by hand
1. Open `sample/legacy_3des.pcap` in Wireshark; filter `isakmp`.
2. In the IKE_SA_INIT request, expand *Security Association* and list the proposals; in the response, note the selected one.
3. Compare encryption, PRF, integrity and DH group with the dashboard's *Offered vs selected* table (session `10.0.2.2`).
Note: the lab IP/UDP checksums are zero, so Wireshark may flag them; the IKE fields are what matter.

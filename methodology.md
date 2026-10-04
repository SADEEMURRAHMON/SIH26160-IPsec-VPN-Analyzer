# Methodology
**Evidence:** only cleartext IKE_SA_INIT fields are read. IKE_AUTH authenticates SA_INIT, so tampering is detectable;
weak offers are a configuration exposure, not proof of attack.
**Offered vs selected:** each proposal is graded 0-3 by its weakest component (DES/MD5/DH1-2 = 0; 3DES/SHA-1/DH5 = 1;
AES-CBC or DH14 = 2; AEAD/SHA-2/ECP/Curve = 3). OFFER-WEAK: a grade<=1 proposal was offered but the selected one is >1.
RESP-WEAKER: selected grade is below the best offered.
**Risk score:** sum of rule points, capped at 100 (see README). Not a probability.
**ML:** Isolation Forest on log-scaled features, trained on a seeded synthetic normal baseline; anomaly_score is the
percentile of anomalousness against that baseline. Sessions under 20 packets are "insufficient data". An anomaly is not
automatically malicious. Missing feature values are filled with baseline medians.
**References to verify before citing:** RFC 8247 (IKEv2 algorithm guidance), RFC 9370 (multiple key exchanges), NIST SP 800-131A/800-57.

"""IKE parsing. Reads only CLEARTEXT fields: IKEv2 IKE_SA_INIT proposals and the IKEv1 header.
Nothing here decrypts traffic. Every length field is bounds-checked (input is untrusted)."""
import struct

ENCR = {1: "DES", 3: "3DES", 12: "AES-CBC", 18: "AES-GCM-8", 19: "AES-GCM-12", 20: "AES-GCM-16", 28: "CHACHA20-POLY1305"}
PRF = {1: "HMAC-MD5", 2: "HMAC-SHA1", 5: "HMAC-SHA2-256", 6: "HMAC-SHA2-384", 7: "HMAC-SHA2-512"}
INTEG = {1: "HMAC-MD5-96", 2: "HMAC-SHA1-96", 12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192", 14: "HMAC-SHA2-512-256"}
DH = {1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048", 15: "MODP-3072", 16: "MODP-4096",
      19: "ECP-256", 20: "ECP-384", 21: "ECP-521", 31: "Curve25519", 32: "Curve448"}
MAPS = {1: ENCR, 2: PRF, 3: INTEG, 4: DH}


def parse_sa(b):
    """Parse an IKEv2 SA payload body into a list of proposals ({transform_type: [(id, keylen)]})."""
    off, out = 0, []
    while off + 8 <= len(b) and len(out) < 32:
        more, _, pl, _, _, spis, nt = struct.unpack("!BBHBBBB", b[off:off + 8])
        if pl < 8 or off + pl > len(b):
            break
        t, tf = off + 8 + spis, {}
        for _ in range(min(nt, 64)):
            if t + 8 > off + pl:
                break
            _, _, tl, tt, _, tid = struct.unpack("!BBHBBH", b[t:t + 8])
            if tl < 8 or t + tl > off + pl:
                break
            kl = None
            if tl >= 12:
                a, v = struct.unpack("!HH", b[t + 8:t + 12])
                kl = v if a == 0x800E else None
            tf.setdefault(tt, []).append((tid, kl))
            t += tl
        if tf:
            out.append(tf)
        off += pl
        if more == 0:
            break
    return out


def parse(b):
    """Return a dict for an IKEv2 IKE_SA_INIT or an IKEv1 header, else None. Never raises."""
    try:
        if len(b) < 28:
            return None
        ispi, _, nxt, ver, ex, fl, _, ln = struct.unpack("!8s8sBBBBII", b[:28])
        if ver >> 4 == 1:
            if ex not in (2, 4, 5, 32) or ln < 28:
                return None
            return dict(version=1, ispi=ispi.hex(), response=False, exchange=ex, aggressive=ex == 4, proposals=[])
        if ver >> 4 != 2 or ex != 34:
            return None
        off, props, n, end = 28, [], 0, min(len(b), ln)
        while nxt and off + 4 <= end and n < 16:
            n2, _, pl = struct.unpack("!BBH", b[off:off + 4])
            if pl < 4 or off + pl > end:
                break
            if nxt == 33:
                props += parse_sa(b[off + 4:off + pl])
            nxt, off, n = n2, off + pl, n + 1
        return dict(version=2, ispi=ispi.hex(), response=bool(fl & 0x20), exchange=ex, aggressive=False, proposals=props)
    except struct.error:
        return None


def name(tt, tid, kl=None):
    return MAPS[tt].get(tid, f"id{tid}") + (f"-{kl}" if kl else "")


def suite(p):
    """Human-readable proposal string."""
    s = [f"{l}={name(t, i, k)}" for t, l in ((1, "ENCR"), (2, "PRF"), (3, "INTEG"), (4, "DH"))
         for i, k in p.get(t, []) if not (t == 3 and i == 0)]
    return " ".join(s + (["ADDKE(RFC9370)"] if any(6 <= t <= 12 for t in p) else []))


def grade(p):
    """0 broken .. 3 strong. A proposal is as strong as its weakest component."""
    g = [0 if i == 1 else 1 if i == 3 else 3 if i in (18, 19, 20, 28) else 2 for i, _ in p.get(1, [])]
    g += [0 if i in (1, 2) else 1 if i == 5 else 2 if i == 14 else 3 for i, _ in p.get(4, [])]
    g += [0 if i == 1 else 1 if i == 2 else 3 for t in (2, 3) for i, _ in p.get(t, []) if i != 0]
    return min(g) if g else 0

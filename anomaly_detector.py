"""Behavioural indicator: Isolation Forest trained on a deterministic SYNTHETIC normal baseline.
An anomaly is NOT automatically malicious. Works with 1+ sessions; missing values use baseline medians."""
from functools import lru_cache
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

MIN_PACKETS = 20
FEATURES = ["packets", "bytes", "duration", "pps", "mean_pkt"]


def synthetic_baseline(n=400, seed=7):
    rng = np.random.default_rng(seed)
    pk, sz, du = rng.lognormal(5.2, 0.6, n), rng.normal(800, 150, n).clip(200, 1400), rng.lognormal(5.0, 0.5, n)
    return pd.DataFrame(dict(packets=pk, bytes=pk * sz, duration=du, pps=pk / du, mean_pkt=sz))


@lru_cache(maxsize=1)
def baseline_medians():
    """Median of each behaviour feature in the synthetic normal baseline (used to explain a flag)."""
    return synthetic_baseline().median().to_dict()


def _x(df, med):
    return np.log1p(df[FEATURES].astype(float).fillna(med).clip(lower=0).to_numpy())


@lru_cache(maxsize=1)
def _model():
    base = synthetic_baseline()
    med = base.median()
    sc = RobustScaler().fit(_x(base, med))
    iso = IsolationForest(n_estimators=200, contamination=0.02, random_state=42).fit(sc.transform(_x(base, med)))
    return sc, iso, med, -iso.score_samples(sc.transform(_x(base, med)))


def detect(df):
    """Adds anomaly_score (0-100 = percentile of anomalousness vs the synthetic baseline) and ml_anomaly (0/1)."""
    if df.empty:
        return df.assign(anomaly_score=[], ml_anomaly=[], ml_status=[])
    sc, iso, med, base_s = _model()
    X = sc.transform(_x(df, med))
    s = -iso.score_samples(X)
    df = df.copy()
    df["anomaly_score"] = np.round(100 * (base_s[None, :] <= s[:, None]).mean(axis=1), 1)
    df["ml_anomaly"] = (iso.predict(X) == -1).astype(int)
    thin = df.packets.astype(float).fillna(0) < MIN_PACKETS  # too little traffic to judge behaviour
    df.loc[thin, "anomaly_score"], df.loc[thin, "ml_anomaly"] = np.nan, 0
    df["ml_status"] = np.where(thin, "insufficient data", "scored")
    return df


def evaluate(n=500, outliers=50, seed=11):
    """Synthetic self-test: detection rate on injected outliers and false-positive rate on held-out normals."""
    sc, iso, med, _ = _model()
    norm = synthetic_baseline(n, seed)
    out = synthetic_baseline(outliers, seed + 1)
    out["packets"] *= 15
    out["bytes"] *= 20
    out["pps"] *= 15
    pred = lambda d: (iso.predict(sc.transform(_x(d, med))) == -1)
    return dict(false_positive_rate=float(pred(norm).mean()), detection_rate=float(pred(out).mean()), n_normal=n, n_outliers=outliers)

"""Step 3 - Train Falcon f[0] templates from a LEARN .trs.

Method (from the POI/N/model sweep):
  1. POIs   pick N_POI samples by |correlation with the leak model| (Hamming
            weight of the decode value for leak1, or of the mod-q negate for
            leak2), spaced >= MIN_SPACING apart. ~80 POIs is the sweet spot -
            f[0] leaks at several points, not just the one decode peak, so 80
            POIs (≈99%) beats 20 (≈85%).
  2. NORM   z-score each POI.
  3. FIT    two linear classifiers on the POI features and save both as (W, b):
              LDA    - per-class mean + pooled covariance
              LogReg - multinomial logistic regression (if scikit-learn present)
            prediction is argmax(W @ z + b) for either.
Streaming (two passes) so it handles 200k-sample traces without loading them all.

Run:  python falcon_train_template.py LEARN.trs [templates.npz] [hw32|hwmodq]
"""
import os
import sys

import numpy as np
import trsfile

_HERE       = os.path.dirname(os.path.abspath(__file__))
LEARN_TRS   = "C:/Users/mervkara/Inspector/data/falcon_gui_split_leak1/split_LEARN.trs"
OUT_NPZ     = os.path.join(_HERE, "templates.npz")   # write next to the script, where attack reads it
POI_MODEL   = "hw32"   # hw32 = leak1 (decode) | hwmodq = leak2
N_POI       = 80
MIN_SPACING = 5


def read_class(p):
    if "f0_class" in p:
        return int(p["f0_class"].value[0])
    if "f0" in p:
        b = bytes(p["f0"].value)[0]
        return (b - 256 if b >= 128 else b) + 10
    raise KeyError("trace has neither 'f0_class' nor 'f0'")


def leak_model(f0):
    """HW of the decode value (hw32) or of the two's-complement negate (hwmodq)."""
    return bin(f0 & 0xFFFFFFFF).count("1") if POI_MODEL == "hw32" else bin((-f0) & 0xFFFFFFFF).count("1")


def main():
    # ---- pass 1: streaming correlation with the leak model -> POIs ----
    with trsfile.trs_open(LEARN_TRS, "r") as ts:
        n = len(ts); ns = len(np.asarray(ts[0].samples))
        sx = np.zeros(ns); sxx = np.zeros(ns); sxm = np.zeros(ns); sm = smm = 0.0
        for i in range(n):
            x = np.asarray(ts[i].samples, np.float64)
            m = float(leak_model(read_class(ts[i].parameters) - 10))
            sx += x; sxx += x * x; sxm += x * m; sm += m; smm += m * m
            if (i + 1) % 3000 == 0:
                print(f"  pass1 {i+1}/{n}")
    mx = sx / n; vx = sxx / n - mx * mx
    cxm = sxm / n - mx * (sm / n); vm = smm / n - (sm / n) ** 2
    corr = cxm / (np.sqrt(np.abs(vx * vm)) + 1e-9)
    a = np.abs(corr).copy(); pois = []
    while len(pois) < N_POI and a.max() > 0:
        p = int(a.argmax()); pois.append(p)
        a[max(0, p - MIN_SPACING):p + MIN_SPACING + 1] = 0
    pois = np.sort(pois)
    print(f"selected {len(pois)} POIs ({POI_MODEL}); span {pois.min()}..{pois.max()}")

    # ---- pass 2: extract POI columns -> fit ----
    P = np.asarray(pois)
    with trsfile.trs_open(LEARN_TRS, "r") as ts:
        F = np.empty((n, len(P)), np.float32); y = np.empty(n, np.int64)
        for i in range(n):
            F[i] = np.asarray(ts[i].samples)[P]; y[i] = read_class(ts[i].parameters)
            if (i + 1) % 3000 == 0:
                print(f"  pass2 {i+1}/{n}")
    classes = np.unique(y)
    mu = F.mean(0); sd = F.std(0) + 1e-9; Z = (F - mu) / sd

    # LDA -> (W, b)
    mus = np.array([Z[y == c].mean(0) for c in classes])
    cov = np.zeros((len(P), len(P)))
    for k, c in enumerate(classes):
        d = Z[y == c] - mus[k]; cov += d.T @ d
    cov /= (n - len(classes)); Si = np.linalg.pinv(cov)
    W_lda = mus @ Si; b_lda = -0.5 * np.einsum("cj,jk,ck->c", mus, Si, mus)
    out = dict(pois=pois, classes=classes, mu=mu, sd=sd, cmean=mus, cov=cov,
               W_lda=W_lda, b_lda=b_lda, model=POI_MODEL)

    # LogReg -> (W, b)
    try:
        from sklearn.linear_model import LogisticRegression
        lr = LogisticRegression(max_iter=800, C=1.0).fit(Z, y)
        W_lr = np.zeros((len(classes), len(P))); b_lr = np.zeros(len(classes))
        for j, c in enumerate(lr.classes_):
            k = int(np.where(classes == c)[0][0]); W_lr[k] = lr.coef_[j]; b_lr[k] = lr.intercept_[j]
        out["W_lr"] = W_lr; out["b_lr"] = b_lr
        print("fitted LogReg")
    except Exception as e:
        print("LogReg skipped (no scikit-learn?):", e)

    np.savez(OUT_NPZ, **out)
    print(f"saved {OUT_NPZ}  ({len(classes)} classes, {len(P)} POIs, models: "
          f"LDA{' + LogReg' if 'W_lr' in out else ''})")


if __name__ == "__main__":
    main()

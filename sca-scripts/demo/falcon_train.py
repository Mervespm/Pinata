"""Step 2 - TRAIN the template from the profiling capture.

POIs by |correlation with the leak model| (Hamming weight of the sign-extended
decode value, leak1) spaced >= MIN_SPACING apart; then an LDA (per-class mean +
pooled covariance) and, if scikit-learn is present, a LogReg - both saved as a
linear model (W, b) where prediction is argmax(W @ z + b).

Reports a held-out accuracy so you can see the template's quality on THIS
firmware before running the demo, then refits on all traces and saves.

Run:  python falcon_train.py
Out:  demo/templates.npz   (used by falcon_test.py)
"""
import glob
import os
import sys

import numpy as np
import trsfile

_HERE = os.path.dirname(os.path.abspath(__file__))
PROFILE = sys.argv[1] if len(sys.argv) > 1 else "C:/Users/mervkara/Inspector/data/demo/demo_profile.trs"
OUT_NPZ = os.path.join(_HERE, "templates.npz")
N_POI, MIN_SPACING = 80, 5


def resolve(path):
    """Inspector may write ~name.trs / ~name(2).trs when the target exists.
    Use the exact file if present, else the newest matching temp variant."""
    if os.path.exists(path):
        return path
    d, base = os.path.dirname(path), os.path.basename(path)[:-4]
    cand = glob.glob(os.path.join(d, "~" + base + "*.trs"))
    if not cand:
        raise SystemExit(f"profiling file not found: {path}\n  (run falcon_profile_capture.py first)")
    newest = max(cand, key=os.path.getmtime)
    print(f"using {os.path.basename(newest)} (Inspector temp name)")
    return newest


def read_class(p):
    return int(p["f0_class"].value[0])


def hw(v):
    return bin(v & 0xFFFFFFFF).count("1")     # HW of sign-extended decode value (leak1)


def main():
    path = resolve(PROFILE)

    # ---- pass 1: streaming correlation with the leak model -> POIs ----
    with trsfile.trs_open(path, "r") as ts:
        n = len(ts); ns = len(np.asarray(ts[0].samples))
        sx = np.zeros(ns); sxx = np.zeros(ns); sxm = np.zeros(ns); sm = smm = 0.0
        for i in range(n):
            x = np.asarray(ts[i].samples, np.float64)
            m = float(hw(read_class(ts[i].parameters) - 10))
            sx += x; sxx += x * x; sxm += x * m; sm += m; smm += m * m
            if (i + 1) % 1000 == 0:
                print(f"  pass1 {i + 1}/{n}")
    mx = sx / n; vx = sxx / n - mx * mx
    cxm = sxm / n - mx * (sm / n); vm = smm / n - (sm / n) ** 2
    corr = cxm / (np.sqrt(np.abs(vx * vm)) + 1e-9)
    a = np.abs(corr).copy(); pois = []
    while len(pois) < N_POI and a.max() > 0:
        p = int(a.argmax()); pois.append(p)
        a[max(0, p - MIN_SPACING):p + MIN_SPACING + 1] = 0
    pois = np.sort(pois)
    print(f"selected {len(pois)} POIs; span {pois.min()}..{pois.max()}, peak |corr|={np.abs(corr).max():.3f}")

    # ---- pass 2: load POI features (n x 80) + labels ----
    with trsfile.trs_open(path, "r") as ts:
        F = np.empty((n, len(pois)), np.float32); y = np.empty(n, np.int64)
        for i in range(n):
            F[i] = np.asarray(ts[i].samples)[pois]; y[i] = read_class(ts[i].parameters)
    classes = np.unique(y)

    def fit_lda(Ftr, ytr):
        mu = Ftr.mean(0); sd = Ftr.std(0) + 1e-9; Z = (Ftr - mu) / sd
        mus = np.array([Z[ytr == c].mean(0) for c in classes])
        cov = np.zeros((len(pois),) * 2)
        for k, c in enumerate(classes):
            d = Z[ytr == c] - mus[k]; cov += d.T @ d
        cov /= max(1, len(ytr) - len(classes)); Si = np.linalg.pinv(cov)
        W = mus @ Si; b = -0.5 * np.einsum("cj,jk,ck->c", mus, Si, mus)
        return mu, sd, mus, cov, W, b

    # ---- held-out check (80/20) ----
    rng = np.random.default_rng(0); perm = rng.permutation(n); cut = int(0.8 * n)
    tr, te = perm[:cut], perm[cut:]
    mu, sd, _, _, W, b = fit_lda(F[tr], y[tr])
    Zte = (F[te] - mu) / sd
    single = 100 * np.mean(classes[(Zte @ W.T + b).argmax(1)] == y[te])
    acc = []
    for c in classes:                       # accumulated (all same-class test traces averaged)
        m = y[te] == c
        if m.sum():
            acc.append(classes[(Zte[m] @ W.T + b).sum(0).argmax()] == c)
    print(f"held-out: single-trace {single:.1f}%  |  accumulated {100 * np.mean(acc):.1f}%  "
          f"({len(te)} test traces)")

    # ---- refit on everything and save ----
    mu, sd, mus, cov, W, b = fit_lda(F, y)
    out = dict(pois=pois, classes=classes, mu=mu, sd=sd, cmean=mus, cov=cov,
               W_lda=W, b_lda=b, model="hw32")
    try:
        from sklearn.linear_model import LogisticRegression
        Z = (F - mu) / sd
        lr = LogisticRegression(max_iter=800).fit(Z, y)
        W_lr = np.zeros((len(classes), len(pois))); b_lr = np.zeros(len(classes))
        for j, c in enumerate(lr.classes_):
            k = int(np.where(classes == c)[0][0]); W_lr[k] = lr.coef_[j]; b_lr[k] = lr.intercept_[j]
        out["W_lr"] = W_lr; out["b_lr"] = b_lr
    except Exception as e:
        print("LogReg skipped:", e)
    np.savez(OUT_NPZ, **out)
    print(f"saved {OUT_NPZ}  ({len(classes)} classes, {len(pois)} POIs)")
    print("next:  python falcon_demo_capture.py   then   python falcon_test.py <demo.trs>")


if __name__ == "__main__":
    main()

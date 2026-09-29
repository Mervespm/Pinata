"""Step 4 - TEST: recover f[0] from a demo capture using the fresh template.

Applies demo/templates.npz (trained on THIS firmware by falcon_train.py) to the
traces in a demo .trs, and reports the recovered f[0]. If the traces carry a
true f0_class label it also prints SUCCESS/FAIL.

Run:  python falcon_test.py <demo.trs>
      python falcon_test.py            (auto-uses the newest demo_v2*.trs)
"""
import glob
import os
import sys

import numpy as np
import trsfile

_HERE = os.path.dirname(os.path.abspath(__file__))
TEMPL = os.path.join(_HERE, "templates.npz")
DEMO_DIR = "C:/Users/mervkara/Inspector/data/demo"


def newest(pattern):
    c = glob.glob(pattern)
    if not c:
        raise SystemExit(f"no file matches {pattern}")
    return max(c, key=os.path.getmtime)


def main():
    if not os.path.exists(TEMPL):
        raise SystemExit("templates.npz not found - run falcon_train.py first")
    trs = sys.argv[1] if len(sys.argv) > 1 else newest(os.path.join(DEMO_DIR, "*demo_v2*.trs"))
    print("template:", os.path.basename(TEMPL))
    print("traces:  ", os.path.basename(trs))

    T = np.load(TEMPL)
    pois, classes, mu, sd, W, b = T["pois"], T["classes"], T["mu"], T["sd"], T["W_lda"], T["b_lda"]

    X, truth = [], []
    with trsfile.trs_open(trs, "r") as ts:
        for i in range(len(ts)):
            X.append(np.asarray(ts[i].samples)[pois])
            p = ts[i].parameters
            if "f0_class" in p:
                truth.append(int(p["f0_class"].value[0]) - 10)
    Z = (np.asarray(X, float) - mu) / sd
    score = (Z @ W.T + b).sum(0)               # accumulate over all traces of the one key
    pred = int(classes[score.argmax()]) - 10

    top = np.argsort(score)[::-1][:3]
    print("\ntop-3:", [(int(classes[k]) - 10, round(float(score[k]), 1)) for k in top])
    if truth:
        t = truth[0]
        print(f"\nRecovered from {len(X)} traces:  f[0] = {pred:+d}   "
              f"(true {t:+d})   [{'SUCCESS' if pred == t else 'FAIL'}]")
    else:
        print(f"\nRecovered from {len(X)} traces:  f[0] = {pred:+d}")


if __name__ == "__main__":
    main()

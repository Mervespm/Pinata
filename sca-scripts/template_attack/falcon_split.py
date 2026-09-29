"""Split a captured Falcon .trs into a LEARN set and a TEST set.

Stratified by f0_class (equal fraction held out from every class) so that
template TRAINING (LEARN) and attack EVALUATION (TEST) use disjoint traces -
never test on a trace you trained on. Deterministic given the seed.

Usage:
  python falcon_split.py INPUT.trs                       # -> INPUT_LEARN.trs, INPUT_TEST.trs (20% test)
  python falcon_split.py INPUT.trs LEARN.trs TEST.trs    # custom names
  python falcon_split.py INPUT.trs LEARN.trs TEST.trs 0.3   # 30% test
"""
import collections
import random
import sys

import trsfile


def split(src_path, learn_path, test_path, test_frac=0.2, seed=0):
    rng = random.Random(seed)
    with trsfile.trs_open(src_path, "r") as src:
        n = len(src)

        # 1) group trace indices by class
        buckets = collections.defaultdict(list)
        for i in range(n):
            c = int(src[i].parameters["f0_class"].value[0])
            buckets[c].append(i)

        # 2) hold out test_frac of EACH class for the test set
        test_idx = set()
        for c, idxs in buckets.items():
            rng.shuffle(idxs)
            k = int(round(len(idxs) * test_frac))
            test_idx.update(idxs[:k])

        # 3) write the two sets
        with trsfile.trs_open(learn_path, "w") as L, trsfile.trs_open(test_path, "w") as T:
            nl = nt = 0
            for i in range(n):
                if i in test_idx:
                    T.append(src[i]); nt += 1
                else:
                    L.append(src[i]); nl += 1
                if (i + 1) % 2000 == 0:
                    print(f"  {i+1}/{n}")
    print(f"done: LEARN={nl} traces -> {learn_path}")
    print(f"      TEST ={nt} traces -> {test_path}")
    print(f"      {len(buckets)} classes, ~{nt//max(len(buckets),1)} test traces/class")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    src = sys.argv[1]
    learn = sys.argv[2] if len(sys.argv) > 2 else src.replace(".trs", "_LEARN.trs")
    test = sys.argv[3] if len(sys.argv) > 3 else src.replace(".trs", "_TEST.trs")
    frac = float(sys.argv[4]) if len(sys.argv) > 4 else 0.2
    split(src, learn, test, frac)

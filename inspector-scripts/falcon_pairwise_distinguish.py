"""Pairwise distinguishability sweep for Falcon's f[0] template attack.

falcon_template_attack.py answers "how well can we classify f[0] among ALL
18 usable values at once" (currently ~15%, since many values sit close
together in the HW32 leakage model and are genuinely hard to tell apart).
This script instead asks, for every PAIR of f[0] values: "if it were only
these two, how separable are they?" - which is the more useful question
for understanding WHERE the leakage model is strong vs. weak, and it's
what actually explains that 15% number (it's an average over many easy
pairs and many hard ones).

Reuses the same POIs found in falcon_template_attack.py (fixed once from
all usable classes, not re-searched per pair - keeps every pair's number
directly comparable) and just refits/evaluates a 2-class template at those
POIs for each pair via k-fold cross-validation.

Usage:
    python falcon_pairwise_distinguish.py [PROFILE_DIR] [N_POIS] [TOP_N]
"""
import itertools
import sys

import numpy as np

import falcon_template_attack as fta


def pair_accuracy(traces, f0s, pois, c1, c2, n_folds):
    mask = np.isin(f0s, [c1, c2])
    t, y = traces[mask], f0s[mask]
    n = len(y)
    folds = fta.kfold_indices(n, n_folds)
    correct = 0
    total = 0
    for k in range(n_folds):
        test_idx = folds[k]
        train_idx = np.concatenate([folds[j] for j in range(n_folds) if j != k])
        train_y = y[train_idx]
        train_classes = [c for c in (c1, c2) if (train_y == c).sum() >= 2]
        if len(train_classes) < 2:
            continue
        means, cov = fta.fit_templates(t[train_idx], train_y, pois, train_classes)
        for i in test_idx:
            true_c = int(y[i])
            if true_c not in train_classes:
                continue
            pred_c, _ = fta.classify(t[i], pois, means, cov)
            correct += int(pred_c == true_c)
            total += 1
    return correct / total if total else float("nan"), total


def main():
    profile_dir = sys.argv[1] if len(sys.argv) > 1 else fta.DEFAULT_DIR
    n_pois = int(sys.argv[2]) if len(sys.argv) > 2 else fta.N_POIS_DEFAULT
    top_n = int(sys.argv[3]) if len(sys.argv) > 3 else 15

    traces, f0s = fta.load_profile(profile_dir)
    counts = {int(c): int((f0s == c).sum()) for c in sorted(set(f0s.tolist()))}
    classes = sorted(c for c, n in counts.items() if n >= fta.MIN_CLASS_COUNT)
    print(f"Loaded {len(traces)} traces, {len(classes)} usable classes: {classes}\n")

    mask = np.isin(f0s, classes)
    traces_u, f0s_u = traces[mask], f0s[mask]
    pois, corr = fta.find_pois(traces_u, f0s_u, n_pois, fta.POI_MIN_SPACING)
    print(f"POIs (fixed for every pair below): {pois}\n")

    results = []
    for c1, c2 in itertools.combinations(classes, 2):
        n_folds = max(2, min(5, min(counts[c1], counts[c2]) // 2))
        acc, n_eval = pair_accuracy(traces_u, f0s_u, pois, c1, c2, n_folds)
        hw_dist = abs(fta.hw32(c1) - fta.hw32(c2))
        results.append((acc, c1, c2, hw_dist, n_eval))

    results.sort(key=lambda r: r[0], reverse=True)

    print(f"{'f[0] pair':<12}{'HW32 dist':<11}{'accuracy':<10}{'n traces':<10}")
    print("-" * 43)
    print(f"Easiest {top_n} pairs to tell apart:")
    for acc, c1, c2, hw_dist, n_eval in results[:top_n]:
        print(f"  {c1:>3} vs {c2:<3}   {hw_dist:<11}{acc:<10.1%}{n_eval}")

    print(f"\nHardest {top_n} pairs to tell apart:")
    for acc, c1, c2, hw_dist, n_eval in results[-top_n:]:
        print(f"  {c1:>3} vs {c2:<3}   {hw_dist:<11}{acc:<10.1%}{n_eval}")

    accs = np.array([r[0] for r in results])
    dists = np.array([r[3] for r in results], dtype=np.float64)
    valid = ~np.isnan(accs)
    r = np.corrcoef(accs[valid], dists[valid])[0, 1]
    print(f"\nCorrelation(accuracy, |HW32 distance|) across all {valid.sum()} pairs: {r:.3f}")
    print("(positive = pairs further apart in the leakage model are easier to tell apart, as expected)")


if __name__ == "__main__":
    main()

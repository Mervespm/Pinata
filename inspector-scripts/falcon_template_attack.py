"""Profiled (template) attack on Falcon's f[0] secret-key coefficient.

This is NOT a CPA/DPA attack: f[0] is decoded straight out of the secret
key with no public/known input varying under a fixed secret (the classic
"fixed secret + known varying plaintext" structure CPA needs), and every
profiling trace comes from an independent key. So instead:

  1. POI-finding: correlate a known leakage model against power, using the
     TRUE f[0] value from many independent profiling keys. The model is the
     Hamming weight of the 32-bit two's-complement sign-extension of f[0] -
     that's the actual register value trim_i8_decode() holds right before
     truncating to int8 (Cortex-M4 registers are 32-bit), so it - not the
     8-bit truncated value - is what should track switching-activity power.

  2. Per-class Gaussian templates at those POIs, one per observed f[0]
     value, built with a single shared ("pooled") covariance matrix rather
     than a separate covariance per class. Falcon's Gaussian key sampling
     means the tails (f[0] near +-14) have very few profiling traces even
     at full scale - too few to estimate their own stable covariance -
     while a pooled covariance estimated across all classes' residuals
     stays well-conditioned.

  3. Classification: score a trace against every class's template via the
     multivariate Gaussian log-likelihood and take the argmax.

Evaluated here via k-fold cross-validation on the profiling set itself (no
separate held-out "attack" trace set exists yet) - this measures how well
the profile explains held-out draws from the same profiling process, which
is the right sanity check before ever pointing this at a genuinely unknown
key.

Usage:
    python falcon_template_attack.py [PROFILE_DIR] [N_POIS] [N_FOLDS] [CLASSES]

CLASSES is an optional comma-separated list of f[0] values to restrict the
attack to, e.g. "0,7" - useful for isolating how separable a specific pair
(or small group) of classes is, rather than always fighting the full
18-way problem. Omit it to use every class with enough profiling traces,
as before.
"""
import glob
import os
import sys

import numpy as np
from scipy.stats import multivariate_normal

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DIR = os.path.join(HERE, "falcon_captures", "f_only_profile_falcon_profile_keys")

MIN_CLASS_COUNT = 5     # classes with fewer profiling traces than this are excluded
N_POIS_DEFAULT = 5
POI_MIN_SPACING = 5      # samples - don't pick two POIs off the same correlation peak
N_FOLDS_DEFAULT = 5


def hw32(f0):
    """Hamming weight of the 32-bit two's-complement sign-extension of an
    int8 f[0] value (Python's & on a negative int already gives the correct
    two's-complement bit pattern)."""
    return bin(int(f0) & 0xFFFFFFFF).count("1")


def load_profile(profile_dir):
    trace_files = sorted(glob.glob(os.path.join(profile_dir, "trace_*.npy")))
    traces, f0s = [], []
    for tf in trace_files:
        idx = os.path.basename(tf)[len("trace_"):-len(".npy")]
        ft = os.path.join(profile_dir, f"f_true_{idx}.npy")
        if not os.path.exists(ft):
            continue
        traces.append(np.load(tf))
        f0s.append(int(np.load(ft)[0]))
    return np.array(traces), np.array(f0s, dtype=np.int64)


def find_pois(traces, f0s, n_pois, min_spacing):
    model = np.array([hw32(v) for v in f0s], dtype=np.float64)
    model -= model.mean()
    X = traces - traces.mean(axis=0, keepdims=True)
    num = X.T @ model
    denom = np.sqrt((X ** 2).sum(axis=0)) * np.sqrt((model ** 2).sum()) + 1e-12
    corr = num / denom

    pois = []
    abs_corr = np.abs(corr).copy()
    n_samples = traces.shape[1]
    while len(pois) < n_pois and abs_corr.max() > 0:
        p = int(np.argmax(abs_corr))
        pois.append(p)
        lo, hi = max(0, p - min_spacing), min(n_samples, p + min_spacing + 1)
        abs_corr[lo:hi] = 0
    return sorted(pois), corr


def fit_templates(traces, f0s, pois, classes):
    """Per-class mean at the POIs + one pooled (shared) covariance matrix."""
    X = traces[:, pois]
    means = {}
    residuals = []
    for c in classes:
        Xc = X[f0s == c]
        mu = Xc.mean(axis=0)
        means[c] = mu
        residuals.append(Xc - mu)
    residuals = np.vstack(residuals)
    cov = np.cov(residuals, rowvar=False)
    if cov.ndim == 0:
        cov = np.array([[cov]])
    # Small ridge for numerical safety, not because this is expected to be
    # singular (far more pooled traces than POIs here).
    cov += np.eye(len(pois)) * 1e-6 * np.trace(cov) / len(pois)
    return means, cov


def classify(trace, pois, means, cov):
    x = trace[pois]
    lls = {c: multivariate_normal.logpdf(x, mean=mu, cov=cov) for c, mu in means.items()}
    best_c = max(lls, key=lls.get)
    return best_c, lls


def kfold_indices(n, k, seed=0):
    rng = np.random.default_rng(seed)
    idx = rng.permutation(n)
    return np.array_split(idx, k)


def main():
    profile_dir = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DIR
    n_pois = int(sys.argv[2]) if len(sys.argv) > 2 else N_POIS_DEFAULT
    n_folds = int(sys.argv[3]) if len(sys.argv) > 3 else N_FOLDS_DEFAULT
    classes_arg = sys.argv[4] if len(sys.argv) > 4 else None

    traces, f0s = load_profile(profile_dir)
    print(f"Loaded {len(traces)} traces from {profile_dir}")

    counts = {int(c): int((f0s == c).sum()) for c in sorted(set(f0s.tolist()))}
    print("f[0] class counts:", counts)

    if classes_arg is not None:
        requested = [int(c) for c in classes_arg.split(",")]
        classes = [c for c in requested if counts.get(c, 0) >= 2]
        skipped = [c for c in requested if c not in classes]
        print(f"\nRestricted to requested classes: {classes}")
        if skipped:
            print(f"Skipped (fewer than 2 profiling traces, can't build/evaluate a template): {skipped}")
    else:
        classes = sorted(c for c, n in counts.items() if n >= MIN_CLASS_COUNT)
        excluded = sorted(c for c, n in counts.items() if n < MIN_CLASS_COUNT)
        print(f"\nUsing {len(classes)} classes with >= {MIN_CLASS_COUNT} traces: {classes}")
        if excluded:
            print(f"Excluded (too few traces so far - will be included as capture grows): {excluded}")

    print(f"HW32(f[0]) leakage-model value per class: "
          f"{ {c: hw32(c) for c in classes} }")

    mask = np.isin(f0s, classes)
    traces_u, f0s_u = traces[mask], f0s[mask]

    pois, corr = find_pois(traces_u, f0s_u, n_pois, POI_MIN_SPACING)
    print(f"\nTop {len(pois)} POIs (sample index): {pois}")
    print(f"Correlation at POIs: {[round(float(corr[p]), 4) for p in pois]}")

    n = len(traces_u)
    top1_correct = 0
    true_ranks = []
    folds = kfold_indices(n, n_folds)
    for k in range(n_folds):
        test_idx = folds[k]
        train_idx = np.concatenate([folds[j] for j in range(n_folds) if j != k])

        train_f0 = f0s_u[train_idx]
        train_classes = sorted(c for c in classes if (train_f0 == c).sum() >= 2)
        means, cov = fit_templates(traces_u[train_idx], train_f0, pois, train_classes)

        for i in test_idx:
            true_c = int(f0s_u[i])
            if true_c not in train_classes:
                continue  # too rare to have survived this fold's training split
            pred_c, lls = classify(traces_u[i], pois, means, cov)
            if pred_c == true_c:
                top1_correct += 1
            ranked = sorted(lls, key=lls.get, reverse=True)
            true_ranks.append(ranked.index(true_c) + 1)

    n_evaluated = len(true_ranks)
    print(f"\n{n_folds}-fold cross-validation over {n_evaluated} held-out traces:")
    print(f"  Top-1 accuracy: {top1_correct / n_evaluated:.1%}  "
          f"(random-guess baseline: {1 / len(classes):.1%})")
    print(f"  Mean rank of true value: {np.mean(true_ranks):.2f} / {len(classes)} classes")
    print(f"  Median rank: {np.median(true_ranks):.0f}")

    # Fit final templates on ALL usable data and save for classifying
    # genuinely unknown (attack) traces later.
    means, cov = fit_templates(traces_u, f0s_u, pois, classes)
    tag = "_".join(str(c) for c in classes) if classes_arg is not None else "all"
    out_path = os.path.join(profile_dir, f"templates_{tag}.npz")
    np.savez(out_path,
              pois=np.array(pois), cov=cov,
              classes=np.array(classes),
              means=np.array([means[c] for c in classes]))
    print(f"\nSaved templates -> {out_path}")


if __name__ == "__main__":
    main()

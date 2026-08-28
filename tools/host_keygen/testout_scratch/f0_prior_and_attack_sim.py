"""
Scratch analysis (not part of the shipped pipeline):
1) Derive the REAL f[0] probability distribution directly from the exact
   table fndsa/kgen_gauss.c uses on-device for logn=9 (gauss_512, zz=1 -
   a single direct table draw, no summing needed at this degree).
2) Quantify how much probability mass sits in a "practical" range around 0.
3) Run a from-scratch Top-1 recovery simulation (B/C/D leak points, real
   bit arithmetic from codec.c's trim_i8_decode, linear-in-Hamming-weight
   + Gaussian noise leakage model) comparing a uniform prior vs the real
   one, at a few noise levels.
"""
import math
import random

# Exact table from fndsa/kgen_gauss.c, degree-512 (logn=9), zz=1.
GAUSS_512 = [
    1, 4, 11, 28, 65, 146, 308, 615,
    1164, 2083, 3535, 5692, 8706, 12669, 17574, 23285,
    29542, 35993, 42250, 47961, 52866, 56829, 59843, 62000,
    63452, 64371, 64920, 65227, 65389, 65470, 65507, 65524,
    65531, 65534,
]
KMAX = len(GAUSS_512) // 2  # 17

# PMF over s = j - KMAX, j = 0..2*KMAX, from table differences (as the
# real sampler's count-based construction implies).
cdf = [0] + GAUSS_512 + [65536]
pmf_by_s = {}
for j in range(len(cdf) - 1):
    s = j - KMAX
    pmf_by_s[s] = cdf[j + 1] - cdf[j]
total = sum(pmf_by_s.values())
pmf_by_s = {s: c / total for s, c in pmf_by_s.items()}

print(f"Real f[0] support (this exact on-device table): {min(pmf_by_s)}..{max(pmf_by_s)}"
      f" ({len(pmf_by_s)} values), total mass check = {sum(pmf_by_s.values()):.6f}")

for half_width, label in [(9, "-9..9 (19 values)"), (10, "-10..10 (21 values)"), (17, "full -17..17 (35 values)")]:
    mass = sum(p for s, p in pmf_by_s.items() if abs(s) <= half_width)
    print(f"  mass within {label}: {mass*100:.2f}%")

# --- Leak-point bit arithmetic, straight from codec.c's trim_i8_decode (BITS=6) ---
BITS = 6
MASK1 = (1 << BITS) - 1
MASK2 = 1 << (BITS - 1)  # 0x20
FIELD_VALUES = [w for w in range(1 << BITS) if w != MASK2]  # exclude the one undecodable pattern


def popcount(x, bits):
    return bin(x & ((1 << bits) - 1)).count("1")


def hw_b(w):
    return popcount(w, BITS)


def sign_extended_reg(w):
    if w & MASK2:
        return (w | 0xFFFFFFE0) & 0xFFFFFFFF  # matches w |= -(w & mask2)
    return w


def hw_c(w):
    return popcount(sign_extended_reg(w), 32)


def hw_d(w):
    return popcount(sign_extended_reg(w) & 0xFF, 8)


def w_of_signed(s):
    return s if s >= 0 else s + 64


# Real prior over the 63 decodable field values: mass from GAUSS_512 for
# |s|<=17, a small floor elsewhere (valid encodings the real keygen just
# essentially never produces).
FLOOR = 1e-6
real_prior = {}
for w in FIELD_VALUES:
    s = w if w < 32 else w - 64
    real_prior[w] = pmf_by_s.get(s, FLOOR)
norm = sum(real_prior.values())
real_prior = {w: p / norm for w, p in real_prior.items()}
uniform_prior = {w: 1.0 / len(FIELD_VALUES) for w in FIELD_VALUES}


def run_sim(sigma, n_trials, prior_for_sampling, prior_for_attacker, rng):
    ws = list(prior_for_sampling.keys())
    weights = list(prior_for_sampling.values())
    correct = 0
    for _ in range(n_trials):
        w0 = rng.choices(ws, weights=weights, k=1)[0]
        mb = hw_b(w0) + rng.gauss(0, sigma)
        mc = hw_c(w0) + rng.gauss(0, sigma)
        md = hw_d(w0) + rng.gauss(0, sigma)
        best_w, best_score = None, -math.inf
        for w in FIELD_VALUES:
            score = (
                -((mb - hw_b(w)) ** 2 + (mc - hw_c(w)) ** 2 + (md - hw_d(w)) ** 2) / (2 * sigma * sigma)
                + math.log(prior_for_attacker[w])
            )
            if score > best_score:
                best_score, best_w = score, w
        if best_w == w0:
            correct += 1
    return correct / n_trials


rng = random.Random(42)
print("\nTop-1 accuracy for f[0], ground truth drawn from the REAL distribution,")
print("attacker uses the matching real prior vs (for comparison) a uniform prior:")
print(f"{'sigma':>6} | {'real prior':>10} | {'uniform prior':>13}")
for sigma in [0.5, 1.0, 1.5, 2.0, 3.0, 4.0]:
    acc_real = run_sim(sigma, 4000, real_prior, real_prior, rng)
    acc_unif = run_sim(sigma, 4000, real_prior, uniform_prior, rng)
    print(f"{sigma:>6.1f} | {acc_real*100:>9.2f}% | {acc_unif*100:>12.2f}%")

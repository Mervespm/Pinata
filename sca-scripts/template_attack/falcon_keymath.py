"""Falcon-512 key math: public-key decode, h = g/f, and linear key completion.

Two parts, tightly coupled (completion reuses the codec's matrix machinery):

1. Codec / h:
   - mqpoly_decode_py(pk_bytes) - unpack h from the public key (14 bits/coef,
     matches codec.c's mqpoly_decode).
   - compute_h_py(f, g)         - h = g/f mod q via the negacyclic convolution
     matrix of f (O(n^3) reference, same result as the firmware's fast NTT).

2. Completion (analogue of the Dilithium paper's Variant 1): given a
   confidence-ranked partial recovery of f and g (>= n=512 combined
   coefficients known), solve H*f - g = 0 for the rest exactly, where H is the
   negacyclic matrix of the PUBLIC h (fully known from pk - no t0-style
   reconstruction needed).

Run: python falcon_keymath.py   (validates h decode, then tests the solver)
"""
import json
import os
import sys

import numpy as np

Q = 12289
N = 512
HEADER_LOGN = 9


# --------------------------------------------------------------------------
# Codec / h
# --------------------------------------------------------------------------
def mqpoly_decode_py(pk_bytes):
    """Exact port of codec.c's mqpoly_decode. pk_bytes must be the 896-byte
    payload (header byte already stripped)."""
    d = pk_bytes
    h = np.zeros(N, dtype=np.uint32)
    j = 0
    for i in range(0, N, 4):
        d0, d1, d2, d3, d4, d5, d6 = d[j], d[j+1], d[j+2], d[j+3], d[j+4], d[j+5], d[j+6]
        j += 7
        h0 = ((d0 << 6) | (d1 >> 2)) & 0xFFFFFFFF
        h1 = ((d1 << 12) | (d2 << 4) | (d3 >> 4)) & 0x3FFF
        h2 = ((d3 << 10) | (d4 << 2) | (d5 >> 6)) & 0x3FFF
        h3 = ((d5 << 8) | d6) & 0x3FFF
        h[i], h[i+1], h[i+2], h[i+3] = h0, h1, h2, h3
    if np.any(h >= Q):
        raise ValueError("decoded coefficient >= Q - corrupt pk or wrong offset")
    return h


def negacyclic_matrix(a, q=Q, n=N):
    """n x n matrix M such that (M @ b) mod q == coefficients of a(x)*b(x)
    mod (x^n+1) mod q. x^n = -1 gives the wraparound sign flip."""
    a = np.asarray(a, dtype=np.int64) % q
    M = np.zeros((n, n), dtype=np.int64)
    for i in range(n):
        idx = (i - np.arange(n)) % n
        sign = np.where(np.arange(n) <= i, 1, -1)
        M[i, :] = (a[idx] * sign) % q
    return M % q


def modinv_matrix_gf_q(M, q=Q):
    """Gaussian elimination over GF(q) (q prime) to invert M mod q."""
    n = M.shape[0]
    A = np.concatenate([M.copy() % q, np.eye(n, dtype=np.int64)], axis=1)
    for col in range(n):
        piv = None
        for r in range(col, n):
            if A[r, col] % q != 0:
                piv = r
                break
        if piv is None:
            raise ValueError("matrix singular mod q - f is not invertible")
        A[[col, piv]] = A[[piv, col]]
        inv = pow(int(A[col, col]), q - 2, q)  # Fermat's little theorem, q prime
        A[col, :] = (A[col, :] * inv) % q
        for r in range(n):
            if r != col and A[r, col] != 0:
                factor = A[r, col]
                A[r, :] = (A[r, :] - factor * A[col, :]) % q
    return A[:, n:] % q


def compute_h_py(f, g, q=Q, n=N):
    """h = g * f^-1 mod q, mod (x^n+1), via direct negacyclic-matrix solve."""
    Mf = negacyclic_matrix(f, q, n)
    Mf_inv = modinv_matrix_gf_q(Mf, q)
    g_vec = np.asarray(g, dtype=np.int64) % q
    return ((Mf_inv @ g_vec) % q).astype(np.uint32)


def load_keyset(prefix):
    with open(prefix + ".meta.json") as fh:
        meta = json.load(fh)
    rs, nk, fields = meta["record_size"], meta["num_keys"], meta["fields"]
    with open(prefix + ".bin", "rb") as fh:
        data = fh.read()
    keys = []
    for i in range(nk):
        base = i * rs
        def field(name, base=base):
            spec = fields[name]
            return data[base + spec["offset"]: base + spec["offset"] + spec["size"]]
        keys.append({"pk": field("pk"), "f": field("f"), "g": field("g")})
    return keys


# --------------------------------------------------------------------------
# Completion
# --------------------------------------------------------------------------
def solve_completion(h, known_f, known_g, q=Q, n=N):
    """known_f, known_g: dict {index: value} of HIGH-CONFIDENCE recovered
    coefficients (signed range). Returns (f_full, g_full) if the system has a
    unique solution; raises if under-determined or inconsistent."""
    H = negacyclic_matrix(h, q, n)
    unk_f = [i for i in range(n) if i not in known_f]
    unk_g = [i for i in range(n) if i not in known_g]
    n_unknown = len(unk_f) + len(unk_g)
    if n_unknown > n:
        raise ValueError(
            f"under-determined: {n_unknown} unknowns > {n} equations "
            f"(need >= {n} combined known coefficients, have {2*n - n_unknown})")

    # Row i: sum_j H[i,j]*f[j] - g[i] = 0; move known terms to the RHS.
    rhs = np.zeros(n, dtype=np.int64)
    for j, v in known_f.items():
        rhs -= (H[:, j] * (v % q)) % q
    for i, v in known_g.items():
        rhs[i] += v % q
    rhs %= q

    # Coefficient matrix over the unknowns: [H[:,unk_f] | -I[:,unk_g]]
    A = np.zeros((n, n_unknown), dtype=np.int64)
    A[:, :len(unk_f)] = H[:, unk_f]
    for k, i in enumerate(unk_g):
        A[i, len(unk_f) + k] = (-1) % q
    A %= q

    x = solve_linear_gf_q_rect(A, rhs, q)

    f_full = np.zeros(n, dtype=np.int64)
    g_full = np.zeros(n, dtype=np.int64)
    for j, v in known_f.items():
        f_full[j] = v % q
    for i, v in known_g.items():
        g_full[i] = v % q
    for k, j in enumerate(unk_f):
        f_full[j] = x[k]
    for k, i in enumerate(unk_g):
        g_full[i] = x[len(unk_f) + k]
    return f_full, g_full


def solve_linear_gf_q_rect(A, b, q=Q):
    """Solve A x = b over GF(q) (q prime), A is (n_rows x n_cols) with
    n_rows >= n_cols. Picks each column's pivot from any unused row, so
    extra/redundant rows are skipped rather than pre-selected."""
    n_rows, n_cols = A.shape
    M = np.concatenate([A.copy() % q, (b % q).reshape(-1, 1)], axis=1)
    used_rows = set()
    pivot_row_for_col = {}
    for col in range(n_cols):
        piv = None
        for r in range(n_rows):
            if r not in used_rows and M[r, col] % q != 0:
                piv = r
                break
        if piv is None:
            raise ValueError(
                f"column {col} has no available pivot - system is rank-deficient "
                f"(need more/different known coefficients, not just more rows)")
        used_rows.add(piv)
        pivot_row_for_col[col] = piv
        inv = pow(int(M[piv, col]), q - 2, q)
        M[piv, :] = (M[piv, :] * inv) % q
        for r in range(n_rows):
            if r != piv and M[r, col] != 0:
                M[r, :] = (M[r, :] - M[r, col] * M[piv, :]) % q
    x = np.zeros(n_cols, dtype=np.int64)
    for col in range(n_cols):
        x[col] = M[pivot_row_for_col[col], -1] % q
    return x


def to_signed(v, q=Q):
    """Map a Z_q representative back to the signed small range."""
    v = int(v) % q
    return v - q if v > q // 2 else v


# --------------------------------------------------------------------------
# Self-test: validate h decode, then test the completion solver
# --------------------------------------------------------------------------
def main():
    prefix = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "keys", "falcon_f0_forced_21k")
    keys = load_keyset(prefix)
    print(f"Loaded {len(keys)} keys from {prefix}\n")

    # 1. h decode vs h=g/f, a few keys
    print("== h decode / h=g/f ==")
    ok = 0
    n_check = min(5, len(keys))
    for idx in range(n_check):
        k = keys[idx]
        h_pk = mqpoly_decode_py(k["pk"][1:])
        f = np.frombuffer(k["f"], dtype=np.int8).astype(np.int64)
        g = np.frombuffer(k["g"], dtype=np.int8).astype(np.int64)
        match = np.array_equal(h_pk, compute_h_py(f, g))
        ok += match
        print(f"  key {idx}: {'MATCH (all 512)' if match else 'MISMATCH'}")
    print(f"  {ok}/{n_check} keys match\n")

    # 2. completion solver on one key
    print("== linear completion (300 of f + 220 of g known) ==")
    k = keys[0]
    f_true = np.frombuffer(k["f"], dtype=np.int8).astype(np.int64)
    g_true = np.frombuffer(k["g"], dtype=np.int8).astype(np.int64)
    h = mqpoly_decode_py(k["pk"][1:])
    rng = np.random.default_rng(0)
    known_f = {int(i): int(f_true[i]) for i in rng.choice(N, 300, replace=False)}
    known_g = {int(i): int(g_true[i]) for i in rng.choice(N, 220, replace=False)}
    f_full, g_full = solve_completion(h, known_f, known_g)
    f_ok = np.array_equal([to_signed(v) for v in f_full], f_true)
    g_ok = np.array_equal([to_signed(v) for v in g_full], g_true)
    print(f"  f recovered: {f_ok}   g recovered: {g_ok}")
    print("  PASS" if (ok == n_check and f_ok and g_ok) else "  FAIL")


if __name__ == "__main__":
    main()

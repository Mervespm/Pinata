"""Merge two Inspector .trs trace sets into one (append batch 2 on top of batch 1).

Use this after acquiring a SECOND 21k leak2 batch in Inspector with the SAME
acquisition settings as the first (same 200k-sample window, same 8-bit coding,
same keyset so f0 is 1000 per class). The result is one 42k set = 2000 per f0,
which you can then re-split with prepare_data.split_learn_test().

The two inputs must agree on sample count and sample coding, or Inspector
(and template learning) would choke on the mixed set -- this script checks and
refuses if they differ.

Usage:
  python merge_trs.py BATCH1.trs BATCH2.trs COMBINED.trs
"""
import sys
import trsfile


def merge(path1, path2, out_path):
    with trsfile.trs_open(path1, "r") as a, trsfile.trs_open(path2, "r") as b:
        t0a, t0b = a[0], b[0]
        na, nb = len(t0a.samples), len(t0b.samples)
        if na != nb:
            raise SystemExit(f"REFUSING: sample counts differ ({na} vs {nb}). "
                             "Re-acquire batch 2 with the same window as batch 1.")
        ca, cb = t0a.samples.dtype, t0b.samples.dtype
        if ca != cb:
            raise SystemExit(f"REFUSING: sample dtype differs ({ca} vs {cb}). "
                             "Match the scope resolution / sample coding.")
        keys_a = set(t0a.parameters.keys())
        keys_b = set(t0b.parameters.keys())
        if keys_a != keys_b:
            print(f"[warning] parameter sets differ: only-in-1={keys_a-keys_b}, "
                  f"only-in-2={keys_b-keys_a}. Merging anyway.")

        print(f"batch 1: {len(a)} traces | batch 2: {len(b)} traces | "
              f"{na} samples/trace ({ca})")
        with trsfile.trs_open(out_path, "w") as out:
            for src, label in ((a, "batch1"), (b, "batch2")):
                for i in range(len(src)):
                    out.append(src[i])
                    if (i + 1) % 2000 == 0:
                        print(f"  {label}: {i+1}/{len(src)}")
        print(f"merged -> {out_path}  ({len(a)+len(b)} traces total)")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    merge(sys.argv[1], sys.argv[2], sys.argv[3])

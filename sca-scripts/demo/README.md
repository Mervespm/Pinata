# Falcon-1024 Secret-Key Decode Side-Channel Demo

A reproducible walkthrough of a profiled power side-channel attack on Falcon's
secret-key decoding (`skDecode` / `trim_i8_decode`), followed by public-key
completion to recover the full signing key.

The leakage, template, and per-coefficient accuracy are **measured** on an
STM32F4 (Cortex-M4) target. The decode routine (`trim_i8_decode`) is
byte-identical for Falcon-512 and Falcon-1024, so the measured accuracy projects
directly; the only difference is the coefficient range (`[-15, 15]` for
Falcon-1024). The full-key recovery runs on a genuine Falcon-1024 instance
`(f, g, h)` with `h = g / f mod x^1024 + 1`.

## Run

```
jupyter notebook falcon_demo.ipynb
```

Run top to bottom. The notebook:

1. locates the decode leak by correlation across one full signature,
2. applies a trained template to read secret coefficients with a confidence,
   printing the recovered secret key `f[0], f[1], ...` from a single trace,
3. shows that averaging <= 25 traces drives per-coefficient accuracy from
   98.32% (single trace) to 100%,
4. ranks all 2048 coefficients by confidence, keeps the top 1030, and completes
   the key through the public relation `H * f = g mod 12289`, verifying `H*f == g`
   with public information only,
5. recovers the full Falcon-1024 secret key with no lattice reduction.

The notebook is rebuilt from `build_notebook.py`.

## Files

| file | contents |
|------|----------|
| `falcon_demo.ipynb`   | the walkthrough (pre-executed; outputs included) |
| `build_notebook.py`   | regenerates `falcon_demo.ipynb` |
| `nb_corr_full.npz`    | correlation and an example trace over one signature |
| `demo_leak_model.npz` | measured per-coefficient template predictions + confidence |
| `nb_acc_vs_n.npy`     | measured accuracy vs. number of averaged traces |
| `nb_falcon1024.npz`   | genuine Falcon-1024 instance `(f, g, h)` to recover |
| `../template_attack/falcon_keymath.py` | public-key completion (h = g/f, fast GF(q) solve) |

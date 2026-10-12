# Falcon-512 Secret-Key Decode Side-Channel Demo

A reproducible walkthrough of a profiled power side-channel attack on Falcon's
secret-key decoding (`skDecode` / `trim_i8_decode`), followed by public-key
completion to recover the full signing key. All data is real, measured on an
STM32F4 (Cortex-M4) target.

## Run

```
jupyter notebook falcon_demo.ipynb
```

Run top to bottom. The notebook:

1. locates the decode leak by correlation across one full signature,
2. applies a trained template to read secret coefficients with a confidence,
3. ranks coefficients by confidence and completes the key through the public
   relation `h = g * f^-1 mod q`, verifying by the coefficient range,
4. recovers the full secret key with no lattice reduction.

## Files

| file | contents |
|------|----------|
| `falcon_demo.ipynb`   | the walkthrough (pre-executed; outputs included) |
| `nb_corr_full.npz`    | correlation and an example trace over one signature |
| `demo_leak_model.npz` | measured per-coefficient template predictions + confidence |
| `../template_attack/falcon_keymath.py` | public-key completion (h = g/f, solve) |
| `../template_attack/templates.npz`     | template points of interest |
| `../keys/falcon_f0_forced_demo.*`      | 32 sample Falcon-512 keys |

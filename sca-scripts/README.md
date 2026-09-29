# Falcon-512 Power Side-Channel Attack — Code Package

Recovers the Falcon-512 secret polynomials `f`, `g` from power traces of a
signing STM32F4 "Pinata", then completes the full key via the public NTRU
relation `h = g·f⁻¹ mod q`.

## Folder layout

```
inspector-scripts/
├── capture/            capture power traces
│   ├── falcon_capture.py        traces -> .trs   (PicoScope, EXTERNAL trigger on PC2)
│   ├── falcon_capture_png.py    one trace -> PNG (eyeball where the leak is)
│   └── pico_scope_3000a.py      PicoScope 3000 driver
├── template_attack/    build templates, attack, solve the key
│   ├── falcon_split.py           stratified LEARN / TEST split
│   ├── falcon_train_template.py  POI extraction + templates (LDA)   [leak1 or leak2]
│   ├── falcon_attack.py          single-leak attack (accuracy vs. averaging)
│   ├── falcon_attack_combined.py leak1 + leak2 fused (added log-likelihoods)
│   ├── falcon_crypto3_full.py    the same, via Riscure Inspector / crypto3
│   ├── falcon_keymath.py         h-decode, h=g/f, full-key completion
│   └── merge_trs.py              combine two .trs
├── trace_data/         PNG + .mat trace data and figure outputs
├── reference/          _recovered_falcon_template_attack.py  (original profiling script)
├── keys/               shared key sets (falcon_f0_forced_21k, …)
└── README.md
```

## Pipeline

```
 capture/            template_attack/                                    template_attack/
 ┌─────────┐  .trs   ┌────────┐  ┌──────────────┐  ┌─────────┐  ┌──────────────┐
 │ capture │───────▶ │ split  │─▶│ train (leak1 │─▶│ attack  │─▶│ solve key    │
 │         │         │ L / T  │  │  + leak2)    │  │ combined│  │ h = g·f⁻¹    │
 └─────────┘         └────────┘  └──────────────┘  └─────────┘  └──────────────┘
```

Per-coefficient accuracy alone isn't enough (`0.99^1024 ≈ 0`), so the last step
turns the near-key into the exact key with the public equation.

## Quick run

```bash
cd inspector-scripts

# 1. capture (Pinata connected, firmware flashed)
python capture/falcon_capture.py

# 2. split into learn / test
python template_attack/falcon_split.py "SCA Falcon Pinata Acquisition.trs"

# 3. train templates (run once per leak; give each its own output name)
python template_attack/falcon_train_template.py LEAK1_LEARN.trs templates_leak1.npz
python template_attack/falcon_train_template.py LEAK2_LEARN.trs templates_leak2.npz

# 4a. single-leak attack           4b. combined two-leak attack
python template_attack/falcon_attack.py LEAK1_TEST.trs templates_leak1.npz
python template_attack/falcon_attack_combined.py "LEAK1_TEST*.trs" "LEAK2_TEST*.trs"

# 5. complete the full key from the recovered coefficients
python template_attack/falcon_keymath.py keys/falcon_f0_forced_21k
```

## Method notes

- **Label**: `f0_class = f[0] + 10` (f[0] ∈ −10..+10 → classes 0..20). Loaders accept `f0_class` or a signed `f0`.
- **Templates = LDA**: per-class mean + one pooled covariance, features z-scored (crypto3's "Mean + Cov pooled").
- **Averaging**: averaging N traces of the same key raises accuracy; `falcon_attack.py` sweeps N.
- **Two leaks**: values that collide at the decode POI (same Hamming weight) can separate at the mod-q POI; `falcon_attack_combined.py` adds the two log-likelihoods.
- **Full key**: `falcon_keymath.py` solves `H·f − g = 0` (H = negacyclic matrix of the public `h`) once ≥ n of the 2n coefficients are recovered.

## Requirements

```
python 3.11, numpy, scipy, trsfile, matplotlib, pyserial, picosdk (capture),
python-flint or galois (fast GF(q) solve), riscure.inspector (crypto3 only)
```

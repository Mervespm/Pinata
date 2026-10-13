# Falcon-1024 Single-Trace Attack Demo

A lean, attacker's-eye power side-channel attack on Falcon's secret-key decode,
measured on an STM32F4. Templates are already trained; the notebook runs the
attack:

1. show the victim power trace (`f[0]` is read directly from it),
2. show the decode is a periodic loop,
3. attack one coefficient — score it against every template, rank the candidate
   values, predict with a confidence,
4. repeat for a few coefficients,
5. recover the full key: keep the most-confident reads, solve the public relation
   `H*f = g (mod 12289)` for the rest, and check the result lies in Falcon-1024's
   coefficient bound `[-15, 15]`.

It is a **profiled per-coefficient attack projected across the key**: one
coefficient of the decode is profiled over all values, and the same template is
applied to every coefficient. `f[0]` is read from a **real power trace**; the
full key `(f, g, h)` is a valid Falcon-1024 instance used to demonstrate
recovery of all 1024 coefficients.

## Run

```
jupyter notebook falcon_demo.ipynb
```

Reads real traces from a local Inspector capture (`split_TEST.trs`; path at the
top of the trace-loading cell). Ships **pre-executed**, so it can be read without
the raw traces. Rebuild with `python build_notebook.py`.

## Files

| file | contents |
|------|----------|
| `falcon_demo.ipynb` | the walkthrough (pre-executed) |
| `build_notebook.py` | regenerates the notebook |
| `nb_falcon1024.npz` | the key `(f, g, h)` and the victim trace |
| `../template_attack/templates.npz` | the trained template (one model per value) |
| `../template_attack/falcon_keymath.py` | public-key completion (`H*f = g`, fast GF(q) solve) |

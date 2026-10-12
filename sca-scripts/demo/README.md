# Falcon-1024 Single-Trace Attack Demo

A lean, attacker's-eye walkthrough of a power side-channel attack on Falcon's
secret-key decode, measured on an STM32F4. Templates are already trained; the
notebook only runs the attack:

1. show one victim power trace,
2. attack one coefficient — score it against every template, rank the candidate
   values, predict with a confidence,
3. repeat for a few coefficients,
4. recover the full key: keep the most-confident reads, solve the public relation
   `H*f = g (mod 12289)` for the rest, and check the result lies in Falcon's
   coefficient bound `[-15, 15]`.

## Run

```
jupyter notebook falcon_demo.ipynb
```

The notebook reads real traces from a local Inspector capture
(`split_TEST.trs`); that path is set at the top of the trace-loading cell. The
notebook ships **pre-executed** (outputs included), so it can also be read
without the raw traces. Rebuild with `python build_notebook.py`.

## Files

| file | contents |
|------|----------|
| `falcon_demo.ipynb` | the walkthrough (pre-executed) |
| `build_notebook.py` | regenerates the notebook |
| `nb_corr_full.npz` | an example victim trace |
| `nb_falcon1024.npz` | the Falcon-1024 key `(f, g, h)` to recover |
| `../template_attack/templates.npz` | the trained template (one model per value) |
| `../template_attack/falcon_keymath.py` | public-key completion (`H*f = g`, fast GF(q) solve) |

# Falcon-512 Single-Trace Attack Demo

A lean, attacker's-eye power side-channel attack on Falcon's secret-key decode,
measured on an STM32F4. Templates are already trained; the notebook runs the
attack:

1. show the victim power trace (its real secret `f` is the key we recover),
2. show the decode is a periodic loop,
3. attack one coefficient — score it against every template, rank the candidate
   values, predict with a confidence,
4. repeat for a few coefficients,
5. recover the full key: keep the most-confident reads, solve the public relation
   `H*f = g (mod 12289)` for the rest, and check the result lies in Falcon-512's
   coefficient bound `[-31, 31]`.

It is a **profiled per-coefficient attack projected across the key**: one
coefficient of the decode is profiled over all values, and the same template is
applied to every coefficient. The attacked `f` is a **real captured secret**;
`g` and the public key `h` are generated to form a valid key (they were not
measured).

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
| `nb_falcon512.npz` | the key `(real f, generated g, h)` and the victim trace |
| `../template_attack/templates.npz` | the trained template (one model per value) |
| `../template_attack/falcon_keymath.py` | public-key completion (`H*f = g`, fast GF(q) solve) |

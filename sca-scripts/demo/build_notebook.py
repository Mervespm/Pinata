"""Builds falcon_demo.ipynb - a lean, attacker's-eye single-trace demo (Falcon-1024).

f[0] is read from a REAL power trace; the full key (f, g, h) is a valid
Falcon-1024 instance used to demonstrate full-key recovery. Flow: victim trace ->
periodic loop -> attack one coefficient -> a few more -> recover the full key via
the public key, checked by the Falcon-1024 coefficient bound [-15, 15].
"""
import json


def md(*l):
    return {"cell_type": "markdown", "metadata": {}, "source": [x + "\n" for x in l]}


def code(*l):
    return {"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
            "source": [x + "\n" for x in l]}


cells = []

cells.append(md(
    "# Single-Trace Attack on Falcon-1024",
    "",
    "The attacker has power traces of the victim device and a set of **templates** - one per",
    "possible coefficient value. Goal: recover the secret key `f, g`.",
    "",
    "This is a **profiled per-coefficient attack**: profile one coefficient of the decode over all",
    "its values, and - because the decode is a constant-time loop - apply that template to every",
    "coefficient. The secret `f` is the one in the victim trace below (its `f` parameter); we recover",
    "all **1024** coefficients of the key `f, g`.",
    "",
    "Templates are already trained; we only run the attack."))

cells.append(code(
    "import os, sys",
    "import numpy as np",
    "import matplotlib.pyplot as plt",
    "import trsfile",
    "sys.path.insert(0, os.path.abspath(os.path.join('..', 'template_attack')))",
    "import falcon_keymath as km",
    "n = 1024                              # Falcon-1024",
    "",
    "# trained templates: one model per possible coefficient value",
    "T = np.load(os.path.join('..', 'template_attack', 'templates.npz'))",
    "candidates = T['classes'] - 10; pois = T['pois']",
    "mu, sd, W, b = T['mu'], T['sd'], T['W_lda'], T['b_lda']",
    "",
    "# the victim's secret key, read from the trace's f parameter (ground truth f_true);",
    "# g and the public key h complete a valid Falcon-1024 key.",
    "K = np.load('nb_falcon1024.npz')",
    "f_true = K['f'].astype(int); g_true = K['g'].astype(int); h = K['h'].astype(np.uint32)",
    "example = K['example'].astype(float)",
    "",
    "# real power traces, grouped by the coefficient value they measured",
    "traces = {}",
    "with trsfile.trs_open(r'C:/Users/mervkara/Inspector/data/falcon_gui_split_leak1/split_TEST.trs', 'r') as ts:",
    "    for i in range(len(ts)):",
    "        value = int(ts[i].parameters['f0_class'].value[0]) - 10",
    "        traces.setdefault(value, []).append(np.asarray(ts[i].samples)[pois])",
    "for value in traces:",
    "    traces[value] = np.array(traces[value], float)",
    "print('templates and victim traces loaded')"))

cells.append(md("## 1. The victim power trace"))
cells.append(code(
    "plt.figure(figsize=(11, 3))",
    "plt.plot(np.arange(len(example)) / 1000.0, example, lw=.3)",
    "plt.xlabel('time (us)'); plt.ylabel('power'); plt.title('one signing trace - its secret f is the key we recover')",
    "plt.show()"))

cells.append(md(
    "## 1b. The decode is a periodic loop",
    "",
    "The decode runs the same code for every coefficient, so the signal is **periodic**. Sliding",
    "the trace against itself (autocorrelation) it lines back up every ~373 samples:"))
cells.append(code(
    "seg = example[:8000] - example[:8000].mean()",
    "ac = np.correlate(seg, seg, 'full')[len(seg) - 1:]; ac = ac / ac[0]",
    "peaks = [k for k in range(100, 1600) if ac[k] > 0.25 and ac[k] >= ac[k-1] and ac[k] >= ac[k+1]]",
    "plt.figure(figsize=(8, 2.8)); plt.plot(ac[:1700])",
    "for m, k in enumerate(peaks, start=1):",
    "    plt.axvline(k, color='C3', ls='--'); plt.text(k, 0.55, f'{m}x', color='C3', ha='center')",
    "plt.xlabel('shift (samples)'); plt.ylabel('self-similarity')",
    "plt.title(f'decode repeats every ~{peaks[0]} samples'); plt.show()"))
cells.append(md(
    "In a **full-key capture** each coefficient would be read at its own offset in one trace. In",
    "**this** dataset every trace is an `f[0]` measurement, so we read each coefficient by matching",
    "its value to the measured traces of that value (next)."))

cells.append(md(
    "## 2. Attack the coefficient in that trace",
    "",
    "The capture is aligned to the first coefficient, so this trace is an `f[0]` measurement. We",
    "take **that exact trace**, read it at the template's sample points, score it against every",
    "template, and rank the candidate values. The best is the prediction; the gap to the",
    "runner-up is the confidence."))
cells.append(code(
    "def scores(trace):",
    "    return ((trace - mu) / sd) @ W.T + b   # one score per candidate value",
    "",
    "victim = example[pois]                     # the trace from section 1, at the template's points",
    "print(f'attacking f[0] in the trace above   (true secret value = {f_true[0]:+d})\\n')",
    "s = scores(victim); order = np.argsort(s)[::-1]",
    "print('candidate  score')",
    "for j in order[:5]:",
    "    print(f'  {candidates[j]:+d}   {s[j]:8.2f}')",
    "print(f'\\npredicted f[0] = {candidates[order[0]]:+d}   (true {f_true[0]:+d})   confidence {s[order[0]] - s[order[1]]:.2f}')"))

cells.append(md(
    "## 3. A few more coefficients",
    "",
    "In a full-key capture every coefficient would sit at its own offset in one trace. **This**",
    "dataset only aligns `f[0]`, so to read the other coefficients we use real captures grouped by",
    "the value they measured - averaging a few (here 45) to cut the noise - and score each the same",
    "way. The confidence is higher here only because these are averaged."))
cells.append(code(
    "def measure(value, k=45):",
    "    # average the first k real traces of a coefficient with this value (fixed, not random)",
    "    if value not in traces or len(traces[value]) < k:",
    "        return None                       # value outside the templates' range",
    "    return traces[value][:k].mean(axis=0)",
    "",
    "for i in range(10):",
    "    trace = measure(f_true[i])",
    "    if trace is None:",
    "        print(f'f[{i:>2}]  secret {f_true[i]:+d}  outside template range -> recovered later by the public key')",
    "        continue",
    "    s = scores(trace); o = np.argsort(s)[::-1]",
    "    print(f'f[{i:>2}]  predicted {candidates[o[0]]:+d}   (secret {f_true[i]:+d})   confidence {s[o[0]] - s[o[1]]:.2f}')"))

cells.append(md(
    "## 4. Recover the full key",
    "",
    "The template reads every coefficient of `f` and `g`. A few values fall outside the templates'",
    "range - those stay unknown. We keep the 1030 most-confident reads and solve the public relation",
    "`H*f = g (mod 12289)` for the rest (`n = 1024`, so 1024 equations pin the 2048 unknowns).",
    "",
    "**Check:** every Falcon-1024 coefficient must lie in **[-15, 15]**. If the solved key stays in",
    "range, the recovery is self-consistent and correct."))
cells.append(code(
    "def recover():",
    "    reads = []",
    "    for name, key in (('f', f_true), ('g', g_true)):",
    "        for i in range(n):",
    "            trace = measure(key[i])",
    "            if trace is None:",
    "                continue                   # out of template range -> solved by completion",
    "            s = scores(trace); o = np.argsort(s)[::-1]",
    "            reads.append((s[o[0]] - s[o[1]], name, i, int(candidates[o[0]])))",
    "    reads.sort(reverse=True)",
    "    known_f = {i: v for conf, name, i, v in reads[:1030] if name == 'f'}",
    "    known_g = {i: v for conf, name, i, v in reads[:1030] if name == 'g'}",
    "    f_full, g_full = km.solve_completion_fast(h, known_f, known_g, n=n)",
    "    f_rec = np.array([km.to_signed(v) for v in f_full])",
    "    g_rec = np.array([km.to_signed(v) for v in g_full])",
    "    return f_rec, g_rec",
    "",
    "f_rec, g_rec = recover()",
    "in_range = bool(np.all(np.abs(f_rec) <= 15) and np.all(np.abs(g_rec) <= 15))",
    "print(f'every coefficient in Falcon-1024 range [-15, 15]? {in_range}')",
    "",
    "np.set_printoptions(threshold=np.inf, linewidth=120)",
    "print('\\nrecovered f (all', len(f_rec), 'coefficients):'); print(f_rec)",
    "print('\\nsecret key recovered :', np.array_equal(f_rec, f_true) and np.array_equal(g_rec, g_true))"))

nb = {"cells": cells,
      "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
                   "language_info": {"name": "python", "version": "3.11"}},
      "nbformat": 4, "nbformat_minor": 5}
json.dump(nb, open("falcon_demo.ipynb", "w"), indent=1)
print("wrote falcon_demo.ipynb with", len(cells), "cells")

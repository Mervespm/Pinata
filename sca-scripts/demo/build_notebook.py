"""Builds falcon_demo.ipynb - a lean, attacker's-eye single-trace demo (Falcon-512).

The attacked key's f is a REAL captured secret (from the shown trace); g and the
public key h are generated to form a valid key (they were not measured). Flow:
victim trace -> periodic loop -> attack one coefficient -> a few more -> recover
the full key via the public key, checked by the Falcon coefficient bound.
"""
import json


def md(*l):
    return {"cell_type": "markdown", "metadata": {}, "source": [x + "\n" for x in l]}


def code(*l):
    return {"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
            "source": [x + "\n" for x in l]}


cells = []

cells.append(md(
    "# Single-Trace Attack on Falcon-512",
    "",
    "The attacker has power traces of the victim device and a set of **templates** - one per",
    "possible coefficient value. Goal: recover the secret key `f, g`.",
    "",
    "This is a **profiled per-coefficient attack**: profile one coefficient of the decode over all",
    "its values, and - because the decode is a constant-time loop - apply that template to every",
    "coefficient. The attacked `f` is a **real captured secret** (the one in the trace below); `g`",
    "and the public key `h` are generated to form a valid key (they were not measured).",
    "",
    "Templates are already trained; we only run the attack."))

cells.append(code(
    "import os, sys, random",
    "import numpy as np",
    "import matplotlib.pyplot as plt",
    "import trsfile",
    "sys.path.insert(0, os.path.abspath(os.path.join('..', 'template_attack')))",
    "import falcon_keymath as km",
    "n = 512                               # Falcon-512",
    "",
    "# trained templates: one model per possible coefficient value",
    "T = np.load(os.path.join('..', 'template_attack', 'templates.npz'))",
    "candidates = T['classes'] - 10; pois = T['pois']",
    "mu, sd, W, b = T['mu'], T['sd'], T['W_lda'], T['b_lda']",
    "",
    "# the victim key: real f (from the trace), generated g and public h",
    "K = np.load('nb_falcon512.npz')",
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
    "print('templates for', len(candidates), 'values; victim traces loaded')"))

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
    "## 2. Attack one coefficient",
    "",
    "Each coefficient is measured a few times (here 45 traces) and **averaged** to cut the noise.",
    "We score that trace against every template and rank the candidate values. The best is the",
    "prediction; the gap to the runner-up is the confidence."))
cells.append(code(
    "random.seed(0)",
    "def measure(value, k=45):",
    "    # average k real traces of a coefficient with this value",
    "    if value not in traces or len(traces[value]) < k:",
    "        return None                       # value outside the templates' range",
    "    return np.mean(random.sample(list(traces[value]), k), axis=0)",
    "",
    "def scores(trace):",
    "    return ((trace - mu) / sd) @ W.T + b   # one score per candidate value",
    "",
    "print(f'attacking f[0]   (true secret value = {f_true[0]:+d})\\n')",
    "s = scores(measure(f_true[0])); order = np.argsort(s)[::-1]",
    "print('candidate  score')",
    "for j in order[:5]:",
    "    print(f'  {candidates[j]:+d}   {s[j]:8.2f}')",
    "print(f'\\npredicted f[0] = {candidates[order[0]]:+d}   (true {f_true[0]:+d})   confidence {s[order[0]] - s[order[1]]:.2f}')"))

cells.append(md("## 3. A few more coefficients"))
cells.append(code(
    "for i in range(10):",
    "    s = scores(measure(f_true[i])); o = np.argsort(s)[::-1]",
    "    print(f'f[{i:>2}]  predicted {candidates[o[0]]:+d}   (secret {f_true[i]:+d})   confidence {s[o[0]] - s[o[1]]:.2f}')"))

cells.append(md(
    "## 4. Recover the full key",
    "",
    "The template reads every coefficient of `f` and `g`. A few values fall outside the templates'",
    "range - those stay unknown. We keep the 520 most-confident reads and solve the public relation",
    "`H*f = g (mod 12289)` for the rest (`n = 512`, so 512 equations pin the 1024 unknowns).",
    "",
    "**Check:** every Falcon-512 coefficient must lie in **[-31, 31]**. If the solved key stays in",
    "range it is correct; if not, a trusted read was wrong, so we re-read and retry."))
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
    "    known_f = {i: v for conf, name, i, v in reads[:520] if name == 'f'}",
    "    known_g = {i: v for conf, name, i, v in reads[:520] if name == 'g'}",
    "    f_full, g_full = km.solve_completion_fast(h, known_f, known_g, n=n)",
    "    f_rec = np.array([km.to_signed(v) for v in f_full])",
    "    g_rec = np.array([km.to_signed(v) for v in g_full])",
    "    return f_rec, g_rec",
    "",
    "random.seed(0)",
    "for attempt in range(1, 6):",
    "    f_rec, g_rec = recover()",
    "    in_range = bool(np.all(np.abs(f_rec) <= 31) and np.all(np.abs(g_rec) <= 31))",
    "    print(f'attempt {attempt}: coefficients in [-31, 31]? {in_range}')",
    "    if in_range:",
    "        break",
    "    print('   a kept read was wrong - re-reading and retrying')",
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

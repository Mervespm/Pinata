"""Builds falcon_demo.ipynb - a lean, attacker's-eye single-trace demo.

Templates already exist. Flow: victim trace -> where it leaks -> attack one
coefficient (rank candidate values, predict + confidence) -> repeat -> recover
the full key. Code is kept plain and presentation-friendly.
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
    "possible coefficient value (-10 .. +10). Goal: recover the secret key `f, g`.",
    "",
    "Templates are already trained; we only run the attack."))

cells.append(code(
    "import os, sys, random",
    "import numpy as np",
    "import matplotlib.pyplot as plt",
    "import trsfile",
    "sys.path.insert(0, os.path.abspath(os.path.join('..', 'template_attack')))",
    "import falcon_keymath as km",
    "",
    "# the trained templates: one model per possible coefficient value",
    "T = np.load(os.path.join('..', 'template_attack', 'templates.npz'))",
    "candidates = T['classes'] - 10        # the possible values, -10 .. +10",
    "pois = T['pois']                      # the time samples the template looks at",
    "mu, sd = T['mu'], T['sd']             # used to normalize a trace",
    "W, b = T['W_lda'], T['b_lda']         # the template model",
    "",
    "# the victim key we want to recover, and the public key",
    "K = np.load('nb_falcon1024.npz')",
    "f_true = K['f'].astype(int)",
    "g_true = K['g'].astype(int)",
    "h = K['h'].astype(np.uint32)",
    "N = km.N",
    "",
    "# the real power traces, grouped by which coefficient value they measured",
    "traces = {}",
    "with trsfile.trs_open(r'C:/Users/mervkara/Inspector/data/falcon_gui_split_leak1/split_TEST.trs', 'r') as ts:",
    "    for i in range(len(ts)):",
    "        value = int(ts[i].parameters['f0_class'].value[0]) - 10",
    "        traces.setdefault(value, []).append(np.asarray(ts[i].samples)[pois])",
    "for value in traces:",
    "    traces[value] = np.array(traces[value], float)",
    "",
    "print('loaded templates for', len(candidates), 'values, and the victim traces')"))

cells.append(md("## 1. A victim power trace"))
cells.append(code(
    "example = np.load('nb_corr_full.npz')['example'].astype(float)",
    "plt.figure(figsize=(11, 3))",
    "plt.plot(np.arange(len(example)) / 1000.0, example, lw=.3)",
    "plt.xlabel('time (us)'); plt.ylabel('power'); plt.title('one signing trace')",
    "plt.show()"))

cells.append(md(
    "## 1b. Where the key leaks",
    "",
    "Correlating the power with the secret coefficient marks the two leak points we template:",
    "the **decode** (`|rho|~0.97`) and the **mod-q** step (`|rho|~0.38`)."))
cells.append(code(
    "corr = np.load('nb_corr_full.npz')['corr']",
    "plt.figure(figsize=(11, 3))",
    "plt.plot(np.arange(len(corr)) / 1000.0, corr, lw=.5, color='C3')",
    "plt.annotate('decode  0.97', xy=(1.1, corr[1093]), xytext=(16, 0.80), arrowprops=dict(arrowstyle='->'))",
    "plt.annotate('mod-q  0.38', xy=(92.7, corr[92676]), xytext=(115, 0.55), arrowprops=dict(arrowstyle='->'))",
    "plt.xlabel('time (us)'); plt.ylabel('|correlation with secret|'); plt.title('two attack points')",
    "plt.show()"))

cells.append(md(
    "## 2. Attack one coefficient",
    "",
    "Take the victim's measurement of `f[0]`, score it against every template, and rank the",
    "candidate values. The best score is the prediction; the gap to the runner-up is the confidence."))
cells.append(code(
    "random.seed(0)                        # fixed so the demo repeats identically",
    "",
    "def measure(value, n=45):",
    "    # the attacker measures this coefficient n times and averages to cut the noise",
    "    sample = random.sample(list(traces[value]), n)",
    "    return np.mean(sample, axis=0)",
    "",
    "def scores(trace):",
    "    # score the trace against every template; higher score = better match",
    "    normalized = (trace - mu) / sd",
    "    return normalized @ W.T + b",
    "",
    "s = scores(measure(f_true[0]))",
    "order = np.argsort(s)[::-1]            # sort candidates, best first",
    "",
    "print('candidate  score')",
    "for j in order[:5]:",
    "    print(f'  {candidates[j]:+d}   {s[j]:8.2f}')",
    "",
    "best = candidates[order[0]]",
    "confidence = s[order[0]] - s[order[1]]",
    "print(f'\\npredicted f[0] = {best:+d}   confidence {confidence:.2f}')"))

cells.append(md("## 3. A few more coefficients"))
cells.append(code(
    "for i in range(10):",
    "    s = scores(measure(f_true[i]))",
    "    order = np.argsort(s)[::-1]",
    "    predicted = candidates[order[0]]",
    "    confidence = s[order[0]] - s[order[1]]",
    "    print(f'f[{i:>2}]  predicted {predicted:+d}   (secret {f_true[i]:+d})   confidence {confidence:.2f}')"))

cells.append(md(
    "## 4. Recover the full key",
    "",
    "The template reads every coefficient (~98% correct). We keep the 1030 most-confident reads and",
    "solve the public relation `H*f = g (mod 12289)` for the rest. A Falcon coefficient must be in",
    "**[-15, 15]**, so that bound is our check: if the solved key stays in range, it is correct."))
cells.append(code(
    "# read every coefficient of f and g, each with a confidence",
    "reads = []",
    "for name, key in (('f', f_true), ('g', g_true)):",
    "    for i in range(N):",
    "        s = scores(measure(key[i]))",
    "        order = np.argsort(s)[::-1]",
    "        predicted = int(candidates[order[0]])",
    "        confidence = s[order[0]] - s[order[1]]",
    "        reads.append((confidence, name, i, predicted))",
    "",
    "# keep the 1030 most-confident reads",
    "reads.sort(reverse=True)",
    "known_f = {i: v for conf, name, i, v in reads[:1030] if name == 'f'}",
    "known_g = {i: v for conf, name, i, v in reads[:1030] if name == 'g'}",
    "",
    "# solve H*f = g for the rest, using the public key",
    "f_full, g_full = km.solve_completion_fast(h, known_f, known_g)",
    "f_rec = np.array([km.to_signed(v) for v in f_full])",
    "g_rec = np.array([km.to_signed(v) for v in g_full])",
    "",
    "in_range = np.all(np.abs(f_rec) <= 15) and np.all(np.abs(g_rec) <= 15)",
    "print('recovered f[0:16] :', f_rec[:16].tolist())",
    "print('secret    f[0:16] :', f_true[:16].tolist())",
    "print('\\nall coefficients in [-15, 15] :', bool(in_range))",
    "print('secret key recovered          :', np.array_equal(f_rec, f_true) and np.array_equal(g_rec, g_true))"))

nb = {"cells": cells,
      "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
                   "language_info": {"name": "python", "version": "3.11"}},
      "nbformat": 4, "nbformat_minor": 5}
json.dump(nb, open("falcon_demo.ipynb", "w"), indent=1)
print("wrote falcon_demo.ipynb with", len(cells), "cells")

"""Paper figure: mean power traces for representative f[0] candidates.

Two panels, same y-scale, zoomed to the decode leak window:
  Panel A - an "easy" pair (opposite sign / different Hamming weight):
            widely separated mean traces, ~100% pairwise classification
            accuracy (see falcon_pairwise_distinguish.py).
  Panel B - a "hard" pair (identical Hamming weight, e.g. 1 and 2, both
            popcount 1): near-overlapping mean traces, ~52% pairwise
            accuracy (chance level) - visual confirmation of the
            Hamming-weight-collision finding.

Shaded bands are +/-1 std across that class's profiling traces at each
sample - the actual per-trace spread, which is what determines whether two
classes are separable from a single trace, not just how far apart their
means sit.

Usage:
    python falcon_plot_mean_traces.py [PROFILE_DIR] [EASY_A] [EASY_B] [HARD_A] [HARD_B]
"""
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

import falcon_template_attack as fta

# Validated 4-slot categorical palette (dataviz skill reference palette,
# slots 1/2/3/8 - blue, orange, aqua, red).
COLORS = {"easy_a": "#2a78d6", "easy_b": "#eb6834", "hard_a": "#1baf7a", "hard_b": "#e34948"}
INK = "#0b0b0b"
SECONDARY_INK = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
SURFACE = "#fcfcfb"


def mean_and_std(traces, f0s, c):
    x = traces[f0s == c]
    return x.mean(axis=0), x.std(axis=0), len(x)


def plot_panel(ax, t, traces, f0s, c_a, c_b, color_a, color_b, poi_t, title):
    mean_a, std_a, n_a = mean_and_std(traces, f0s, c_a)
    mean_b, std_b, n_b = mean_and_std(traces, f0s, c_b)

    # The two curves converge back together at the right edge (post-leak),
    # so direct end-labels there would collide - use a legend instead (the
    # dependable identity channel per the dataviz skill's guidance for
    # converging series).
    for mean, std, color, c, n in [(mean_a, std_a, color_a, c_a, n_a),
                                     (mean_b, std_b, color_b, c_b, n_b)]:
        ax.fill_between(t, mean - std, mean + std, color=color, alpha=0.10, linewidth=0)
        ax.plot(t, mean, color=color, linewidth=1.8, solid_capstyle="round", zorder=3,
                 label=f"f[0]={c}  (HW32={fta.hw32(c)}, n={n})")

    ax.axvline(poi_t, color=MUTED, linewidth=1.0, linestyle=(0, (3, 2)), zorder=1)
    ax.text(poi_t, ax.get_ylim()[1] if ax.get_ylim()[1] else 1, "  leak point",
            fontsize=8, color=MUTED, rotation=90, va="top", ha="left")

    legend = ax.legend(loc="upper right", fontsize=8.5, frameon=False,
                         labelcolor=INK, handlelength=1.6, borderaxespad=0.3)

    ax.set_title(title, fontsize=10.5, color=INK, loc="left", pad=8)
    ax.set_xlabel("time (us, relative to trigger)", fontsize=9, color=SECONDARY_INK)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color(MUTED)
        ax.spines[spine].set_linewidth(0.8)
    ax.grid(axis="y", color=GRID, linewidth=0.8, zorder=0)
    ax.tick_params(colors=SECONDARY_INK, labelsize=8.5)
    ax.set_facecolor(SURFACE)


def main():
    profile_dir = sys.argv[1] if len(sys.argv) > 1 else fta.DEFAULT_DIR
    easy_a = int(sys.argv[2]) if len(sys.argv) > 2 else -5
    easy_b = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    hard_a = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    hard_b = int(sys.argv[5]) if len(sys.argv) > 5 else 2

    traces, f0s = fta.load_profile(profile_dir)
    t_us = np.load(os.path.join(profile_dir, "time_us.npy"))

    counts = {int(c): int((f0s == c).sum()) for c in sorted(set(f0s.tolist()))}
    classes = sorted(c for c, n in counts.items() if n >= fta.MIN_CLASS_COUNT)
    mask = np.isin(f0s, classes)
    pois, corr = fta.find_pois(traces[mask], f0s[mask], 1, fta.POI_MIN_SPACING)
    poi_t = t_us[pois[0]]

    # Zoom to the decode leak, with context before/after.
    lo, hi = poi_t - 0.8, poi_t + 1.2
    win = (t_us >= lo) & (t_us <= hi)
    t = t_us[win]
    traces_win = traces[:, win]

    fig, axes = plt.subplots(1, 2, figsize=(9.5, 3.6), sharey=True)
    fig.patch.set_facecolor(SURFACE)

    plot_panel(axes[0], t, traces_win, f0s, easy_a, easy_b,
               COLORS["easy_a"], COLORS["easy_b"], poi_t,
               f"Distinguishable: f[0]={easy_a} vs f[0]={easy_b}\n"
               f"(different Hamming weight -> ~100% pairwise accuracy)")
    plot_panel(axes[1], t, traces_win, f0s, hard_a, hard_b,
               COLORS["hard_a"], COLORS["hard_b"], poi_t,
               f"Not distinguishable: f[0]={hard_a} vs f[0]={hard_b}\n"
               f"(same Hamming weight -> ~52% pairwise accuracy, chance level)")

    axes[0].set_ylabel("channel A power (mV)", fontsize=9, color=SECONDARY_INK)
    fig.suptitle("Mean power traces at Falcon f[0] decode, by Hamming-weight separation",
                  fontsize=12, color=INK, y=1.04)
    fig.text(0.5, -0.04,
              f"Shaded band: +/-1 std across profiling traces at each sample. "
              f"Leak point: correlation r={corr[pois[0]]:.2f} with HW32(f[0]).",
              ha="center", fontsize=8.5, color=MUTED)

    fig.tight_layout()
    out_dir = os.path.join(profile_dir, "figures")
    os.makedirs(out_dir, exist_ok=True)
    png_path = os.path.join(out_dir, "mean_traces_easy_vs_hard.png")
    pdf_path = os.path.join(out_dir, "mean_traces_easy_vs_hard.pdf")
    fig.savefig(png_path, dpi=300, bbox_inches="tight", facecolor=SURFACE)
    fig.savefig(pdf_path, bbox_inches="tight", facecolor=SURFACE)
    print(f"Saved -> {png_path}")
    print(f"Saved -> {pdf_path}")


if __name__ == "__main__":
    main()

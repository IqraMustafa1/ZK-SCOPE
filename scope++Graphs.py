# ---------------------------------------------
# SCOPE++ Evaluation Graphs (Matplotlib ONLY)
# Professional, paper-ready figures (PDF + PNG)
#
# Figures:
# 1) E2E latency vs attribute-set size (cold & warm)
#    - classic vs hybrid
#    - median line with upper-only p95 cap
#    - mean shown as "x" marker (single legend entry)
# 2) Hybrid overhead vs classic (median)
#    - absolute overhead (ms) + relative overhead (%) on twin axis
# 3) ECDF template (needs raw samples)
#
# Output: ./figs/*.pdf and ./figs/*.png
# ---------------------------------------------

import os
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

# =========================
# Data (RECOMPUTED from CSVs)
# metric: total_end2end_ms
# groups: scenario (cold/warm) x attrs (1,2,4,8,16,21) x approach (classic/hybrid)
# n=30 each group
# =========================
attrs = np.array([1, 2, 4, 8, 16, 21], dtype=int)

data = {
    "cold": {
        "classic": {
            "mean":   np.array([122.73, 110.64, 112.78, 112.17, 110.16, 111.84]),
            "median": np.array([107.99, 108.90, 115.31, 109.98, 109.00, 112.39]),
            "p95":    np.array([138.47, 129.97, 139.30, 140.75, 130.58, 135.44]),
        },
        "hybrid": {
            "mean":   np.array([100.72,  92.68,  93.84,  99.80, 102.62, 103.39]),
            "median": np.array([103.27,  84.92,  85.28,  95.35,  98.45, 103.26]),
            "p95":    np.array([132.59, 131.17, 132.26, 146.17, 150.31, 151.35]),
        },
    },
    "warm": {
        "classic": {
            "mean":   np.array([105.99, 100.03, 100.00, 100.45, 104.50, 102.22]),
            "median": np.array([104.58, 100.44,  99.62, 101.88, 101.46,  97.47]),
            "p95":    np.array([122.89, 122.55, 127.95, 120.88, 151.42, 140.88]),
        },
        "hybrid": {
            "mean":   np.array([ 94.19,  94.62,  97.78,  97.23,  99.23,  97.21]),
            "median": np.array([ 91.08,  91.87,  92.55,  95.76, 100.12,  96.71]),
            "p95":    np.array([136.10, 147.59, 139.62, 143.15, 143.71, 124.58]),
        },
    },
}

# =========================
# Output folder
# =========================
OUTDIR = "figs"
os.makedirs(OUTDIR, exist_ok=True)

# =========================
# Professional style setup
# =========================
plt.rcParams.update({
    "figure.dpi": 160,
    "savefig.dpi": 300,
    "font.size": 11,
    "axes.titlesize": 12,
    "axes.labelsize": 11,
    "legend.fontsize": 10,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "axes.grid": True,
    "grid.alpha": 0.28,
    "grid.linestyle": "-",
    "grid.linewidth": 0.6,
    "lines.linewidth": 2.3,
    "lines.markersize": 6.5,
})

# Color palette (pleasant, high-contrast, paper-friendly)
COLORS = {
    "classic": "#1f77b4",  # blue
    "hybrid":  "#ff7f0e",  # orange
    "mean":    "#2ca02c",  # green
    "over_ms": "#9467bd",  # purple
    "over_pct":"#d62728",  # red
}

MARKER = {"classic": "o", "hybrid": "s"}
LINESTYLE = {"classic": "-", "hybrid": "-"}

def style_axis(ax):
    """Consistent axis styling for IEEE-like figures."""
    ax.grid(True, which="major")
    ax.grid(True, which="minor", alpha=0.18)
    ax.minorticks_on()
    ax.yaxis.set_major_locator(MaxNLocator(integer=False, nbins=6))
    for spine in ax.spines.values():
        spine.set_linewidth(0.9)

def _upper_err(p95: np.ndarray, med: np.ndarray) -> np.ndarray:
    """Upper-only error (p95 - median)."""
    e = p95 - med
    e[e < 0] = 0
    return e

def save_fig(fig, name_base: str):
    pdf_path = os.path.join(OUTDIR, f"{name_base}.pdf")
    png_path = os.path.join(OUTDIR, f"{name_base}.png")
    fig.savefig(pdf_path, bbox_inches="tight")
    fig.savefig(png_path, bbox_inches="tight")
    print(f"Saved: {pdf_path}")
    print(f"Saved: {png_path}\n")

# ==========================================================
# Figure 1: E2E vs attrs (two panels: cold, warm) — clean legend
# ==========================================================
fig, axes = plt.subplots(1, 2, figsize=(12.8, 4.9), sharey=True)

legend_handles = None
legend_labels = None

for ax, scenario in zip(axes, ["cold", "warm"]):
    style_axis(ax)

    c = data[scenario]["classic"]
    h = data[scenario]["hybrid"]

    c_med, c_p95, c_mean = c["median"], c["p95"], c["mean"]
    h_med, h_p95, h_mean = h["median"], h["p95"], h["mean"]

    # Classic: median line + upper-only p95 cap
    eb1 = ax.errorbar(
        attrs, c_med,
        yerr=np.vstack([np.zeros_like(c_med), _upper_err(c_p95, c_med)]),
        fmt=LINESTYLE["classic"] + MARKER["classic"],
        color=COLORS["classic"],
        capsize=4,
        elinewidth=1.5,
        label="Classic (median + p95 cap)"
    )

    # Hybrid: median line + upper-only p95 cap
    eb2 = ax.errorbar(
        attrs, h_med,
        yerr=np.vstack([np.zeros_like(h_med), _upper_err(h_p95, h_med)]),
        fmt=LINESTYLE["hybrid"] + MARKER["hybrid"],
        color=COLORS["hybrid"],
        capsize=4,
        elinewidth=1.5,
        label="Hybrid (median + p95 cap)"
    )

    # Means: shown as X markers (single semantic legend entry)
    mean1 = ax.plot(
        attrs, c_mean,
        linestyle="None", marker="x", markersize=7,
        color=COLORS["mean"],
        label="Mean (marker)"
    )[0]
    ax.plot(attrs, h_mean, linestyle="None", marker="x", markersize=7, color=COLORS["mean"])

    ax.set_title(f"E2E Latency vs |A| ({scenario.capitalize()})")
    ax.set_xlabel("Attribute-set size |A|")
    ax.set_xticks(attrs)
    ax.set_xlim(0.5, 21.5)

    if legend_handles is None:
        legend_handles = [eb1.lines[0], eb2.lines[0], mean1]
        legend_labels = ["Classic (median + p95 cap)", "Hybrid (median + p95 cap)", "Mean (marker)"]

axes[0].set_ylabel("End-to-end latency (ms)")

fig.suptitle("SCOPE++: End-to-End Latency Scaling (Classic vs Hybrid)", y=1.03)

# Shared legend ABOVE plots (no overlap)
fig.legend(
    legend_handles, legend_labels,
    loc="upper center",
    ncol=3,
    frameon=True,
    bbox_to_anchor=(0.5, 1.00),
    borderaxespad=0.2
)

# Leave room at the top for legend
fig.tight_layout(rect=[0, 0, 1, 0.92])

save_fig(fig, "scopepp_e2e_vs_attrs")

# ==========================================================
# Figure 2: Hybrid overhead (median) relative to classic
# - left y: absolute overhead (ms)
# - right y: relative overhead (%)
# - clean legend placed above each panel
# ==========================================================
fig2, axes2 = plt.subplots(1, 2, figsize=(12.8, 4.6), sharey=True)

for ax, scenario in zip(axes2, ["cold", "warm"]):
    style_axis(ax)

    c_med = data[scenario]["classic"]["median"]
    h_med = data[scenario]["hybrid"]["median"]

    overhead_abs = h_med - c_med
    overhead_pct = 100.0 * (h_med - c_med) / c_med

    l1 = ax.plot(
        attrs, overhead_abs,
        "-o",
        color=COLORS["over_ms"],
        label="Absolute overhead (ms)"
    )[0]

    ax2b = ax.twinx()
    style_axis(ax2b)
    l2 = ax2b.plot(
        attrs, overhead_pct,
        "--s",
        color=COLORS["over_pct"],
        label="Relative overhead (%)"
    )[0]

    ax.set_title(f"Hybrid Overhead vs Classic (Median) — {scenario.capitalize()}")
    ax.set_xlabel("Attribute-set size |A|")
    ax.set_xticks(attrs)
    ax.set_xlim(0.5, 21.5)
    ax.set_ylabel("Overhead (ms)")
    ax2b.set_ylabel("Overhead (%)")

    # Legend (merge both axes) — place above to avoid overlap
    ax.legend(
        [l1, l2], ["Absolute overhead (ms)", "Relative overhead (%)"],
        loc="upper center",
        bbox_to_anchor=(0.5, 1.02),
        ncol=2,
        frameon=True
    )

fig2.suptitle("SCOPE++: Hybrid Overhead Relative to Classic", y=1.04)
fig2.tight_layout(rect=[0, 0, 1, 0.95])

save_fig(fig2, "scopepp_hybrid_overhead")

# ==========================================================
# Figure 3 (Template): Empirical CDF of E2E latency
# Requires raw samples, not summary stats.
# ==========================================================
def plot_ecdf(samples_ms: np.ndarray, ax, label: str, color: str, linestyle: str, marker: str):
    x = np.sort(samples_ms)
    y = np.arange(1, len(x) + 1) / len(x)
    ax.plot(x, y, label=label, color=color, linestyle=linestyle,
            marker=marker, markevery=max(1, len(x)//12))
    ax.set_xlabel("End-to-end latency (ms)")
    ax.set_ylabel("Empirical CDF")
    style_axis(ax)

# Example usage (uncomment and supply your arrays):
# classic_samples = np.array([...], dtype=float)  # length n=30
# hybrid_samples  = np.array([...], dtype=float)  # length n=30
# fig3, ax3 = plt.subplots(1, 1, figsize=(6.8, 4.8))
# plot_ecdf(classic_samples, ax3, "Classic (warm, |A|=16)", COLORS["classic"], "-", "o")
# plot_ecdf(hybrid_samples,  ax3, "Hybrid  (warm, |A|=16)", COLORS["hybrid"],  "-", "s")
# ax3.set_title("SCOPE++: E2E Latency ECDF (Tail Behavior)")
# ax3.legend(loc="lower right", frameon=True)
# fig3.tight_layout()
# save_fig(fig3, "scopepp_e2e_ecdf_example")

print("Done. Figures written to ./figs/")

"""
Redraw the per-snapshot plot for outbound peers whose block height is greater
than or equal to the target node's self height.

The script reuses the existing CSV, so the analysis time window and parsed
statistics remain unchanged. It only changes the plot layout and labels.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.ticker import MaxNLocator

plt.rcParams["pdf.fonttype"] = 42
plt.rcParams["ps.fonttype"] = 42
plt.rcParams["font.family"] = "DejaVu Sans"

OUTPUT_DIR = Path(__file__).resolve().parent / "analysis_output"
CSV_PATH = OUTPUT_DIR / "malicious_height_gte_self_snapshots.csv"
OUT_BASE = OUTPUT_DIR / "malicious_out_height_gte_self_snapshots"


def main() -> None:
    df = pd.read_csv(CSV_PATH)
    x = df["elapsed_seconds"]
    malicious = df["malicious_out_height_gte_self"]
    benign = df["benign_out_height_gte_self"]

    fig, ax = plt.subplots(figsize=(3.5, 2.55))
    ax.plot(
        x,
        malicious,
        label="malicious outbound peers",
        color="#CC7C71",
        linewidth=0.9,
    )
    ax.plot(
        x,
        benign,
        label="benign outbound peers",
        color="#2472A3",
        linewidth=0.9,
    )
    ax.set_xlim(0, max(x))
    ax.set_ylim(0, max(12.5, malicious.max() + 0.5, benign.max() + 0.5))
    ax.set_xlabel("Timestamps (s)", fontsize=11, labelpad=2)
    ax.set_ylabel("Peer count", fontsize=11, labelpad=2)
    ax.tick_params(axis="both", labelsize=9.5, width=0.9, length=3)
    ax.set_xticks([0, 1000, 2000, 3000, 4000, 5000])
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.grid(axis="y", alpha=0.25, linewidth=0.7)
    ax.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, 1.22),
        ncol=2,
        fontsize=7.6,
        frameon=True,
        facecolor="white",
        edgecolor="#555555",
        framealpha=0.95,
        borderpad=0.25,
        handlelength=1.4,
        columnspacing=0.45,
        labelspacing=0.2,
    )
    for spine in ax.spines.values():
        spine.set_linewidth(0.9)
    fig.tight_layout(pad=0.25)
    fig.savefig(OUT_BASE.with_suffix(".png"), dpi=300)
    fig.savefig(OUT_BASE.with_suffix(".pdf"))
    plt.close(fig)

    print(f"Wrote: {OUT_BASE.with_suffix('.png')}")
    print(f"Wrote: {OUT_BASE.with_suffix('.pdf')}")


if __name__ == "__main__":
    main()

"""
Redraw the 20-round value=1000 connection-reset timing figures as bar charts.

The original line charts are preserved. This script reads the existing
20_rounds_time_cost_stats.csv, keeps only round 1..20, writes clean CSV files
for Origin, and exports bar charts whose y-axis unit is seconds.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

plt.rcParams["hatch.linewidth"] = 0.9
plt.rcParams["pdf.fonttype"] = 42
plt.rcParams["ps.fonttype"] = 42


BASE_DIR = Path(r"C:\Users\24407\Desktop\20times_reset_1000_data")
INPUT_CSV = BASE_DIR / "20_rounds_time_cost_stats.csv"

LOCAL_OUT_DIR = Path(__file__).resolve().parent / "analysis_output" / "20rounds_bars"
LOCAL_OUT_DIR.mkdir(parents=True, exist_ok=True)

ORIGIN_CSV = LOCAL_OUT_DIR / "20_rounds_time_cost_for_origin.csv"
ZERO_ORIGIN_CSV = LOCAL_OUT_DIR / "20_rounds_time_to_benign_out_zero_for_origin.csv"
RECOVERY_ORIGIN_CSV = LOCAL_OUT_DIR / "20_rounds_time_to_recovery_2_benign_out_for_origin.csv"
ZERO_PNG = LOCAL_OUT_DIR / "time_to_benign_out_zero_bar_hatched.png"
ZERO_PDF = LOCAL_OUT_DIR / "time_to_benign_out_zero_bar_hatched.pdf"
RECOVERY_PNG = LOCAL_OUT_DIR / "time_to_recovery_2_benign_out_bar_hatched.png"
RECOVERY_PDF = LOCAL_OUT_DIR / "time_to_recovery_2_benign_out_bar_hatched.pdf"
COMBINED_PNG = LOCAL_OUT_DIR / "20_rounds_time_cost_bar_combined_hatched.png"
COMBINED_PDF = LOCAL_OUT_DIR / "20_rounds_time_cost_bar_combined_hatched.pdf"


def load_clean_data() -> pd.DataFrame:
    df = pd.read_csv(INPUT_CSV, encoding="utf-8-sig")
    df["round_num"] = pd.to_numeric(df["round"], errors="coerce")
    df = df[df["round_num"].between(1, 20)].copy()
    df["round"] = df["round_num"].astype(int)
    for col in [
        "time_to_benign_out_zero_seconds",
        "time_to_benign_out_zero_minutes",
        "recovery_to_2_seconds",
        "recovery_to_2_minutes",
    ]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.sort_values("round").reset_index(drop=True)
    df["zero_avg_seconds"] = df["time_to_benign_out_zero_seconds"].mean()
    df["recovery_avg_seconds"] = df["recovery_to_2_seconds"].mean()
    df["zero_avg_minutes"] = df["time_to_benign_out_zero_minutes"].mean()
    df["recovery_avg_minutes"] = df["recovery_to_2_minutes"].mean()
    return df


def apply_hatch(bars, hatch: str | None) -> None:
    if not hatch:
        return
    for bar in bars:
        bar.set_hatch(hatch)


def plot_single(
    df: pd.DataFrame,
    y_col: str,
    avg_col: str,
    ylabel: str,
    png_path: Path,
    pdf_path: Path,
    color: str,
    hatch: str | None = None,
    legend_loc: str = "upper center",
) -> None:
    x = df["round"].tolist()
    y = df[y_col].tolist()
    avg = df[avg_col].iloc[0]

    fig, ax = plt.subplots(figsize=(4.2, 3.0))
    bars = ax.bar(x, y, color=color, edgecolor="#263238", linewidth=1.0, alpha=0.95)
    apply_hatch(bars, hatch)
    ax.axhline(avg, color="#9b1c31", linewidth=1.6, linestyle="--", label=f"Avg. {avg:.2f} s")
    ax.set_xlabel("Round", fontsize=18, labelpad=2)
    ax.set_ylabel(ylabel, fontsize=18, labelpad=2)
    ax.set_xticks([1, 5, 10, 15, 20])
    ax.tick_params(axis="both", labelsize=14, width=1.0, length=3)
    ax.grid(axis="y", alpha=0.25, linewidth=0.8)
    ax.legend(
        loc=legend_loc,
        bbox_to_anchor=(0.5, 1.18),
        fontsize=13,
        frameon=True,
        facecolor="white",
        edgecolor="#555555",
        framealpha=0.95,
        borderpad=0.25,
        handlelength=1.7,
        labelspacing=0.2,
    )
    for spine in ax.spines.values():
        spine.set_linewidth(1.0)
    fig.tight_layout(pad=0.25)
    fig.savefig(png_path, dpi=240)
    fig.savefig(pdf_path)
    plt.close(fig)


def plot_combined(df: pd.DataFrame) -> None:
    rounds = df["round"].tolist()
    x = list(range(len(rounds)))
    width = 0.38

    fig, ax = plt.subplots(figsize=(8.4, 6))
    zero_bars = ax.bar(
        [i - width / 2 for i in x],
        df["time_to_benign_out_zero_seconds"],
        width=width,
        label="Benign OUT to 0",
        color="#2472A3",
        edgecolor="#263238",
        linewidth=0.8,
        alpha=0.95,
    )
    recovery_bars = ax.bar(
        [i + width / 2 for i in x],
        df["recovery_to_2_seconds"],
        width=width,
        label="Recover to >=2 benign OUT",
        color="#FAA419",
        edgecolor="#263238",
        linewidth=0.8,
        alpha=0.95,
    )
    apply_hatch(zero_bars, "///")
    ax.axhline(df["zero_avg_seconds"].iloc[0], color="#1f4e79", linewidth=1.5, linestyle="--")
    ax.axhline(df["recovery_avg_seconds"].iloc[0], color="#9b1c31", linewidth=1.5, linestyle=":")
    ax.set_xlabel("Round", fontsize=18)
    ax.set_ylabel("Time cost (s)", fontsize=18)
    ax.set_xticks(x)
    ax.set_xticklabels(rounds)
    ax.tick_params(axis="both", labelsize=14)
    ax.grid(axis="y", alpha=0.25)
    ax.legend(loc="upper right", fontsize=12, frameon=True, facecolor="white", edgecolor="#555555", framealpha=0.95)
    fig.tight_layout()
    fig.savefig(COMBINED_PNG, dpi=240)
    fig.savefig(COMBINED_PDF)
    plt.close(fig)


def main() -> None:
    df = load_clean_data()
    origin_cols = [
        "round",
        "time_to_benign_out_zero_seconds",
        "time_to_benign_out_zero_minutes",
        "recovery_to_2_seconds",
        "recovery_to_2_minutes",
        "zero_avg_seconds",
        "recovery_avg_seconds",
        "zero_avg_minutes",
        "recovery_avg_minutes",
    ]
    df[origin_cols].to_csv(ORIGIN_CSV, index=False, encoding="utf-8-sig")
    df[
        [
            "round",
            "time_to_benign_out_zero_seconds",
            "zero_avg_seconds",
        ]
    ].to_csv(ZERO_ORIGIN_CSV, index=False, encoding="utf-8-sig")
    df[
        [
            "round",
            "recovery_to_2_seconds",
            "recovery_avg_seconds",
        ]
    ].to_csv(RECOVERY_ORIGIN_CSV, index=False, encoding="utf-8-sig")

    plot_single(
        df,
        "time_to_benign_out_zero_seconds",
        "zero_avg_seconds",
        "Time cost (s)",
        ZERO_PNG,
        ZERO_PDF,
        "#2472A3",
        "///",
    )
    plot_single(
        df,
        "recovery_to_2_seconds",
        "recovery_avg_seconds",
        "Time cost (s)",
        RECOVERY_PNG,
        RECOVERY_PDF,
        "#FAA419",
        None,
    )
    plot_combined(df)

    print(f"Wrote: {ORIGIN_CSV}")
    print(f"Wrote: {ZERO_ORIGIN_CSV}")
    print(f"Wrote: {RECOVERY_ORIGIN_CSV}")
    print(f"Wrote: {ZERO_PNG}")
    print(f"Wrote: {ZERO_PDF}")
    print(f"Wrote: {RECOVERY_PNG}")
    print(f"Wrote: {RECOVERY_PDF}")
    print(f"Wrote: {COMBINED_PNG}")
    print(f"Wrote: {COMBINED_PDF}")
    print(df[origin_cols].to_string(index=False))


if __name__ == "__main__":
    main()

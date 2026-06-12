"""
Analyze the 2026-05-25 whitelist filling experiment by snapshot.

The plot window is 2026-05-25 10:08:46 to 2026-05-25 12:00:00.
Timestamps in the whitelist log are Beijing time. Outputs are written under
analysis_output.
"""

from __future__ import annotations

import csv
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator


BASE_DIR = Path(r"C:\Users\24407\Desktop\analysis_whitelist_graylist")
WHITELIST_LOG = BASE_DIR / "2026-05-25_whitelist.log"
OUTPUT_DIR = Path(__file__).resolve().parent / "analysis_output"

ATTACK_START = datetime.fromisoformat("2026-05-25 10:09:46")
ATTACK_END = datetime.fromisoformat("2026-05-25 10:20:40")
FILL_START = datetime.fromisoformat("2026-05-25 10:20:54")
ANALYSIS_START = ATTACK_START - timedelta(seconds=60)
ANALYSIS_END = datetime.fromisoformat("2026-05-25 12:00:00")

HEADER_RE = re.compile(
    r"=+\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+White List\s+\]=+"
)
RATIO_RE = re.compile(r"(malicious) peer / (top|total) peer:\s*\[\s*(\d+)\s*/\s*(\d+)\s*\]")


@dataclass
class WhiteSnapshot:
    timestamp: datetime
    malicious_total_count: int | None = None
    total_peer: int | None = None
    malicious_top_count: int | None = None
    top_peer: int | None = None


def parse_whitelist_snapshots(path: Path) -> list[WhiteSnapshot]:
    snapshots: list[WhiteSnapshot] = []
    current: WhiteSnapshot | None = None

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            header = HEADER_RE.search(line)
            if header:
                if (
                    current
                    and ANALYSIS_START <= current.timestamp <= ANALYSIS_END
                    and current.malicious_total_count is not None
                ):
                    snapshots.append(current)
                ts_value = header.group("ts")
                current = WhiteSnapshot(timestamp=datetime.fromisoformat(ts_value))
                continue

            if current is None:
                continue

            ratio = RATIO_RE.search(line)
            if not ratio:
                continue

            _, denominator_name, numerator, denominator = ratio.groups()
            numerator_i = int(numerator)
            denominator_i = int(denominator)
            if denominator_name == "total":
                current.malicious_total_count = numerator_i
                current.total_peer = denominator_i
            elif denominator_name == "top":
                current.malicious_top_count = numerator_i
                current.top_peer = denominator_i

    if (
        current
        and ANALYSIS_START <= current.timestamp <= ANALYSIS_END
        and current.malicious_total_count is not None
    ):
        snapshots.append(current)

    return snapshots


def write_snapshot_csv(snapshots: list[WhiteSnapshot], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "timestamp",
                "elapsed_seconds_from_plot_start",
                "elapsed_seconds_from_attack_start",
                "malicious_peer",
                "total_peer",
                "malicious_peer_per_total_peer",
                "malicious_top_peer",
                "top_peer",
                "malicious_peer_per_top_peer",
            ],
        )
        writer.writeheader()
        for snapshot in snapshots:
            total_ratio = (
                snapshot.malicious_total_count / snapshot.total_peer
                if snapshot.total_peer
                else math.nan
            )
            top_ratio = (
                snapshot.malicious_top_count / snapshot.top_peer if snapshot.top_peer else math.nan
            )
            writer.writerow(
                {
                    "timestamp": snapshot.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "elapsed_seconds_from_plot_start": round(
                        (snapshot.timestamp - ANALYSIS_START).total_seconds(), 3
                    ),
                    "elapsed_seconds_from_attack_start": round(
                        (snapshot.timestamp - ATTACK_START).total_seconds(), 3
                    ),
                    "malicious_peer": snapshot.malicious_total_count,
                    "total_peer": snapshot.total_peer,
                    "malicious_peer_per_total_peer": total_ratio,
                    "malicious_top_peer": snapshot.malicious_top_count,
                    "top_peer": snapshot.top_peer,
                    "malicious_peer_per_top_peer": top_ratio,
                }
            )


def style_axes(ax: plt.Axes, ylabel: str, ylim: tuple[float, float]) -> None:
    ax.set_xlabel("timestamps(s)", fontsize=20)
    ax.set_ylabel(ylabel, fontsize=20)
    ax.set_xlim(0, (ANALYSIS_END - ANALYSIS_START).total_seconds())
    ax.set_ylim(*ylim)
    ax.tick_params(axis="both", labelsize=18)
    ax.grid(axis="y", alpha=0.25)


def add_phase_separator(ax: plt.Axes) -> None:
    attack_end_x = (ATTACK_END - ANALYSIS_START).total_seconds()

    ax.axvline(attack_end_x, color="#444444", linewidth=1.2, linestyle="--", alpha=0.85)


def plot_malicious_count(snapshots: list[WhiteSnapshot], out_base: Path) -> None:
    x = [(snapshot.timestamp - ANALYSIS_START).total_seconds() for snapshot in snapshots]
    y = [snapshot.malicious_total_count or 0 for snapshot in snapshots]

    fig, ax = plt.subplots(figsize=(8.4, 6))
    ax.fill_between(x, y, color="#4c78a8", alpha=0.18)
    ax.plot(x, y, color="#2f5f8f", linewidth=1.8)
    style_axes(ax, "Malicious peer count", (0, 1000))
    add_phase_separator(ax)
    fig.tight_layout()
    fig.savefig(out_base.with_suffix(".png"), dpi=220)
    fig.savefig(out_base.with_suffix(".pdf"))
    plt.close(fig)


def plot_top_malicious_count(snapshots: list[WhiteSnapshot], out_base: Path) -> None:
    x = [(snapshot.timestamp - ANALYSIS_START).total_seconds() for snapshot in snapshots]
    y = [snapshot.malicious_top_count or 0 for snapshot in snapshots]

    fig, ax = plt.subplots(figsize=(8.4, 6))
    ax.fill_between(x, y, color="#d07c2c", alpha=0.18)
    ax.plot(x, y, color="#b65f16", linewidth=1.8)
    style_axes(ax, "Malicious top peer count", (0, 20))
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    add_phase_separator(ax)
    fig.tight_layout()
    fig.savefig(out_base.with_suffix(".png"), dpi=220)
    fig.savefig(out_base.with_suffix(".pdf"))
    plt.close(fig)


def plot_malicious_ratios(snapshots: list[WhiteSnapshot], out_base: Path) -> None:
    x = [(snapshot.timestamp - ANALYSIS_START).total_seconds() for snapshot in snapshots]
    total_ratio = [
        (snapshot.malicious_total_count / snapshot.total_peer) if snapshot.total_peer else math.nan
        for snapshot in snapshots
    ]
    top_ratio = [
        (snapshot.malicious_top_count / snapshot.top_peer) if snapshot.top_peer else math.nan
        for snapshot in snapshots
    ]

    fig, ax = plt.subplots(figsize=(8.4, 6))
    ax.fill_between(x, total_ratio, color="#4c78a8", alpha=0.14)
    ax.plot(x, total_ratio, color="#2f5f8f", linewidth=1.8, label="malicious peer / total peer")
    ax.plot(x, top_ratio, color="#d07c2c", linewidth=1.8, label="malicious peer / top peer")
    style_axes(ax, "Ratio", (0, 1.05))
    add_phase_separator(ax)
    ax.legend(fontsize=15, frameon=False, loc="lower right")
    fig.tight_layout()
    fig.savefig(out_base.with_suffix(".png"), dpi=220)
    fig.savefig(out_base.with_suffix(".pdf"))
    plt.close(fig)


def write_summary_csv(snapshots: list[WhiteSnapshot], path: Path) -> None:
    rows: list[tuple[str, str | int | float]] = [
        ("attack_start", ATTACK_START.strftime("%Y-%m-%d %H:%M:%S")),
        ("attack_end", ATTACK_END.strftime("%Y-%m-%d %H:%M:%S")),
        ("fill_start", FILL_START.strftime("%Y-%m-%d %H:%M:%S")),
        ("analysis_start", ANALYSIS_START.strftime("%Y-%m-%d %H:%M:%S")),
        ("analysis_end", ANALYSIS_END.strftime("%Y-%m-%d %H:%M:%S")),
        ("analysis_duration_seconds", int((ANALYSIS_END - ANALYSIS_START).total_seconds())),
        ("snapshot_count", len(snapshots)),
    ]

    if snapshots:
        first = snapshots[0]
        last = snapshots[-1]
        counts = [snapshot.malicious_total_count or 0 for snapshot in snapshots]
        total_ratios = [
            (snapshot.malicious_total_count / snapshot.total_peer)
            for snapshot in snapshots
            if snapshot.total_peer
        ]
        top_ratios = [
            (snapshot.malicious_top_count / snapshot.top_peer)
            for snapshot in snapshots
            if snapshot.top_peer
        ]
        top_counts = [snapshot.malicious_top_count or 0 for snapshot in snapshots]
        rows.extend(
            [
                ("first_snapshot", first.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]),
                ("last_snapshot", last.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]),
                ("first_malicious_peer", first.malicious_total_count or 0),
                ("last_malicious_peer", last.malicious_total_count or 0),
                ("mean_malicious_peer", sum(counts) / len(counts)),
                ("max_malicious_peer", max(counts)),
                ("first_malicious_peer_per_total_peer", total_ratios[0]),
                ("last_malicious_peer_per_total_peer", total_ratios[-1]),
                ("mean_malicious_peer_per_total_peer", sum(total_ratios) / len(total_ratios)),
                ("max_malicious_peer_per_total_peer", max(total_ratios)),
                ("first_malicious_peer_per_top_peer", top_ratios[0]),
                ("last_malicious_peer_per_top_peer", top_ratios[-1]),
                ("mean_malicious_peer_per_top_peer", sum(top_ratios) / len(top_ratios)),
                ("max_malicious_peer_per_top_peer", max(top_ratios)),
                ("first_malicious_top_peer", first.malicious_top_count or 0),
                ("last_malicious_top_peer", last.malicious_top_count or 0),
                ("mean_malicious_top_peer", sum(top_counts) / len(top_counts)),
                ("max_malicious_top_peer", max(top_counts)),
            ]
        )

    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        writer.writerows(rows)


def main() -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)
    snapshots = parse_whitelist_snapshots(WHITELIST_LOG)

    snapshot_csv = OUTPUT_DIR / "whitelist_20260525_100846_120000_snapshots.csv"
    summary_csv = OUTPUT_DIR / "whitelist_20260525_100846_120000_summary.csv"
    count_base = OUTPUT_DIR / "whitelist_20260525_100846_120000_malicious_count"
    top_count_base = OUTPUT_DIR / "whitelist_20260525_100846_120000_malicious_top_count"
    ratio_base = OUTPUT_DIR / "whitelist_20260525_100846_120000_malicious_ratios"

    write_snapshot_csv(snapshots, snapshot_csv)
    write_summary_csv(snapshots, summary_csv)
    plot_malicious_count(snapshots, count_base)
    plot_top_malicious_count(snapshots, top_count_base)
    plot_malicious_ratios(snapshots, ratio_base)

    print(f"Whitelist snapshots: {len(snapshots)}")
    if snapshots:
        first = snapshots[0]
        last = snapshots[-1]
        print(f"First snapshot: {first.timestamp} malicious={first.malicious_total_count}/{first.total_peer}")
        print(f"Last snapshot: {last.timestamp} malicious={last.malicious_total_count}/{last.total_peer}")
    print(f"Wrote: {snapshot_csv}")
    print(f"Wrote: {summary_csv}")
    print(f"Wrote: {count_base.with_suffix('.png')}")
    print(f"Wrote: {count_base.with_suffix('.pdf')}")
    print(f"Wrote: {top_count_base.with_suffix('.png')}")
    print(f"Wrote: {top_count_base.with_suffix('.pdf')}")
    print(f"Wrote: {ratio_base.with_suffix('.png')}")
    print(f"Wrote: {ratio_base.with_suffix('.pdf')}")


if __name__ == "__main__":
    main()

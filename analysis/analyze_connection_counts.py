"""Analyze outbound connection counts and malicious peer height anomalies.

This script parses `2026-05-25_connections.log` and produces CSV files and
PNG/PDF figures for:

1. Benign outbound connection count and total outbound connection count during
   the reset attack plus whitelist filling window.
2. Malicious outbound connections whose peer height is greater than or equal to the local
   node's self height during the selected whitelist-filling window.

Timestamps are treated as Beijing local time exactly as written in the log.
"""

from __future__ import annotations

import argparse
import re
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


DEFAULT_LOG = Path(r"C:\Users\24407\Desktop\analysis_whitelist_graylist\2026-05-25_connections.log")
DEFAULT_OUTPUT_DIR = Path.cwd() / "analysis_output"

CONNECTION_COUNT_START = datetime.fromisoformat("2026-05-25 10:09:46")
CONNECTION_COUNT_END = datetime.fromisoformat("2026-05-25 14:54:13")

RESET_ATTACK_START = datetime.fromisoformat("2026-05-25 10:09:46")
RESET_ATTACK_END = datetime.fromisoformat("2026-05-25 10:20:40")

MALICIOUS_HEIGHT_START = datetime.fromisoformat("2026-05-25 10:20:54")
MALICIOUS_HEIGHT_END = datetime.fromisoformat("2026-05-25 12:00:00")

MALICIOUS_IP = "152.136.24.233"

HEADER_RE = re.compile(r"Current Connections")
TS_RE = re.compile(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")
SELF_HEIGHT_RE = re.compile(r"Current self block height:\s*(\d+)")
PEER_RE = re.compile(
    r"Peer addr:\s*\[\s*((?:\d{1,3}\.){3}\d{1,3}):(\d+),\s*(OUT|INC),\s*(\d+),\s*([^\]]+)\]"
)


def parse_ts(line: str) -> datetime | None:
    match = TS_RE.search(line)
    if not match:
        return None
    return datetime.fromisoformat(match.group(1))


def in_any_window(ts: datetime) -> bool:
    return CONNECTION_COUNT_START <= ts <= CONNECTION_COUNT_END


def in_malicious_height_window(ts: datetime) -> bool:
    return MALICIOUS_HEIGHT_START <= ts <= MALICIOUS_HEIGHT_END


def parse_connection_snapshots(log_path: Path) -> pd.DataFrame:
    rows: list[dict] = []
    current_ts: datetime | None = None
    in_snapshot = False
    self_height: int | None = None
    peers: list[tuple[str, str, str, int]] = []

    def flush() -> None:
        nonlocal current_ts, in_snapshot, self_height, peers
        if not in_snapshot or current_ts is None:
            return
        if not in_any_window(current_ts) and not in_malicious_height_window(current_ts):
            in_snapshot = False
            self_height = None
            peers = []
            return

        total_out = 0
        malicious_out = 0
        malicious_out_height_gte_self = 0
        benign_out_height_gte_self = 0
        for ip, port, direction, peer_height in peers:
            if direction != "OUT":
                continue
            total_out += 1
            is_malicious = ip == MALICIOUS_IP
            if is_malicious:
                malicious_out += 1
                if self_height is not None and peer_height >= self_height:
                    malicious_out_height_gte_self += 1
            elif self_height is not None and peer_height >= self_height:
                benign_out_height_gte_self += 1

        rows.append(
            {
                "timestamp": current_ts,
                "self_height": self_height,
                "total_out_connections": total_out,
                "benign_out_connections": total_out - malicious_out,
                "malicious_out_connections": malicious_out,
                "malicious_out_height_gte_self": malicious_out_height_gte_self,
                "benign_out_height_gte_self": benign_out_height_gte_self,
            }
        )

        in_snapshot = False
        self_height = None
        peers = []

    with log_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if HEADER_RE.search(line):
                flush()
                current_ts = parse_ts(line)
                in_snapshot = current_ts is not None
                self_height = None
                peers = []
                continue

            if not in_snapshot:
                continue

            if line.startswith("==="):
                flush()
                if current_ts and current_ts > CONNECTION_COUNT_END:
                    break
                continue

            height_match = SELF_HEIGHT_RE.search(line)
            if height_match:
                self_height = int(height_match.group(1))
                continue

            peer_match = PEER_RE.search(line)
            if peer_match:
                ip, port, direction, peer_height, _state = peer_match.groups()
                peers.append((ip, port, direction, int(peer_height)))

    flush()
    return pd.DataFrame(rows).sort_values("timestamp")


def minutely_last(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    return (
        df.set_index("timestamp")
        .resample("1min")
        .last()
        .dropna(how="all")
        .reset_index()
    )


def minutely_stats(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    metrics = [
        "total_out_connections",
        "benign_out_connections",
        "malicious_out_connections",
        "malicious_out_height_gte_self",
        "benign_out_height_gte_self",
    ]
    agg = df.set_index("timestamp")[metrics].resample("1min").agg(["min", "mean", "max", "last"])
    agg.columns = [f"{metric}_{stat}" for metric, stat in agg.columns]
    return agg.dropna(how="all").reset_index()


def plot_outbound_counts(df: pd.DataFrame, out_base: Path) -> None:
    fig, ax = plt.subplots(figsize=(13, 6))
    ax.plot(df["timestamp"], df["total_out_connections"], label="total outbound connections")
    ax.plot(df["timestamp"], df["benign_out_connections"], label="benign outbound connections")
    ax.set_title("Outbound connection counts")
    ax.set_xlabel("Time (Beijing)")
    ax.set_ylabel("Connection count")
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(out_base.with_suffix(".png"), dpi=180)
    fig.savefig(out_base.with_suffix(".pdf"))
    plt.close(fig)


def plot_outbound_snapshots(df: pd.DataFrame, out_base: Path) -> None:
    fig, ax = plt.subplots(figsize=(13, 6))
    ax.plot(
        df["timestamp"],
        df["total_out_connections"],
        label="total outbound connections (each snapshot)",
        linewidth=1.2,
    )
    ax.plot(
        df["timestamp"],
        df["benign_out_connections"],
        label="benign outbound connections (each snapshot)",
        linewidth=1.2,
    )
    ax.set_title("Outbound connection counts by snapshot")
    ax.set_xlabel("Time (Beijing)")
    ax.set_ylabel("Connection count")
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(out_base.with_suffix(".png"), dpi=180)
    fig.savefig(out_base.with_suffix(".pdf"))
    plt.close(fig)


def plot_malicious_height(df: pd.DataFrame, out_base: Path) -> None:
    fig, ax = plt.subplots(figsize=(13, 6))
    ax.plot(
        df["timestamp"],
        df["malicious_out_height_gte_self"],
        label="malicious outbound peers with height >= self height",
        color="#9b1c31",
    )
    ax.set_title("Malicious outbound peers with height >= self height")
    ax.set_xlabel("Time (Beijing)")
    ax.set_ylabel("Connection count")
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(out_base.with_suffix(".png"), dpi=180)
    fig.savefig(out_base.with_suffix(".pdf"))
    plt.close(fig)


def plot_malicious_height_snapshots(df: pd.DataFrame, out_base: Path) -> None:
    plot_df = df.copy()
    plot_df["elapsed_seconds"] = (plot_df["timestamp"] - MALICIOUS_HEIGHT_START).dt.total_seconds()

    fig, ax = plt.subplots(figsize=(13, 6))
    ax.plot(
        plot_df["elapsed_seconds"],
        plot_df["malicious_out_height_gte_self"],
        label="malicious outbound peers with height >= self height",
        color="#9b1c31",
        linewidth=1.35,
    )
    ax.plot(
        plot_df["elapsed_seconds"],
        plot_df["benign_out_height_gte_self"],
        label="benign outbound peers with height >= self height",
        color="#1f6f3f",
        linewidth=1.8,
        zorder=3,
    )
    ax.set_title("Outbound peers with height >= self height by snapshot")
    ax.set_xlabel("Elapsed time since 2026-05-25 10:20:54 (seconds)")
    ax.set_ylabel("Connection count")
    ax.set_ylim(bottom=-0.2, top=max(12.5, plot_df["malicious_out_height_gte_self"].max() + 0.5))
    ax.grid(True, alpha=0.3)
    ax.legend(loc="upper right")
    fig.tight_layout()
    fig.savefig(out_base.with_suffix(".png"), dpi=180)
    fig.savefig(out_base.with_suffix(".pdf"))
    plt.close(fig)


def summarize(df: pd.DataFrame, output_dir: Path) -> None:
    count_df = df[
        (df["timestamp"] >= CONNECTION_COUNT_START) & (df["timestamp"] <= CONNECTION_COUNT_END)
    ]
    height_df = df[
        (df["timestamp"] >= MALICIOUS_HEIGHT_START) & (df["timestamp"] <= MALICIOUS_HEIGHT_END)
    ]
    rows = [
        {
            "section": "outbound_connections",
            "metric": "samples",
            "value": len(count_df),
        },
        {
            "section": "outbound_connections",
            "metric": "total_out_first",
            "value": count_df["total_out_connections"].iloc[0] if not count_df.empty else "",
        },
        {
            "section": "outbound_connections",
            "metric": "total_out_last",
            "value": count_df["total_out_connections"].iloc[-1] if not count_df.empty else "",
        },
        {
            "section": "outbound_connections",
            "metric": "total_out_max",
            "value": count_df["total_out_connections"].max() if not count_df.empty else "",
        },
        {
            "section": "outbound_connections",
            "metric": "benign_out_first",
            "value": count_df["benign_out_connections"].iloc[0] if not count_df.empty else "",
        },
        {
            "section": "outbound_connections",
            "metric": "benign_out_last",
            "value": count_df["benign_out_connections"].iloc[-1] if not count_df.empty else "",
        },
        {
            "section": "outbound_connections",
            "metric": "benign_out_max",
            "value": count_df["benign_out_connections"].max() if not count_df.empty else "",
        },
        {
            "section": "malicious_height",
            "metric": "samples",
            "value": len(height_df),
        },
        {
            "section": "malicious_height",
            "metric": "height_gte_self_first",
            "value": height_df["malicious_out_height_gte_self"].iloc[0] if not height_df.empty else "",
        },
        {
            "section": "malicious_height",
            "metric": "height_gte_self_last",
            "value": height_df["malicious_out_height_gte_self"].iloc[-1] if not height_df.empty else "",
        },
        {
            "section": "malicious_height",
            "metric": "height_gte_self_max",
            "value": height_df["malicious_out_height_gte_self"].max() if not height_df.empty else "",
        },
        {
            "section": "benign_height",
            "metric": "height_gte_self_first",
            "value": height_df["benign_out_height_gte_self"].iloc[0] if not height_df.empty else "",
        },
        {
            "section": "benign_height",
            "metric": "height_gte_self_last",
            "value": height_df["benign_out_height_gte_self"].iloc[-1] if not height_df.empty else "",
        },
        {
            "section": "benign_height",
            "metric": "height_gte_self_max",
            "value": height_df["benign_out_height_gte_self"].max() if not height_df.empty else "",
        },
    ]
    pd.DataFrame(rows).to_csv(output_dir / "connection_count_summary.csv", index=False, encoding="utf-8-sig")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze connection counts from 2026-05-25_connections.log.")
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    raw_df = parse_connection_snapshots(args.log)
    raw_df.to_csv(output_dir / "connection_counts_raw.csv", index=False, encoding="utf-8-sig")

    count_df = raw_df[
        (raw_df["timestamp"] >= CONNECTION_COUNT_START) & (raw_df["timestamp"] <= CONNECTION_COUNT_END)
    ]
    count_min_df = minutely_last(count_df)
    count_min_df.to_csv(output_dir / "connection_counts_minutely.csv", index=False, encoding="utf-8-sig")
    minutely_stats(count_df).to_csv(
        output_dir / "connection_counts_minutely_stats.csv",
        index=False,
        encoding="utf-8-sig",
    )
    plot_outbound_snapshots(count_df, output_dir / "outbound_connection_counts_snapshots")
    plot_outbound_counts(count_min_df, output_dir / "outbound_connection_counts")

    reset_attack_df = raw_df[
        (raw_df["timestamp"] >= RESET_ATTACK_START) & (raw_df["timestamp"] <= RESET_ATTACK_END)
    ]
    reset_attack_df.to_csv(output_dir / "reset_attack_connection_counts_raw.csv", index=False, encoding="utf-8-sig")
    minutely_stats(reset_attack_df).to_csv(
        output_dir / "reset_attack_connection_counts_minutely_stats.csv",
        index=False,
        encoding="utf-8-sig",
    )
    plot_outbound_snapshots(reset_attack_df, output_dir / "reset_attack_outbound_connection_counts_snapshots")

    height_df = raw_df[
        (raw_df["timestamp"] >= MALICIOUS_HEIGHT_START) & (raw_df["timestamp"] <= MALICIOUS_HEIGHT_END)
    ].copy()
    if not height_df.empty:
        height_df["elapsed_seconds"] = (height_df["timestamp"] - MALICIOUS_HEIGHT_START).dt.total_seconds()
    height_df.to_csv(output_dir / "malicious_height_gte_self_snapshots.csv", index=False, encoding="utf-8-sig")
    height_min_df = minutely_last(height_df)
    height_min_df.to_csv(output_dir / "malicious_height_gte_self_minutely.csv", index=False, encoding="utf-8-sig")
    plot_malicious_height(height_min_df, output_dir / "malicious_out_height_gte_self")
    plot_malicious_height_snapshots(height_df, output_dir / "malicious_out_height_gte_self_snapshots")

    summarize(raw_df, output_dir)
    print(f"Output written to: {output_dir}")


if __name__ == "__main__":
    main()

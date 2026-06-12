"""
Analyze the 2026-05-28 graylist attack experiment.

This script extracts per-snapshot trash-peer occupancy from the graylist log
and summarizes gray peerlist housekeeping outcomes in the same experiment
window. It writes CSV tables and PNG/PDF figures under analysis_output.
Graylist timestamps are Beijing time. Housekeeping timestamps are UTC and are
converted to Beijing time before filtering and reporting.
"""

from __future__ import annotations

import csv
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib.pyplot as plt


BASE_DIR = Path(r"C:\Users\24407\Desktop\analysis_whitelist_graylist")
GRAYLIST_LOG = BASE_DIR / "2026-05-26_graylist.log"
HOUSEKEEPING_LOG = BASE_DIR / "filtered_peer_housekeeping.log"

OUTPUT_DIR = Path(__file__).resolve().parent / "analysis_output"

START = datetime.strptime("2026-05-28 02:38:11.654", "%Y-%m-%d %H:%M:%S.%f")
END = datetime.strptime("2026-05-28 11:22:59.096", "%Y-%m-%d %H:%M:%S.%f")
ANALYSIS_DURATION_SECONDS = 5000
ANALYSIS_END = min(END, START + timedelta(seconds=ANALYSIS_DURATION_SECONDS))
GRAYLIST_CONTEXT_BEFORE_SECONDS = 60
GRAYLIST_ANALYSIS_START = START - timedelta(seconds=GRAYLIST_CONTEXT_BEFORE_SECONDS)
UTC_TO_BEIJING = timedelta(hours=8)

TIMESTAMP_RE = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")
GRAY_HEADER_RE = re.compile(
    r"=+\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+Gray List\s+\]=+"
)
MALICIOUS_RATIO_RE = re.compile(r"malicious peer / total peer:\s*\[\s*(\d+)\s*/\s*(\d+)\s*\]")
TRASH_RATIO_RE = re.compile(r"trash peer / total peer:\s*\[\s*(\d+)\s*/\s*(\d+)\s*\]")
CONNECT_FAILED_RE = re.compile(r"Connect failed to\s+(.+?):(\d+)(?:\s|$)")
PROMOTED_RE = re.compile(r"PEER PROMOTED TO WHITE PEER LIST IP address:\s*([^\s]+)")
EVICTED_RE = re.compile(r"PEER EVICTED FROM GRAY PEER LIST:\s*address:\s*([^\s]+)")


@dataclass
class GraySnapshot:
    timestamp: datetime
    malicious_count: int | None = None
    malicious_total: int | None = None
    trash_count: int | None = None
    trash_total: int | None = None


@dataclass
class HousekeepingEvent:
    timestamp: datetime
    event_type: str
    ip: str
    port: int | None
    selected_class: str
    success: int
    failure: int
    raw_line: str


def parse_timestamp(text: str) -> datetime | None:
    match = TIMESTAMP_RE.search(text)
    if not match:
        return None
    value = match.group(1)
    fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in value else "%Y-%m-%d %H:%M:%S"
    return datetime.strptime(value, fmt)


def parse_graylist_snapshots(path: Path) -> list[GraySnapshot]:
    snapshots: list[GraySnapshot] = []
    current: GraySnapshot | None = None

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            header = GRAY_HEADER_RE.search(line)
            if header:
                if (
                    current
                    and GRAYLIST_ANALYSIS_START <= current.timestamp <= ANALYSIS_END
                    and current.trash_count is not None
                ):
                    snapshots.append(current)
                ts_value = header.group("ts")
                fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in ts_value else "%Y-%m-%d %H:%M:%S"
                current = GraySnapshot(timestamp=datetime.strptime(ts_value, fmt))
                continue

            if current is None:
                continue

            malicious_match = MALICIOUS_RATIO_RE.search(line)
            if malicious_match:
                current.malicious_count = int(malicious_match.group(1))
                current.malicious_total = int(malicious_match.group(2))
                continue

            trash_match = TRASH_RATIO_RE.search(line)
            if trash_match:
                current.trash_count = int(trash_match.group(1))
                current.trash_total = int(trash_match.group(2))

    if (
        current
        and GRAYLIST_ANALYSIS_START <= current.timestamp <= ANALYSIS_END
        and current.trash_count is not None
    ):
        snapshots.append(current)

    return snapshots


def write_graylist_snapshot_csv(snapshots: list[GraySnapshot], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "timestamp",
                "elapsed_seconds",
                "trash_peer",
                "total_peer",
                "trash_peer_per_total_peer",
                "malicious_peer",
                "malicious_total_peer",
            ],
        )
        writer.writeheader()
        for snapshot in snapshots:
            total = snapshot.trash_total or 0
            ratio = snapshot.trash_count / total if total else math.nan
            writer.writerow(
                {
                    "timestamp": snapshot.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "elapsed_seconds": round((snapshot.timestamp - START).total_seconds(), 3),
                    "trash_peer": snapshot.trash_count,
                    "total_peer": snapshot.trash_total,
                    "trash_peer_per_total_peer": ratio,
                    "malicious_peer": snapshot.malicious_count,
                    "malicious_total_peer": snapshot.malicious_total,
                }
            )


def plot_trash_area_line(snapshots: list[GraySnapshot], png_path: Path, pdf_path: Path) -> None:
    x = [(snapshot.timestamp - GRAYLIST_ANALYSIS_START).total_seconds() for snapshot in snapshots]
    y = [snapshot.trash_count or 0 for snapshot in snapshots]

    fig, ax = plt.subplots(figsize=(8.4, 6))
    ax.fill_between(x, y, color="#4c78a8", alpha=0.18)
    ax.plot(x, y, color="#2f5f8f", linewidth=1.8)
    ax.set_xlabel("timestamps(s)", fontsize=20)
    ax.set_ylabel("Trash peer count", fontsize=20)
    ax.set_xlim(0, (ANALYSIS_END - GRAYLIST_ANALYSIS_START).total_seconds())
    ax.set_ylim(0, 5000)
    ax.tick_params(axis="both", labelsize=18)
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(png_path, dpi=220)
    fig.savefig(pdf_path)
    plt.close(fig)


def parse_housekeeping_events(path: Path) -> list[HousekeepingEvent]:
    events: list[HousekeepingEvent] = []
    pending_failed_by_ip: dict[str, tuple[datetime, int, str]] = {}

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            ts = parse_timestamp(line)
            if ts is None:
                continue
            ts = ts + UTC_TO_BEIJING
            if ts < START - timedelta(seconds=5) or ts > ANALYSIS_END + timedelta(seconds=5):
                continue

            failed = CONNECT_FAILED_RE.search(line)
            if failed:
                ip = failed.group(1).strip().strip("[]")
                port = int(failed.group(2))
                pending_failed_by_ip[ip] = (ts, port, line.strip())
                continue

            promoted = PROMOTED_RE.search(line)
            if promoted and START <= ts <= ANALYSIS_END:
                ip = promoted.group(1).strip().strip("[]")
                events.append(
                    HousekeepingEvent(
                        timestamp=ts,
                        event_type="promoted_to_whitelist",
                        ip=ip,
                        port=None,
                        selected_class="benign",
                        success=1,
                        failure=0,
                        raw_line=line.strip(),
                    )
                )
                continue

            evicted = EVICTED_RE.search(line)
            if evicted and START <= ts <= ANALYSIS_END:
                ip = evicted.group(1).strip().strip("[]")
                pending = pending_failed_by_ip.get(ip)
                port = pending[1] if pending else None
                selected_class = "trash" if port == 28086 else "benign"
                events.append(
                    HousekeepingEvent(
                        timestamp=ts,
                        event_type="evicted_after_connect_failure",
                        ip=ip,
                        port=port,
                        selected_class=selected_class,
                        success=0,
                        failure=1,
                        raw_line=line.strip(),
                    )
                )

    events.sort(key=lambda event: event.timestamp)
    return events


def write_housekeeping_csv(events: list[HousekeepingEvent], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "timestamp",
                "elapsed_seconds",
                "event_type",
                "ip",
                "port",
                "selected_class",
                "success",
                "failure",
                "raw_line",
            ],
        )
        writer.writeheader()
        for event in events:
            writer.writerow(
                {
                    "timestamp": event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "elapsed_seconds": round((event.timestamp - START).total_seconds(), 3),
                    "event_type": event.event_type,
                    "ip": event.ip,
                    "port": event.port if event.port is not None else "",
                    "selected_class": event.selected_class,
                    "success": event.success,
                    "failure": event.failure,
                    "raw_line": event.raw_line,
                }
            )


def summarize_housekeeping(events: list[HousekeepingEvent]) -> dict[str, int | float | str]:
    observed = len(events)
    trash_selected = sum(1 for event in events if event.selected_class == "trash")
    success = sum(event.success for event in events)
    failure = sum(event.failure for event in events)
    benign_selected = observed - trash_selected
    expected_once_per_minute_from_duration = math.floor((ANALYSIS_END - START).total_seconds() / 60) + 1
    expected_minute_boundaries = 0
    tick = START.replace(second=0, microsecond=0)
    if tick < START:
        tick += timedelta(minutes=1)
    while tick <= ANALYSIS_END:
        expected_minute_boundaries += 1
        tick += timedelta(minutes=1)

    first_event = events[0].timestamp if events else None
    last_event = events[-1].timestamp if events else None
    expected_until_last_observed = (
        math.floor((last_event - START).total_seconds() / 60) + 1 if last_event else 0
    )

    return {
        "experiment_start": START.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "experiment_end": END.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "analysis_end": ANALYSIS_END.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "analysis_duration_seconds": ANALYSIS_DURATION_SECONDS,
        "first_observed_housekeeping_event": (
            first_event.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if first_event else ""
        ),
        "last_observed_housekeeping_event": (
            last_event.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if last_event else ""
        ),
        "housekeeping_observed_events": observed,
        "expected_once_per_minute_from_duration": expected_once_per_minute_from_duration,
        "expected_minute_boundary_events": expected_minute_boundaries,
        "expected_once_per_minute_until_last_observed": expected_until_last_observed,
        "selected_benign": benign_selected,
        "selected_trash_port_28086": trash_selected,
        "success_promoted_to_whitelist": success,
        "failure_evicted_after_connect_failure": failure,
        "failure_trash_port_28086": sum(1 for event in events if event.failure and event.selected_class == "trash"),
        "failure_benign": sum(
            1 for event in events if event.failure and event.selected_class != "trash"
        ),
    }


def write_summary_csv(summary: dict[str, int | float | str], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["metric", "value"])
        writer.writeheader()
        for key, value in summary.items():
            writer.writerow({"metric": key, "value": value})


def main() -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)

    snapshots = parse_graylist_snapshots(GRAYLIST_LOG)
    snapshot_csv = OUTPUT_DIR / "graylist_20260528_first5000s_snapshots.csv"
    snapshot_png = OUTPUT_DIR / "graylist_20260528_first5000s_trash_count_snapshots.png"
    snapshot_pdf = OUTPUT_DIR / "graylist_20260528_first5000s_trash_count_snapshots.pdf"
    write_graylist_snapshot_csv(snapshots, snapshot_csv)
    plot_trash_area_line(snapshots, snapshot_png, snapshot_pdf)

    housekeeping_events = parse_housekeeping_events(HOUSEKEEPING_LOG)
    housekeeping_csv = OUTPUT_DIR / "graylist_20260528_first5000s_housekeeping_events.csv"
    summary_csv = OUTPUT_DIR / "graylist_20260528_first5000s_housekeeping_summary.csv"
    write_housekeeping_csv(housekeeping_events, housekeeping_csv)
    summary = summarize_housekeeping(housekeeping_events)
    write_summary_csv(summary, summary_csv)

    if snapshots:
        first = snapshots[0]
        last = snapshots[-1]
        avg_trash = sum(snapshot.trash_count or 0 for snapshot in snapshots) / len(snapshots)
        max_trash = max(snapshot.trash_count or 0 for snapshot in snapshots)
        print(f"Graylist snapshots: {len(snapshots)}")
        print(f"First snapshot: {first.timestamp} trash={first.trash_count}/{first.trash_total}")
        print(f"Last snapshot: {last.timestamp} trash={last.trash_count}/{last.trash_total}")
        print(f"Average trash count: {avg_trash:.2f}; max trash count: {max_trash}")
    else:
        print("Graylist snapshots: 0")

    print("Housekeeping summary:")
    for key, value in summary.items():
        print(f"  {key}: {value}")
    print(f"Wrote: {snapshot_csv}")
    print(f"Wrote: {snapshot_png}")
    print(f"Wrote: {snapshot_pdf}")
    print(f"Wrote: {housekeeping_csv}")
    print(f"Wrote: {summary_csv}")


if __name__ == "__main__":
    main()

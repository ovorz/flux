"""
Count graylist connection selections during the first 5000 seconds of the
2026-05-26 graylist attack experiment.

The analysis window is 2026-05-26 00:41:57.228 to 2026-05-26 02:05:17.228
in Beijing time. A selected gray peer with port 28086 is treated as a trash
record. Connection Success/failed lines are paired with the most recent
selected gray peer address.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path


BASE_DIR = Path(r"C:\Users\24407\Desktop\analysis_whitelist_graylist")
CONNECTION_LOG = BASE_DIR / "2026-05-26_connections.log"
OUTPUT_DIR = Path(__file__).resolve().parent / "analysis_output"

START = datetime.fromisoformat("2026-05-26 00:41:57.228")
END = START + timedelta(seconds=5000)
TRASH_PORT = 28086

TS_RE = re.compile(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\]")
GRAY_START_RE = re.compile(r"Start Selecting peer from peerlist - \[gray\]")
SELECTED_GRAY_RE = re.compile(
    r"Selected peer: .*?((?:\d{1,3}\.){3}\d{1,3}):(\d+).*?\[peer_list=gray\]"
)
CONNECTION_RESULT_RE = re.compile(
    r"Connection\s+(Success|success|failed)\s+with peer:\s+\[((?:\d{1,3}\.){3}\d{1,3}):(\d+)\]"
)


@dataclass
class GraySelection:
    selected_timestamp: datetime
    ip: str
    port: int
    is_trash: bool
    result_timestamp: datetime | None = None
    result: str = "unknown"
    raw_selected_line: str = ""
    raw_result_line: str = ""


def parse_timestamp(line: str) -> datetime | None:
    match = TS_RE.search(line)
    if not match:
        return None
    return datetime.fromisoformat(match.group(1))


def parse_events(path: Path) -> tuple[int, list[GraySelection]]:
    gray_start_count = 0
    selections: list[GraySelection] = []
    pending: dict[tuple[str, int], list[int]] = {}

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            ts = parse_timestamp(line)
            if ts is None:
                continue
            if ts < START:
                continue
            if ts > END:
                break

            if GRAY_START_RE.search(line):
                gray_start_count += 1
                continue

            selected = SELECTED_GRAY_RE.search(line)
            if selected:
                ip = selected.group(1)
                port = int(selected.group(2))
                event = GraySelection(
                    selected_timestamp=ts,
                    ip=ip,
                    port=port,
                    is_trash=(port == TRASH_PORT),
                    raw_selected_line=line.strip(),
                )
                selections.append(event)
                pending.setdefault((ip, port), []).append(len(selections) - 1)
                continue

            result = CONNECTION_RESULT_RE.search(line)
            if result:
                status = result.group(1).lower()
                ip = result.group(2)
                port = int(result.group(3))
                key = (ip, port)
                if key not in pending or not pending[key]:
                    continue
                idx = pending[key].pop(0)
                selections[idx].result_timestamp = ts
                selections[idx].result = "success" if status == "success" else "failed"
                selections[idx].raw_result_line = line.strip()

    return gray_start_count, selections


def write_events_csv(selections: list[GraySelection], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "selected_timestamp",
                "elapsed_seconds",
                "ip",
                "port",
                "is_trash_port_28086",
                "result_timestamp",
                "result",
                "raw_selected_line",
                "raw_result_line",
            ],
        )
        writer.writeheader()
        for event in selections:
            writer.writerow(
                {
                    "selected_timestamp": event.selected_timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "elapsed_seconds": round((event.selected_timestamp - START).total_seconds(), 3),
                    "ip": event.ip,
                    "port": event.port,
                    "is_trash_port_28086": int(event.is_trash),
                    "result_timestamp": (
                        event.result_timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                        if event.result_timestamp
                        else ""
                    ),
                    "result": event.result,
                    "raw_selected_line": event.raw_selected_line,
                    "raw_result_line": event.raw_result_line,
                }
            )


def summarize(gray_start_count: int, selections: list[GraySelection]) -> dict[str, int | str]:
    selected_trash = sum(1 for event in selections if event.is_trash)
    selected_benign = sum(1 for event in selections if not event.is_trash)
    benign_success = sum(1 for event in selections if not event.is_trash and event.result == "success")
    benign_failed = sum(1 for event in selections if not event.is_trash and event.result == "failed")
    trash_failed = sum(1 for event in selections if event.is_trash and event.result == "failed")
    trash_success = sum(1 for event in selections if event.is_trash and event.result == "success")
    unknown = sum(1 for event in selections if event.result == "unknown")

    return {
        "analysis_start": START.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "analysis_end": END.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "duration_seconds": 5000,
        "gray_start_selecting_lines": gray_start_count,
        "gray_selected_valid_candidates": len(selections),
        "selected_trash_port_28086": selected_trash,
        "selected_benign": selected_benign,
        "selected_benign_success": benign_success,
        "selected_benign_failed": benign_failed,
        "selected_trash_failed": trash_failed,
        "selected_trash_success": trash_success,
        "selected_unknown_result": unknown,
    }


def write_summary_csv(summary: dict[str, int | str], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        writer.writerows(summary.items())


def main() -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)
    gray_start_count, selections = parse_events(CONNECTION_LOG)
    summary = summarize(gray_start_count, selections)

    events_csv = OUTPUT_DIR / "graylist_20260526_first5000s_connection_selections.csv"
    summary_csv = OUTPUT_DIR / "graylist_20260526_first5000s_connection_selection_summary.csv"
    write_events_csv(selections, events_csv)
    write_summary_csv(summary, summary_csv)

    print("Graylist connection selection summary:")
    for key, value in summary.items():
        print(f"  {key}: {value}")
    print(f"Wrote: {events_csv}")
    print(f"Wrote: {summary_csv}")


if __name__ == "__main__":
    main()

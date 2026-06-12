# analyze_connections_20rounds.py

"""日志文件的一部分内容是这样的，日志文件名称是2026-05-20_connections.log，
位置在r"C:\\Users\\24407\\Desktop\\20times_reset_1000_data"。我们进行了20次实验，
实验进行的时间如下所示。请写python代码来分析实验数据，恶意节点的IP是152.136.24.233，
其它IP是良性节点。统计每次实验，从实验开始到良性传出连接（OUT）数量降为0共花了多长时间，
以及每次实验，从实验结束到传出连接中良性节点的数量达到2花了多长时间"""

# analyze_20rounds_connections.py
import re
import csv
import math
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

import matplotlib

# 使用非交互式后端，只保存图片，不弹出窗口，避免 Tcl/Tk 报错
matplotlib.use("Agg")

import matplotlib.pyplot as plt

# ==========================
# 1. 基本配置
# ==========================

LOG_FILE = Path(r"C:\Users\24407\Desktop\20times_reset_1000_data\2026-05-20_connections.log")

OUTPUT_DIR = LOG_FILE.parent

OUTPUT_CSV = OUTPUT_DIR / "20_rounds_time_cost_stats.csv"

OUTPUT_ZERO_PNG = OUTPUT_DIR / "time_to_benign_out_zero.png"
OUTPUT_ZERO_PDF = OUTPUT_DIR / "time_to_benign_out_zero.pdf"

OUTPUT_RECOVERY_PNG = OUTPUT_DIR / "time_to_recovery_2_benign_out.png"
OUTPUT_RECOVERY_PDF = OUTPUT_DIR / "time_to_recovery_2_benign_out.pdf"

OUTPUT_COMBINED_PNG = OUTPUT_DIR / "20_rounds_time_cost_combined.png"
OUTPUT_COMBINED_PDF = OUTPUT_DIR / "20_rounds_time_cost_combined.pdf"

MALICIOUS_IP = "152.136.24.233"

# 良性 OUT 恢复阈值：达到 2 条
RECOVERY_THRESHOLD = 2

# 攻击阶段统计范围：
# False：从 start_time 到 end_time 内寻找“良性 OUT 降为 0”
# True ：从 start_time 到 stop_time 内寻找“良性 OUT 降为 0”
USE_STOP_TIME_AS_ATTACK_END = False


# ==========================
# 2. 实验时间
# ==========================

EXPERIMENT_TEXT = r"""
round=1, start_time=2026-05-20 00:53:05, stop_time=2026-05-20 01:18:27, end_time=2026-05-20 01:18:39
round=2, start_time=2026-05-20 01:43:39, stop_time=2026-05-20 02:09:01, end_time=2026-05-20 02:09:11
round=3, start_time=2026-05-20 02:34:11, stop_time=2026-05-20 02:59:33, end_time=2026-05-20 02:59:44
round=4, start_time=2026-05-20 03:24:44, stop_time=2026-05-20 03:50:06, end_time=2026-05-20 03:50:16
round=5, start_time=2026-05-20 04:15:16, stop_time=2026-05-20 04:40:38, end_time=2026-05-20 04:40:49
round=6, start_time=2026-05-20 05:05:49, stop_time=2026-05-20 05:31:11, end_time=2026-05-20 05:31:22
round=7, start_time=2026-05-20 05:56:22, stop_time=2026-05-20 06:21:44, end_time=2026-05-20 06:21:55
round=8, start_time=2026-05-20 06:46:55, stop_time=2026-05-20 07:12:17, end_time=2026-05-20 07:12:28
round=9, start_time=2026-05-20 07:37:28, stop_time=2026-05-20 08:02:51, end_time=2026-05-20 08:03:02
round=10, start_time=2026-05-20 08:28:02, stop_time=2026-05-20 08:53:24, end_time=2026-05-20 08:53:34
round=11, start_time=2026-05-20 09:18:34, stop_time=2026-05-20 09:43:56, end_time=2026-05-20 09:44:07
round=12, start_time=2026-05-20 10:09:07, stop_time=2026-05-20 10:34:29, end_time=2026-05-20 10:34:39
round=13, start_time=2026-05-20 10:59:39, stop_time=2026-05-20 11:25:01, end_time=2026-05-20 11:25:12
round=14, start_time=2026-05-20 11:50:12, stop_time=2026-05-20 12:15:34, end_time=2026-05-20 12:15:45
round=15, start_time=2026-05-20 12:40:45, stop_time=2026-05-20 13:06:07, end_time=2026-05-20 13:06:17
round=16, start_time=2026-05-20 13:31:17, stop_time=2026-05-20 13:56:40, end_time=2026-05-20 13:56:50
round=17, start_time=2026-05-20 14:21:50, stop_time=2026-05-20 14:47:13, end_time=2026-05-20 14:47:23
round=18, start_time=2026-05-20 15:12:23, stop_time=2026-05-20 15:37:45, end_time=2026-05-20 15:37:56
round=19, start_time=2026-05-20 16:02:56, stop_time=2026-05-20 16:28:18, end_time=2026-05-20 16:28:29
round=20, start_time=2026-05-20 16:53:29, stop_time=2026-05-20 17:18:51, end_time=2026-05-20 17:19:01
"""


# ==========================
# 3. 工具函数
# ==========================

def parse_time(s: str) -> datetime:
    return datetime.strptime(s.strip(), "%Y-%m-%d %H:%M:%S")


def format_dt(dt: Optional[datetime]) -> str:
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def seconds_to_hms(seconds: Optional[float]) -> str:
    if seconds is None:
        return ""

    seconds = int(round(seconds))
    h = seconds // 3600
    m = seconds % 3600 // 60
    s = seconds % 60

    return f"{h:02d}:{m:02d}:{s:02d}"


def safe_mean(values: List[float]) -> Optional[float]:
    valid_values = [v for v in values if v is not None and not math.isnan(v)]

    if not valid_values:
        return None

    return sum(valid_values) / len(valid_values)


def parse_experiments(text: str) -> List[Dict]:
    pattern = re.compile(
        r"round=(\d+),\s*"
        r"start_time=([\d\-]+\s+[\d:]+),\s*"
        r"stop_time=([\d\-]+\s+[\d:]+),\s*"
        r"end_time=([\d\-]+\s+[\d:]+)"
    )

    experiments = []

    for m in pattern.finditer(text):
        experiments.append({
            "round": int(m.group(1)),
            "start_time": parse_time(m.group(2)),
            "stop_time": parse_time(m.group(3)),
            "end_time": parse_time(m.group(4)),
        })

    experiments.sort(key=lambda x: x["round"])

    return experiments


# ==========================
# 4. 解析 Current Connections 快照
# ==========================

def parse_connection_snapshots(log_file: Path) -> List[Dict]:
    """
    解析日志中的每个 Current Connections 快照。

    每个快照统计：
    1. benign_out：良性 OUT 数量
    2. malicious_out：恶意 OUT 数量
    3. total_out：总 OUT 数量
    4. benign_inc：良性 INC 数量
    5. malicious_inc：恶意 INC 数量
    6. total_inc：总 INC 数量
    """

    header_re = re.compile(
        r"=+\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+Current Connections\s*\]=+"
    )

    peer_re = re.compile(
        r"Peer addr:\s*\[\s*([^:\],\s]+):\d+,\s*(OUT|INC),\s*(-?\d+),\s*([^\]]+)\]"
    )

    snapshots = []
    current = None

    with log_file.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            header_match = header_re.search(line)

            if header_match:
                if current is not None:
                    snapshots.append(current)

                current = {
                    "time": datetime.strptime(
                        header_match.group(1),
                        "%Y-%m-%d %H:%M:%S.%f"
                    ),
                    "benign_out": 0,
                    "malicious_out": 0,
                    "total_out": 0,
                    "benign_inc": 0,
                    "malicious_inc": 0,
                    "total_inc": 0,
                }

                continue

            if current is None:
                continue

            peer_match = peer_re.search(line)

            if not peer_match:
                continue

            ip = peer_match.group(1)
            direction = peer_match.group(2)

            is_malicious = ip == MALICIOUS_IP

            if direction == "OUT":
                current["total_out"] += 1

                if is_malicious:
                    current["malicious_out"] += 1
                else:
                    current["benign_out"] += 1

            elif direction == "INC":
                current["total_inc"] += 1

                if is_malicious:
                    current["malicious_inc"] += 1
                else:
                    current["benign_inc"] += 1

    if current is not None:
        snapshots.append(current)

    snapshots.sort(key=lambda x: x["time"])

    return snapshots


def find_first_snapshot(
    snapshots: List[Dict],
    start: datetime,
    end: Optional[datetime],
    condition
) -> Optional[Dict]:
    """
    在 [start, end] 范围内寻找第一个满足 condition 的快照。
    end=None 表示不限制结束时间。
    """

    for snap in snapshots:
        t = snap["time"]

        if t < start:
            continue

        if end is not None and t > end:
            break

        if condition(snap):
            return snap

    return None


def find_latest_snapshot_before_or_at(
    snapshots: List[Dict],
    target_time: datetime
) -> Optional[Dict]:
    latest = None

    for snap in snapshots:
        if snap["time"] <= target_time:
            latest = snap
        else:
            break

    return latest


# ==========================
# 5. 绘图函数
# ==========================

def plot_single_metric(
    rows: List[Dict],
    y_key: str,
    title: str,
    ylabel: str,
    output_png: Path,
    output_pdf: Path
):
    rounds = []
    values_min = []

    for row in rows:
        rounds.append(row["round"])

        value = row[y_key]
        if value == "" or value is None:
            values_min.append(float("nan"))
        else:
            values_min.append(float(value) / 60.0)

    valid_values = [v for v in values_min if not math.isnan(v)]
    avg_value = safe_mean(valid_values)

    plt.figure(figsize=(9, 5))

    plt.plot(
        rounds,
        values_min,
        marker="o",
        linewidth=2,
        label="Time cost"
    )

    if avg_value is not None:
        plt.axhline(
            avg_value,
            linestyle="--",
            linewidth=1.8,
            label=f"Average = {avg_value:.2f} min"
        )

        plt.text(
            rounds[-1],
            avg_value,
            f"  Avg: {avg_value:.2f} min",
            va="bottom",
            fontsize=10
        )

    plt.xlabel("Round")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.xticks(rounds)
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.legend()
    plt.tight_layout()

    plt.savefig(output_png, dpi=300)
    plt.savefig(output_pdf)
    plt.close()


def plot_combined_metric(rows: List[Dict]):
    rounds = []
    zero_values_min = []
    recovery_values_min = []

    for row in rows:
        rounds.append(row["round"])

        zero_value = row["time_to_benign_out_zero_seconds"]
        recovery_value = row["recovery_to_2_seconds"]

        if zero_value == "" or zero_value is None:
            zero_values_min.append(float("nan"))
        else:
            zero_values_min.append(float(zero_value) / 60.0)

        if recovery_value == "" or recovery_value is None:
            recovery_values_min.append(float("nan"))
        else:
            recovery_values_min.append(float(recovery_value) / 60.0)

    avg_zero = safe_mean([v for v in zero_values_min if not math.isnan(v)])
    avg_recovery = safe_mean([v for v in recovery_values_min if not math.isnan(v)])

    plt.figure(figsize=(10, 5.5))

    plt.plot(
        rounds,
        zero_values_min,
        marker="o",
        linewidth=2,
        label="Start to benign OUT = 0"
    )

    plt.plot(
        rounds,
        recovery_values_min,
        marker="s",
        linewidth=2,
        label="End to benign OUT >= 2"
    )

    if avg_zero is not None:
        plt.axhline(
            avg_zero,
            linestyle="--",
            linewidth=1.6,
            label=f"Average zero time = {avg_zero:.2f} min"
        )

        plt.text(
            rounds[-1],
            avg_zero,
            f"  Avg zero: {avg_zero:.2f} min",
            va="bottom",
            fontsize=9
        )

    if avg_recovery is not None:
        plt.axhline(
            avg_recovery,
            linestyle=":",
            linewidth=2.0,
            label=f"Average recovery time = {avg_recovery:.2f} min"
        )

        plt.text(
            rounds[-1],
            avg_recovery,
            f"  Avg recovery: {avg_recovery:.2f} min",
            va="bottom",
            fontsize=9
        )

    plt.xlabel("Round")
    plt.ylabel("Time Cost (min)")
    plt.title("Time Cost of Each Round")
    plt.xticks(rounds)
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.legend()
    plt.tight_layout()

    plt.savefig(OUTPUT_COMBINED_PNG, dpi=300)
    plt.savefig(OUTPUT_COMBINED_PDF)
    plt.close()


# ==========================
# 6. 主分析逻辑
# ==========================

def analyze_rounds(experiments: List[Dict], snapshots: List[Dict]) -> List[Dict]:
    rows = []

    for i, exp in enumerate(experiments):
        round_id = exp["round"]
        start_time = exp["start_time"]
        stop_time = exp["stop_time"]
        end_time = exp["end_time"]

        next_start_time = experiments[i + 1]["start_time"] if i + 1 < len(experiments) else None

        attack_search_end = stop_time if USE_STOP_TIME_AS_ATTACK_END else end_time

        # 1. 从实验开始到良性 OUT 数量第一次降为 0
        zero_snap = find_first_snapshot(
            snapshots=snapshots,
            start=start_time,
            end=attack_search_end,
            condition=lambda s: s["benign_out"] == 0
        )

        if zero_snap is not None:
            time_to_zero_seconds = (zero_snap["time"] - start_time).total_seconds()
        else:
            time_to_zero_seconds = None

        # 2. 从实验结束到良性 OUT 数量第一次达到 >= 2
        # 为了避免串到下一轮实验，搜索范围限制为 [end_time, next_start_time]
        recovery_snap = find_first_snapshot(
            snapshots=snapshots,
            start=end_time,
            end=next_start_time,
            condition=lambda s: s["benign_out"] >= RECOVERY_THRESHOLD
        )

        if recovery_snap is not None:
            recovery_seconds = (recovery_snap["time"] - end_time).total_seconds()
        else:
            recovery_seconds = None

        # 辅助记录：start_time、stop_time、end_time 附近最近的快照状态
        start_snap = find_latest_snapshot_before_or_at(snapshots, start_time)
        stop_snap = find_latest_snapshot_before_or_at(snapshots, stop_time)
        end_snap = find_latest_snapshot_before_or_at(snapshots, end_time)

        row = {
            "round": round_id,

            "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "stop_time": stop_time.strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": end_time.strftime("%Y-%m-%d %H:%M:%S"),

            "start_snapshot_time": format_dt(start_snap["time"]) if start_snap else "",
            "start_benign_out": start_snap["benign_out"] if start_snap else "",
            "start_malicious_out": start_snap["malicious_out"] if start_snap else "",
            "start_total_out": start_snap["total_out"] if start_snap else "",

            "stop_snapshot_time": format_dt(stop_snap["time"]) if stop_snap else "",
            "stop_benign_out": stop_snap["benign_out"] if stop_snap else "",
            "stop_malicious_out": stop_snap["malicious_out"] if stop_snap else "",
            "stop_total_out": stop_snap["total_out"] if stop_snap else "",

            "end_snapshot_time": format_dt(end_snap["time"]) if end_snap else "",
            "end_benign_out": end_snap["benign_out"] if end_snap else "",
            "end_malicious_out": end_snap["malicious_out"] if end_snap else "",
            "end_total_out": end_snap["total_out"] if end_snap else "",

            "benign_out_zero_time": format_dt(zero_snap["time"]) if zero_snap else "",
            "time_to_benign_out_zero_seconds": round(time_to_zero_seconds, 3) if time_to_zero_seconds is not None else "",
            "time_to_benign_out_zero_minutes": round(time_to_zero_seconds / 60.0, 3) if time_to_zero_seconds is not None else "",
            "time_to_benign_out_zero_hms": seconds_to_hms(time_to_zero_seconds),

            "zero_time_benign_out": zero_snap["benign_out"] if zero_snap else "",
            "zero_time_malicious_out": zero_snap["malicious_out"] if zero_snap else "",
            "zero_time_total_out": zero_snap["total_out"] if zero_snap else "",

            "recovery_to_2_time": format_dt(recovery_snap["time"]) if recovery_snap else "",
            "recovery_to_2_seconds": round(recovery_seconds, 3) if recovery_seconds is not None else "",
            "recovery_to_2_minutes": round(recovery_seconds / 60.0, 3) if recovery_seconds is not None else "",
            "recovery_to_2_hms": seconds_to_hms(recovery_seconds),

            "recovery_benign_out": recovery_snap["benign_out"] if recovery_snap else "",
            "recovery_malicious_out": recovery_snap["malicious_out"] if recovery_snap else "",
            "recovery_total_out": recovery_snap["total_out"] if recovery_snap else "",

            "next_round_start_time": next_start_time.strftime("%Y-%m-%d %H:%M:%S") if next_start_time else "",
        }

        rows.append(row)

    return rows


def save_rows_to_csv(rows: List[Dict], output_csv: Path):
    if not rows:
        raise RuntimeError("没有可写入 CSV 的统计结果。")

    fieldnames = list(rows[0].keys())

    with output_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def print_summary(rows: List[Dict]):
    zero_values = [
        float(r["time_to_benign_out_zero_seconds"])
        for r in rows
        if r["time_to_benign_out_zero_seconds"] != ""
    ]

    recovery_values = [
        float(r["recovery_to_2_seconds"])
        for r in rows
        if r["recovery_to_2_seconds"] != ""
    ]

    avg_zero = safe_mean(zero_values)
    avg_recovery = safe_mean(recovery_values)

    print()
    print("round | 降为0耗时 | 恢复到>=2耗时 | 降为0时间 | 恢复时间")
    print("-" * 110)

    for r in rows:
        zero_hms = r["time_to_benign_out_zero_hms"] if r["time_to_benign_out_zero_hms"] else "未达到"
        recovery_hms = r["recovery_to_2_hms"] if r["recovery_to_2_hms"] else "未达到"

        zero_time = r["benign_out_zero_time"] if r["benign_out_zero_time"] else "-"
        recovery_time = r["recovery_to_2_time"] if r["recovery_to_2_time"] else "-"

        print(
            f"{r['round']:>5} | "
            f"{zero_hms:>10} | "
            f"{recovery_hms:>14} | "
            f"{zero_time} | "
            f"{recovery_time}"
        )

    print("-" * 110)

    if avg_zero is not None:
        print(f"良性 OUT 降为 0 的平均耗时：{avg_zero:.3f} 秒，约 {avg_zero / 60.0:.3f} 分钟，{seconds_to_hms(avg_zero)}")
    else:
        print("良性 OUT 降为 0 的平均耗时：无有效数据")

    if avg_recovery is not None:
        print(f"良性 OUT 恢复到 >=2 的平均耗时：{avg_recovery:.3f} 秒，约 {avg_recovery / 60.0:.3f} 分钟，{seconds_to_hms(avg_recovery)}")
    else:
        print("良性 OUT 恢复到 >=2 的平均耗时：无有效数据")


def main():
    if not LOG_FILE.exists():
        raise FileNotFoundError(f"日志文件不存在：{LOG_FILE}")

    experiments = parse_experiments(EXPERIMENT_TEXT)

    if len(experiments) != 20:
        print(f"警告：当前解析到的实验轮次数量为 {len(experiments)}，不是 20。")

    snapshots = parse_connection_snapshots(LOG_FILE)

    if not snapshots:
        raise RuntimeError("没有解析到任何 Current Connections 快照，请检查日志格式。")

    rows = analyze_rounds(experiments, snapshots)

    save_rows_to_csv(rows, OUTPUT_CSV)

    plot_single_metric(
        rows=rows,
        y_key="time_to_benign_out_zero_seconds",
        title="Time from Experiment Start to Benign OUT Connections Dropping to 0",
        ylabel="Time Cost (min)",
        output_png=OUTPUT_ZERO_PNG,
        output_pdf=OUTPUT_ZERO_PDF
    )

    plot_single_metric(
        rows=rows,
        y_key="recovery_to_2_seconds",
        title="Time from Experiment End to Benign OUT Connections Recovering to 2",
        ylabel="Time Cost (min)",
        output_png=OUTPUT_RECOVERY_PNG,
        output_pdf=OUTPUT_RECOVERY_PDF
    )

    plot_combined_metric(rows)

    print(f"解析到 Current Connections 快照数量：{len(snapshots)}")
    print(f"统计 CSV 已保存到：{OUTPUT_CSV}")
    print(f"良性 OUT 降为 0 耗时图 PNG 已保存到：{OUTPUT_ZERO_PNG}")
    print(f"良性 OUT 降为 0 耗时图 PDF 已保存到：{OUTPUT_ZERO_PDF}")
    print(f"良性 OUT 恢复到 >=2 耗时图 PNG 已保存到：{OUTPUT_RECOVERY_PNG}")
    print(f"良性 OUT 恢复到 >=2 耗时图 PDF 已保存到：{OUTPUT_RECOVERY_PDF}")
    print(f"综合对比图 PNG 已保存到：{OUTPUT_COMBINED_PNG}")
    print(f"综合对比图 PDF 已保存到：{OUTPUT_COMBINED_PDF}")

    print_summary(rows)


if __name__ == "__main__":
    main()
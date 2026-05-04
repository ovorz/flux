import json
import sqlite3
from pathlib import Path

def init_db(db_path):
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS measurements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        out_conn TEXT NOT NULL,
        ground_truth TEXT NOT NULL
    );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_time ON measurements(timestamp);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_node ON measurements(node);")
    conn.commit()
    conn.close()

def insert_sqlite(db_path, node, timestamp, out_conn, ground_truth):
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    # WAL 已在 init 时启用，不必每次都开
    conn.execute(
        "INSERT INTO measurements (node, timestamp, out_conn, ground_truth) VALUES (?, ?, ?, ?)",
        (node, timestamp, json.dumps(out_conn, ensure_ascii=False),
         json.dumps(ground_truth, ensure_ascii=False))
    )
    conn.commit()
    conn.close()


def main():
    base_dir = Path(__file__).resolve().parent
    db_path = base_dir / "topo_data.db"
    init_db(db_path)
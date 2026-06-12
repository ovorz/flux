import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
from sqlalchemy import create_engine, select, text, Table, MetaData
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta, timezone
# import netifaces
import ipaddress

from levin_async.constants import NETWORK_ID_MAINNET, NETWORK_ID_TESTNET



#LOCAL_P2P_LISTEN_PORT = 18082

'''IP_RANGES = [
    "154.199.217.1-154.199.217.253",
    "38.6.155.1-38.6.155.253",
    "38.6.156.1-38.6.156.253",
    "38.6.157.1-38.6.157.253",
]

IP_RANGES_TOTAL = [
    "154.199.217.1-154.199.217.253",
    "38.6.155.1-38.6.155.253",
    "38.6.156.1-38.6.156.253",
    "38.6.157.1-38.6.157.253",
    "38.12.182.1-38.12.182.253",
    "38.173.81.1-38.173.81.253",
    "154.202.255.1-154.202.255.253",
    "38.6.220.1-38.6.220.253",
]'''

NET_MODE = "testnet"  # 可选 "mainnet"、"testnet"

if NET_MODE == "mainnet":
    NETWORK_ID = NETWORK_ID_MAINNET
    REAL_TIME_DATABASE_NAME = "xmr_mainnet"
    HISTORY_DATABASE_NAME = "xmr_mainnet_every_day"
    TARGET_RPC_PORT = 18081
elif NET_MODE == "testnet":
    NETWORK_ID = NETWORK_ID_TESTNET
    REAL_TIME_DATABASE_NAME = "xmr_testnet"
    HISTORY_DATABASE_NAME = "xmr_testnet_every_day"
    TARGET_RPC_PORT = 28285

PROBE_NODE = ["152.136.24.233"]

BIND_IP = "10.2.4.13"

LOCAL_P2P_PORT_LIST = list(range(20000, 22020, 2))

LOCAL_RPC_PORT_LIST = [p + 1 for p in LOCAL_P2P_PORT_LIST]

target_node_list = [("49.233.169.195", 28285),]

target_ip_list = [node[0] for node in target_node_list]


# 转发目标 monerod 配置：收到 2002 NEW_TRANSACTION 消息后，将其转发到此节点的 P2P 端口
# 将 FORWARD_MONEROD_HOST 设置为目标服务器 IP，置空字符串则禁用转发
FORWARD_MONEROD_HOST = "82.157.60.174"
FORWARD_MONEROD_P2P_PORT = 28285   # 对应 --p2p-bind-port 28285



def configure_node_logger(node_ip, node_port) -> logging.Logger:
    """为每个节点配置独立的日志记录器"""
    logger = logging.getLogger(f"node_{node_ip}_{node_port}")
    logger.setLevel(logging.INFO)

    # 创建日志目录
    log_dir = Path("log")
    log_dir.mkdir(exist_ok=True)
    
    # 日志文件命名格式
    log_file = log_dir / f"node_{node_ip}_{node_port}.log"
    
    # 日志格式
    fmt = "%(asctime)s - %(levelname)s - %(message)s"
    formatter = logging.Formatter(fmt, "%Y-%m-%d %H:%M:%S")
    
    # 文件处理器（带自动轮转）
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=3,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    
    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.propagate = False
    
    return logger

    
# target_node_list = get_stable_nodes()
# target_node_list = [
#     ("89.233.104.112", 18090),
#     ("174.138.187.242", 18090),
#     ("194.35.13.195", 18090),
#     ('88.3.210.198', 18080), 
#     ('95.216.115.54', 18080),
# ]


# target_node_list = [
#     ("89.233.104.112", 18090),
#     ("174.138.187.242", 18090),
#     ("194.35.13.195", 18090),
#     ("103.106.0.231", 18090),
#     ("103.106.0.230", 18090),
#     ("103.106.0.229", 18090),
#     ("103.106.0.228", 18090),
#     ("103.106.0.227", 18090),
#     ("103.106.0.226", 18090),
#     ("103.106.0.225", 18090),
#     ("103.106.0.224", 18090),
#     ("103.106.0.96", 18090),
#     ("103.106.0.3", 18090),
#     ("103.106.0.2", 18090),
#     ("91.194.160.206", 18090),
#     ("91.194.160.202", 18090),
#     ("91.194.160.49", 18090),
#     ("45.89.109.108", 18090),
#     ("45.89.109.54", 18090),
#     ("45.12.134.238", 18090),
#     ("5.253.41.168", 18090),
#     ("5.253.41.90", 18090),
# ]

# target_node_list = [('89.233.104.112', 28080)]

# target_node_list = [('192.99.8.110', 28080), ('103.244.206.122', 28080), ('167.114.18.32', 28080), ('88.99.195.15', 28080), ('170.17.141.244', 28080), ('18.132.93.91', 28080), ('37.187.74.171', 28080), ('88.99.173.38', 28080), ('176.9.0.187', 28080), ('155.138.134.171', 28080), ('125.229.105.12', 28080), ('45.87.251.141', 28080), ('88.198.199.23', 28080), ('67.145.128.190', 28080), ('81.70.23.5', 28090), ('86.48.1.16', 28080), ('50.27.106.111', 28080), ('123.100.144.46', 28080), ('104.207.151.173', 28080), ('84.32.188.191', 28080), ('194.87.28.21', 28080), ('23.137.57.100', 28080), ('88.217.40.6', 28080), ('96.10.28.146', 28080), ('197.232.65.203', 28080), ('194.163.165.110', 28080), ('138.201.206.164', 28080), ('66.42.99.190', 28080), ('174.138.187.242', 28080), ('194.35.13.195', 28080), ('89.233.104.112', 28080)]



base_dir = os.path.dirname(__file__)
json_path = os.path.join(base_dir, "addr_peerid_map.json")
with open(json_path, "r") as f:
    addr_peerid_map = {eval(k): v for k, v in json.load(f).items()}

#local_ip_list = get_public_ips(IP_RANGES)

#total_ip_list = get_public_ips(IP_RANGES_TOTAL)

if __name__ == "__main__":
    print(len(local_ip_list))

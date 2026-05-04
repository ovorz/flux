import os
import configparser

import tools as tools
import levin.constants
from rpc.daemon import Daemon
from rpc.wallet import Wallet

# 读取配置文件
config = configparser.ConfigParser()
config_root = os.path.join(tools.get_project_root_path(), "Attack", "config")
# config_file = "2024-10-09_testnet_attack.ini"
config_file = "2024-10-07_mainnet_attack.ini"
config.read(os.path.join(config_root, config_file), encoding="utf-8")
print(os.path.join(config_root, config_file))

# 读取网络模式
net_mode = config['network']['net_mode']
network_id = levin.constants.NETWORK_ID_MAINNET if net_mode == "mainnet" else levin.constants.NETWORK_ID_TESTNET

# 根据网络模式选择钱包地址
wallet_ip = config["wallet"]["ip"]
wallet_rpc_bind_port = int(config["wallet"]["rpc_bind_port"])
wallet_receive_address = config['wallet']['receive_address']

# 读取目标节点 IP 和端口
target_node_ip = config['target_node']['ip']
target_p2p_bind_port = int(config['target_node']["p2p_bind_port"])
target_rpc_bind_port = int(config['target_node']["rpc_bind_port"])

# 读取 Stem 和 Fluff 节点的 IP 和端口
stem_tx_proxy_node_ip = config["stem_tx_proxy_node"]["ip"]
stem_tx_proxy_node_p2p_bind_port = int(config["stem_tx_proxy_node"]["p2p_bind_port"])
stem_tx_proxy_node_rpc_bind_port = int(config["stem_tx_proxy_node"]["rpc_bind_port"])

fluff_tx_proxy_node_ip = config["fluff_tx_proxy_node"]["ip"]
fluff_tx_proxy_node_p2p_bind_port = int(config["fluff_tx_proxy_node"]["p2p_bind_port"])
fluff_tx_proxy_node_rpc_bind_port = int(config["fluff_tx_proxy_node"]["rpc_bind_port"])

# 根据配置对相关对象进行初始化操作
WALLET_RPC = Wallet(wallet_ip, wallet_rpc_bind_port, "", "")
TARGET_NODE_RPC = Daemon(target_node_ip, target_rpc_bind_port, "", "")
STEM_TX_PROXY_NODE_RPC = Daemon(stem_tx_proxy_node_ip, stem_tx_proxy_node_rpc_bind_port, "", "")
FLUFF_TX_PROXY_NODE_RPC = Daemon(fluff_tx_proxy_node_ip, fluff_tx_proxy_node_rpc_bind_port, "", "")

# 示例打印配置
print(f"当前网络模式: {net_mode}")
print(f"目标节点: {target_node_ip}:{target_p2p_bind_port}")
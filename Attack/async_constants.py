import netifaces
import ipaddress
import random
import json
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta, timezone

import levin
import levin.constants

def get_public_ips():
    public_ips = []
    private_ranges = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('169.254.0.0/16'),  
        ipaddress.ip_network('127.0.0.0/8')    
    ]

    for interface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            for addr_info in addrs[netifaces.AF_INET]:
                ip = addr_info['addr']
                ip_obj = ipaddress.ip_address(ip)
                
                # 检查是否为公网IP
                is_private = any(ip_obj in network for network in private_ranges)
                if not is_private:
                    public_ips.append(ip)
    
    return public_ips


def get_addr_peerid_map():
    ip_port_map = {}
    ip_list = get_public_ips()
    for ip in ip_list:
        ip_port_map[ip] = 18080
    addr_peerid_map = {}
    for ip in ip_port_map:
        port = ip_port_map[ip]
        peer_id = random.getrandbits(64)
        addr_peerid_map[(ip, port)] = peer_id
    return addr_peerid_map


"""
用到的常量和共享变量
"""

target_node = ("81.70.23.5", 18080)

network_mode = "mainnet"
network_id = levin.constants.NETWORK_ID_MAINNET

local_ip_list = get_public_ips()
print(local_ip_list)
addr_peerid_map = get_addr_peerid_map()
# # # 写入文件
# # with open("addr_peerid_map.json", 'w') as f:
# #     json.dump({str(k): v for k, v in addr_peerid_map.items()}, f, indent=2)
# addr_peerid_map = {}
# # 读取文件
# with open("addr_peerid_map.json", "r") as f:
#     addr_peerid_map = {eval(k): v for k, v in json.load(f).items()}

# target_node_list = get_addr_from_database()
target_node_list = []
with open ("target_node_list.json", "r") as f:
    target_node_list = json.load(f)
target_node_list = [(target_node[0], int(target_node[1])) for target_node in target_node_list]
target_ip_list = [node[0] for node in target_node_list]

malicious_peerlist = target_node_list.remove(target_node) if target_node in target_node_list else target_node_list

# local_ip_list_for_graylist_attack = random.sample(local_ip_list, 20)

if __name__ == "__main__":
    # print(get_addr_from_database())
    print(len(target_node_list))
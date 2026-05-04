import json
import random
import ipaddress
import config



# IP_RANGES = [
#     "154.199.217.1-154.199.217.253",
#     "38.6.155.1-38.6.155.253",
#     "38.6.156.1-38.6.156.253",
#     "38.6.157.1-38.6.157.253",
# ]


# def get_public_ips():
#     listened_ip_list = []

#     for ip_range in IP_RANGES:
#         if '-' in ip_range:  # 处理IP范围
#             start_ip, end_ip = ip_range.split('-')
#             start_ip = ipaddress.IPv4Address(start_ip.strip())
#             end_ip = ipaddress.IPv4Address(end_ip.strip())

#             # 生成范围内的所有IP
#             for ip_int in range(int(start_ip), int(end_ip) + 1):
#                 listened_ip_list.append(str(ipaddress.IPv4Address(ip_int)))
        
#         else:  # 处理单个IP
#             listened_ip_list.append(ip_range.strip())

#     return listened_ip_list

def get_addr_peerid_map():
    ip_port_map = {}
    ip_list = config.PROBE_NODE
    for port in config.LOCAL_P2P_PORT_LIST:
        ip_port_map[port] = ip_list[0]
    addr_peerid_map = {}
    for (port,ip) in ip_port_map.items():
        peer_id = random.getrandbits(64)
        addr_peerid_map[(ip, port)] = peer_id
    return addr_peerid_map

addr_peerid_map = get_addr_peerid_map()
with open("addr_peerid_map.json", 'w') as f:
    json.dump({str(k): v for k, v in addr_peerid_map.items()}, f, indent=2)
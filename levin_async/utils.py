import random
import time
import socket
import ipaddress
import struct
from io import BytesIO


def ip2int(addr):
    return struct.unpack("<I", socket.inet_aton(addr))[0]


def int2ip(addr):
    return ipaddress.IPv4Address(addr)


def rshift(val, n):
    # 32bit rightshift
    return (val % 0x100000000) >> n


# 生成随机的ip地址（字符串类型）
def generate_random_ip():
    # 生成四个随机整数作为IP地址的四个部分
    ip_parts = [random.randint(0, 255) for _ in range(4)]

    # 将四个部分连接成IP地址字符串
    ip_address = ".".join(map(str, ip_parts))

    return ip_address
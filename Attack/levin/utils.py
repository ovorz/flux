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



def generate_random_ip():

    ip_parts = [random.randint(0, 255) for _ in range(4)]

    ip_address = ".".join(map(str, ip_parts))

    return ip_address

def generate_random_ip_list(ip_nums: int) -> list:
    ip_list = []
    for i in range(ip_nums):
        ip_list.append((generate_random_ip(), 28086))
    return ip_list
